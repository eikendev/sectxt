use anyhow::{Context, Result};
use reqwest::Response;
use sectxtlib::SecurityTxt;
use std::convert::TryFrom;

pub fn is_file_present(result: Result<reqwest::Response, reqwest::Error>) -> Result<Response> {
    let resp = result.context("HTTP request failed")?;

    if resp.status() != reqwest::StatusCode::OK {
        anyhow::bail!("HTTP status code not OK");
    }

    Ok(resp)
}

pub async fn is_securitytxt(resp: Response) -> Result<SecurityTxt> {
    if let Some(content_type) = resp.headers().get("Content-Type") {
        let value: &str = content_type.to_str().context("error parsing HTTP body")?;

        if value.starts_with("text/plain") && value.contains("charset=utf-8") {
            let s = resp.text().await.context("error parsing HTTP body")?;
            Ok(SecurityTxt::try_from(&s[..])?)
        } else {
            anyhow::bail!("invalid HTTP content type");
        }
    } else {
        anyhow::bail!("HTTP content type not specified");
    }
}
