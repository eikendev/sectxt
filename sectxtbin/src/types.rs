use reqwest::{Error, Response};
use sectxtlib::SecurityTxt;
use std::convert::TryFrom;
use tracing::info;

pub struct Status {
    pub domain: String,
    pub available: bool,
}

pub struct Website {
    pub domain: String,
    pub urls: Vec<String>,
}

async fn is_securitytxt(res: Result<Response, Error>) -> anyhow::Result<SecurityTxt> {
    match res {
        Ok(resp) => {
            if resp.status() == reqwest::StatusCode::OK {
                if let Some(content_type) = resp.headers().get("Content-Type") {
                    let value: &str = match content_type.to_str() {
                        Ok(text) => text,
                        _ => anyhow::bail!("error parsing HTTP body"),
                    };

                    if value.starts_with("text/plain") && value.contains("charset=utf-8") {
                        if let Ok(s) = resp.text().await {
                            Ok(SecurityTxt::try_from(&s[..])?)
                        } else {
                            anyhow::bail!("error parsing HTTP body");
                        }
                    } else {
                        anyhow::bail!("invalid HTTP content type");
                    }
                } else {
                    anyhow::bail!("HTTP content type not specified");
                }
            } else {
                anyhow::bail!("HTTP status code not OK");
            }
        }
        _ => anyhow::bail!("HTTP request failed"),
    }
}

impl Website {
    pub async fn get_status(self, client: &reqwest::Client, quiet: bool) -> Status {
        for url in self.urls {
            let response = client.get(&url[..]).send().await;

            match is_securitytxt(response).await {
                Ok(txt) => {
                    info!(domain = self.domain, len = txt.fields.len(), status = "OK");

                    return Status {
                        domain: self.domain,
                        available: true,
                    };
                }
                Err(e) => {
                    if !quiet {
                        info!(domain = self.domain, error = e.to_string(), status = "ERR");
                    }
                }
            }
        }

        Status {
            domain: self.domain,
            available: false,
        }
    }
}

impl From<&str> for Website {
    fn from(s: &str) -> Self {
        Website {
            domain: s.to_owned(),
            urls: vec![
                format!("https://{s}/.well-known/security.txt"),
                format!("https://{s}/security.txt"),
            ],
        }
    }
}
