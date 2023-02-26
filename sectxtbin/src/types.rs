use sectxtlib::SecurityTxt;
use std::convert::TryFrom;

pub struct Status {
    pub domain: String,
    pub available: bool,
}

pub struct Website {
    pub domain: String,
    pub urls: Vec<String>,
}

async fn is_securitytxt(r: reqwest::Response) -> bool {
    if r.status() == reqwest::StatusCode::OK {
        if let Some(content_type) = r.headers().get("Content-Type") {
            let value: &str = match content_type.to_str() {
                Ok(text) => text,
                _ => return false,
            };

            if value.starts_with("text/plain") && value.contains("charset=utf-8") {
                if let Ok(s) = r.text().await {
                    return SecurityTxt::try_from(&s[..]).is_ok();
                }
            }
        }
    }

    false
}

impl Website {
    pub async fn get_status(self, client: &reqwest::Client, quiet: bool) -> Status {
        let not_available = Status {
            domain: self.domain.to_owned(),
            available: false,
        };

        for url in self.urls {
            let response = client.get(&url[..]).send().await;

            match response {
                Ok(r) => {
                    if is_securitytxt(r).await {
                        println!("{}", self.domain);

                        return Status {
                            domain: self.domain,
                            available: true,
                        };
                    }

                    return not_available;
                }
                Err(e) => {
                    if !quiet {
                        eprintln!("{}: HTTP request failed: {}", self.domain, e)
                    }
                }
            }
        }

        not_available
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
