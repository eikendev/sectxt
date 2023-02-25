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
            if content_type.to_str().unwrap().starts_with("text/plain") {
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
                }
                Err(e) => {
                    if !quiet {
                        eprintln!("{}: HTTP request failed: {}", self.domain, e)
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
                format!("https://{}/.well-known/security.txt", s),
                format!("https://{}/security.txt", s),
            ],
        }
    }
}
