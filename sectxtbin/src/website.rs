use super::network::is_securitytxt;
use super::status::Status;
use anyhow::{Context, Result};
use std::convert::TryFrom;
use tracing::info;
use url::Url;

pub struct Website {
    pub domain: String,
    pub urls: Vec<String>,
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

impl TryFrom<&str> for Website {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self> {
        let url = Url::parse(s).context("unable to parse input as URL")?;
        let host = url.host_str().context("cannot parse hostname in input")?;

        Ok(Website {
            domain: host.to_owned(),
            urls: vec![
                format!("https://{host}/.well-known/security.txt"),
                format!("https://{host}/security.txt"),
            ],
        })
    }
}
