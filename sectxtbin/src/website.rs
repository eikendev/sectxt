use super::network::{is_file_present, is_securitytxt};
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
    fn make_status(&self, available: bool) -> Status {
        Status {
            domain: self.domain.to_owned(),
            available,
        }
    }

    pub async fn get_status(&self, client: &reqwest::Client, quiet: bool) -> Status {
        let mut first_error: Option<anyhow::Error> = None;

        for url in &self.urls {
            let response = client.get(&url[..]).send().await;

            match is_file_present(response) {
                Ok(response) => match is_securitytxt(response).await {
                    Ok(txt) => {
                        // Location exists and file is parsable.
                        info!(domain = self.domain, len = txt.fields.len(), status = "OK");
                        return self.make_status(true);
                    }
                    Err(err) => {
                        // Location exists but file is not parsable.
                        info!(domain = self.domain, error = err.to_string(), status = "ERR");
                        return self.make_status(false);
                    }
                },
                Err(err) => {
                    // Location does not exists.
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        if !quiet {
            let err = first_error.unwrap(); // self.urls is never empty
            info!(domain = self.domain, error = err.to_string(), status = "ERR");
        }

        self.make_status(false)
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
