use chrono::{DateTime, Utc};

/// Options for parsing a security.txt file
#[derive(Debug)]
pub struct SecurityTxtOptions {
    /// The current date and time to validate the "Expires" field against
    pub now: DateTime<Utc>,
}

impl Default for SecurityTxtOptions {
    fn default() -> Self {
        Self { now: Utc::now() }
    }
}
