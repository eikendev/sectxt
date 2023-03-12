use chrono::{DateTime, Utc};

/// TODO
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
