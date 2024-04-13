use chrono::{DateTime, Utc};

/// Options for parsing a security.txt file
#[derive(Clone, Debug)]
pub struct SecurityTxtOptions {
    /// The current date and time to validate the "Expires" field against
    pub now: DateTime<Utc>,

    /// Whether to be strict with line endings or more relaxed
    pub strict: bool,
}

impl SecurityTxtOptions {
    pub fn new(strict: bool) -> Self {
        Self {
            now: Utc::now(),
            strict: strict,
        }
    }
}

impl Default for SecurityTxtOptions {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            strict: true,
        }
    }
}
