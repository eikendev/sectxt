use chrono::{DateTime, Utc};

/// Options for parsing a security.txt file
///
/// # Examples
///
/// ```
/// use chrono::{TimeZone, Utc};
/// use sectxtlib::SecurityTxtOptions;
///
/// let options = SecurityTxtOptions::new().with_now(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SecurityTxtOptions {
    pub(crate) now: DateTime<Utc>,
}

impl SecurityTxtOptions {
    /// Creates options that validate the "Expires" field against the current time
    #[must_use]
    pub fn new() -> Self {
        Self { now: Utc::now() }
    }

    /// Sets the date and time to validate the "Expires" field against
    ///
    /// Files whose "Expires" field lies before this point are rejected with
    /// [`ParseError::ExpiresFieldExpired`](crate::ParseError::ExpiresFieldExpired).
    #[must_use]
    pub fn with_now(mut self, now: DateTime<Utc>) -> Self {
        self.now = now;
        self
    }

    /// The date and time the "Expires" field is validated against
    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        self.now
    }
}

impl Default for SecurityTxtOptions {
    fn default() -> Self {
        Self::new()
    }
}
