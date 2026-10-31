use iri_string::validate;
use oxilangtag::LanguageTagParseError;
use thiserror::Error;

/// The reason a security.txt file was rejected
///
/// Parsing stops at the first problem, so a file with several problems reports only one of them.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ParseError {
    /// The file does not follow the grammar in [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116),
    /// or a field value is not a valid URI or language tag
    #[error("invalid syntax")]
    Malformed,
    /// The "Expires" field is not a valid [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) date and time
    #[error("invalid date format")]
    InvalidDatetime(#[from] chrono::format::ParseError),
    /// A field is present but has no usable value, for example an empty "Preferred-Languages" list
    #[error("field specified in an illegal way")]
    IllegalField,
    /// The file has no "Contact" field, which the RFC requires at least once
    #[error("contact field must be specified")]
    ContactFieldMissing,
    /// The file has no "Expires" field, which the RFC requires exactly once
    #[error("expires field must be specified")]
    ExpiresFieldMissing,
    /// The "Expires" field lies before the reference time, so the file is stale
    #[error("expires field specifies time in the past")]
    ExpiresFieldExpired,
    /// The "Expires" field appears more than once
    #[error("expires field may only be specified once")]
    ExpiresFieldMultiple,
    /// The "Preferred-Languages" field appears more than once
    #[error("preferred languages field may only be specified once")]
    PreferredLanguagesFieldMultiple,
    /// A field links to a web URI with the `http` scheme, which the RFC forbids
    #[error("links must use HTTPS")]
    InsecureHTTP,
}

macro_rules! impl_from {
    ( $for:path, $from:path, $to:path  ) => {
        impl From<$from> for $for {
            fn from(_: $from) -> $for {
                $to
            }
        }
    };
}

impl_from!(ParseError, validate::Error, ParseError::Malformed);
impl_from!(ParseError, nom::Err<nom::error::Error<&str>>, ParseError::Malformed);
impl_from!(ParseError, LanguageTagParseError, ParseError::Malformed);
