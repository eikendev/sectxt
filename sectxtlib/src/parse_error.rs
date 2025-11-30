use iri_string::validate;
use oxilangtag::LanguageTagParseError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("invalid syntax")]
    Malformed,
    #[error("invalid date format")]
    InvalidDatetime(#[from] chrono::format::ParseError),
    #[error("field specified in an illegal way")]
    IllegalField,
    #[error("contact field must be specified")]
    ContactFieldMissing,
    #[error("expires field must be specified")]
    ExpiresFieldMissing,
    #[error("expires field specifies time in the past")]
    ExpiresFieldExpired,
    #[error("expires field may only be specified once")]
    ExpiresFieldMultiple,
    #[error("preferred languages field may only be specified once")]
    PreferredLanguagesFieldMultiple,
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
