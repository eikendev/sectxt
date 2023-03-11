use super::parse_error::ParseError;
use chrono::{DateTime, Utc};
use iri_string::types::IriString;
use oxilangtag::{LanguageTag, LanguageTagParseError};
use std::cmp::Ordering;

macro_rules! IriStringImpl {
    ($structname:ident) => {
        impl $structname {
            pub(crate) fn new(uri: &str) -> Result<Self, ParseError> {
                let uri = uri.parse::<IriString>()?;
                if uri.scheme_str() == "http" {
                    return Err(ParseError::InsecureHTTP);
                }
                Ok(Self { uri })
            }
        }
    };
}

/// An [Acknowledgments field](https://www.rfc-editor.org/rfc/rfc9116#name-acknowledgments) links to a page where security researchers are recognized
#[derive(Debug, PartialEq)]
pub struct AcknowledgmentsField {
    pub uri: IriString,
}
IriStringImpl!(AcknowledgmentsField);

/// A [Canonical field](https://www.rfc-editor.org/rfc/rfc9116#name-canonical) contains a canonical URI for the security.txt file
#[derive(Debug, PartialEq)]
pub struct CanonicalField {
    pub uri: IriString,
}
IriStringImpl!(CanonicalField);

/// A [Contact field](https://www.rfc-editor.org/rfc/rfc9116#name-contact) contains contact information to use for reporting vulnerabilities
#[derive(Debug, PartialEq)]
pub struct ContactField {
    pub uri: IriString,
}
IriStringImpl!(ContactField);

/// An [Encryption field](https://www.rfc-editor.org/rfc/rfc9116#name-encryption) links to a key to be used for encrypted communication
#[derive(Debug, PartialEq)]
pub struct EncryptionField {
    pub uri: IriString,
}
IriStringImpl!(EncryptionField);

/// The [Expires field](https://www.rfc-editor.org/rfc/rfc9116#name-expires) represents the date and time after which the security.txt file is considered stale
#[derive(Debug, PartialEq)]
pub struct ExpiresField {
    pub datetime: DateTime<Utc>,
}

impl ExpiresField {
    pub(crate) fn new(datetime: &str) -> Result<Self, ParseError> {
        let datetime = datetime.parse()?;

        if datetime < Utc::now() {
            return Err(ParseError::ExpiresFieldExpired);
        }

        Ok(Self { datetime })
    }
}

impl PartialOrd for ExpiresField {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.datetime.partial_cmp(&other.datetime)
    }
}

/// A [Hiring field](https://www.rfc-editor.org/rfc/rfc9116#name-hiring) links to the vendor's security-related job positions
#[derive(Debug, PartialEq)]
pub struct HiringField {
    pub uri: IriString,
}
IriStringImpl!(HiringField);

/// A [Policy field](https://www.rfc-editor.org/rfc/rfc9116#name-policy) links to the security policy page
#[derive(Debug, PartialEq)]
pub struct PolicyField {
    pub uri: IriString,
}
IriStringImpl!(PolicyField);

/// The [Preferred-Languages field](https://www.rfc-editor.org/rfc/rfc9116#name-preferred-languages) lists the preferred languages for security reports
#[derive(Debug, PartialEq)]
pub struct PreferredLanguagesField {
    pub languages: Vec<LanguageTag<String>>,
}

impl PreferredLanguagesField {
    pub(crate) fn new(languages: &str) -> Result<Self, ParseError> {
        let languages = languages
            .split(", ")
            .map(LanguageTag::parse_and_normalize)
            .collect::<Result<Vec<LanguageTag<String>>, LanguageTagParseError>>()?;

        if languages.is_empty() {
            return Err(ParseError::IllegalField);
        }

        Ok(Self { languages })
    }
}

/// The "Extension" field acts as a catch-all for any fields not explicitly supported by this library
///
/// This feature accommodates [section 2.4 on Extensibility](https://www.rfc-editor.org/rfc/rfc9116#name-extensibility) in the specification.
#[derive(Debug, PartialEq)]
pub struct ExtensionField {
    pub key: String,
    pub value: String,
}

impl ExtensionField {
    pub(crate) fn new(key: String, value: String) -> Result<Self, ParseError> {
        Ok(Self { key, value })
    }
}
