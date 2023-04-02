use super::parse_error::ParseError;
use chrono::{DateTime, Utc};
use iri_string::types::IriString;
use oxilangtag::{LanguageTag, LanguageTagParseError};
use std::cmp::Ordering;
use valuable::{Valuable, Value, Visit};

macro_rules! IriStringImpl {
    ($structname:ident) => {
        impl $structname {
            pub(crate) fn new(uri: &str) -> Result<Self, ParseError> {
                let uri = uri.trim().parse::<IriString>()?;

                if uri.scheme_str() == "http" {
                    return Err(ParseError::InsecureHTTP);
                }

                let log_value = uri.as_str().to_string();

                Ok(Self { uri, log_value })
            }
        }

        impl Valuable for $structname {
            fn as_value(&self) -> Value<'_> {
                self.log_value.as_value()
            }

            fn visit(&self, _visit: &mut dyn Visit) {}
        }
    };
}

/// An [Acknowledgments field](https://www.rfc-editor.org/rfc/rfc9116#name-acknowledgments) links to a page where security researchers are recognized
#[derive(Debug, PartialEq)]
pub struct AcknowledgmentsField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,

    log_value: String,
}
IriStringImpl!(AcknowledgmentsField);

/// A [Canonical field](https://www.rfc-editor.org/rfc/rfc9116#name-canonical) contains a canonical URI for the security.txt file
#[derive(Debug, PartialEq)]
pub struct CanonicalField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,

    log_value: String,
}
IriStringImpl!(CanonicalField);

/// A [Contact field](https://www.rfc-editor.org/rfc/rfc9116#name-contact) contains contact information to use for reporting vulnerabilities
#[derive(Debug, PartialEq)]
pub struct ContactField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,

    log_value: String,
}
IriStringImpl!(ContactField);

/// An [Encryption field](https://www.rfc-editor.org/rfc/rfc9116#name-encryption) links to a key to be used for encrypted communication
#[derive(Debug, PartialEq)]
pub struct EncryptionField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,

    log_value: String,
}
IriStringImpl!(EncryptionField);

/// The [Expires field](https://www.rfc-editor.org/rfc/rfc9116#name-expires) represents the date and time after which the security.txt file is considered stale
#[derive(Debug, PartialEq)]
pub struct ExpiresField {
    /// The date and time from which the security.txt file is considered stale
    pub datetime: DateTime<Utc>,

    log_value: String,
}

impl ExpiresField {
    pub(crate) fn new(datetime: &str, now: DateTime<Utc>) -> Result<Self, ParseError> {
        let datetime: DateTime<Utc> = datetime.trim().parse()?;

        if datetime < now {
            return Err(ParseError::ExpiresFieldExpired);
        }

        let log_value = datetime.to_rfc3339();

        Ok(Self { datetime, log_value })
    }
}

impl PartialOrd for ExpiresField {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.datetime.partial_cmp(&other.datetime)
    }
}

impl Valuable for ExpiresField {
    fn as_value(&self) -> Value<'_> {
        self.log_value.as_value()
    }

    fn visit(&self, _visit: &mut dyn Visit) {}
}

/// A [Hiring field](https://www.rfc-editor.org/rfc/rfc9116#name-hiring) links to the vendor's security-related job positions
#[derive(Debug, PartialEq)]
pub struct HiringField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,

    log_value: String,
}
IriStringImpl!(HiringField);

/// A [Policy field](https://www.rfc-editor.org/rfc/rfc9116#name-policy) links to the security policy page
#[derive(Debug, PartialEq)]
pub struct PolicyField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,

    log_value: String,
}
IriStringImpl!(PolicyField);

/// The [Preferred-Languages field](https://www.rfc-editor.org/rfc/rfc9116#name-preferred-languages) lists the preferred languages for security reports
#[derive(Debug, PartialEq)]
pub struct PreferredLanguagesField {
    /// The set of preferred languages according to [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646)
    pub languages: Vec<LanguageTag<String>>,

    log_value: String,
}

impl PreferredLanguagesField {
    pub(crate) fn new(languages: &str) -> Result<Self, ParseError> {
        let languages = languages
            .split(',')
            .map(str::trim)
            .map(LanguageTag::parse_and_normalize)
            .collect::<Result<Vec<LanguageTag<String>>, LanguageTagParseError>>()?;

        if languages.is_empty() {
            return Err(ParseError::IllegalField);
        }

        let log_value = languages.join(", ");

        Ok(Self { languages, log_value })
    }
}

impl Valuable for PreferredLanguagesField {
    fn as_value(&self) -> Value<'_> {
        self.log_value.as_value()
    }

    fn visit(&self, _visit: &mut dyn Visit) {}
}

/// The "Extension" field acts as a catch-all for any fields not explicitly supported by this library
///
/// This feature accommodates [section 2.4 on Extensibility](https://www.rfc-editor.org/rfc/rfc9116#name-extensibility) in the specification.
#[derive(Debug, PartialEq, Valuable)]
pub struct ExtensionField {
    /// Name of the extension field
    pub name: String,
    /// Value of the extension field
    pub value: String,
}

impl ExtensionField {
    pub(crate) fn new(name: String, value: String) -> Result<Self, ParseError> {
        Ok(Self { name, value })
    }
}
