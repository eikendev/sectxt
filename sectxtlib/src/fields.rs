use super::parse_error::ParseError;
use chrono::{DateTime, Utc};
use iri_string::types::IriString;
use oxilangtag::{LanguageTag, LanguageTagParseError};
use std::cmp::Ordering;
use std::fmt;

macro_rules! IriStringImpl {
    ($structname:ident) => {
        impl $structname {
            pub(crate) fn new(uri: &str) -> Result<Self, ParseError> {
                let uri = uri.trim().parse::<IriString>()?;

                if uri.scheme_str() == "http" {
                    return Err(ParseError::InsecureHTTP);
                }

                Ok(Self { uri })
            }
        }

        impl fmt::Display for $structname {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.uri.as_str())
            }
        }

        #[cfg(feature = "valuable")]
        impl valuable::Valuable for $structname {
            fn as_value(&self) -> valuable::Value<'_> {
                valuable::Value::String(self.uri.as_str())
            }

            fn visit(&self, visit: &mut dyn valuable::Visit) {
                visit.visit_value(self.as_value());
            }
        }
    };
}

/// An [Acknowledgments field](https://www.rfc-editor.org/rfc/rfc9116#name-acknowledgments) links to a page where security researchers are recognized
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct AcknowledgmentsField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,
}
IriStringImpl!(AcknowledgmentsField);

/// A [Canonical field](https://www.rfc-editor.org/rfc/rfc9116#name-canonical) contains a canonical URI for the security.txt file
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct CanonicalField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,
}
IriStringImpl!(CanonicalField);

/// A [Contact field](https://www.rfc-editor.org/rfc/rfc9116#name-contact) contains contact information to use for reporting vulnerabilities
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct ContactField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,
}
IriStringImpl!(ContactField);

/// A [CSAF field](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#718-requirement-8-securitytxt) contains the canonical URI for the CSAF provider-metadata.json
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct CsafField {
    /// The URI of the link according to the [CSAF Standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#718-requirement-8-securitytxt)
    pub uri: IriString,
}
IriStringImpl!(CsafField);

/// An [Encryption field](https://www.rfc-editor.org/rfc/rfc9116#name-encryption) links to a key to be used for encrypted communication
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct EncryptionField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,
}
IriStringImpl!(EncryptionField);

/// The [Expires field](https://www.rfc-editor.org/rfc/rfc9116#name-expires) represents the date and time after which the security.txt file is considered stale
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct ExpiresField {
    /// The date and time from which the security.txt file is considered stale
    pub datetime: DateTime<Utc>,

    // Cached `Display` output, so that `valuable::Valuable::as_value` can hand out a borrowed string.
    #[cfg_attr(feature = "serde", serde(skip))]
    rendered: String,
}

impl ExpiresField {
    pub(crate) fn new(datetime: &str, now: DateTime<Utc>) -> Result<Self, ParseError> {
        let datetime: DateTime<Utc> = datetime.trim().parse()?;

        if datetime < now {
            return Err(ParseError::ExpiresFieldExpired);
        }

        let rendered = datetime.to_rfc3339();

        Ok(Self { datetime, rendered })
    }
}

impl fmt::Display for ExpiresField {
    /// Formats the date and time according to [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) in UTC
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rendered)
    }
}

impl PartialOrd for ExpiresField {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.datetime.partial_cmp(&other.datetime)
    }
}

#[cfg(feature = "valuable")]
impl valuable::Valuable for ExpiresField {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::String(&self.rendered)
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        visit.visit_value(self.as_value());
    }
}

/// A [Hiring field](https://www.rfc-editor.org/rfc/rfc9116#name-hiring) links to the vendor's security-related job positions
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct HiringField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,
}
IriStringImpl!(HiringField);

/// A [Policy field](https://www.rfc-editor.org/rfc/rfc9116#name-policy) links to the security policy page
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct PolicyField {
    /// The URI of the link according to [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986)
    pub uri: IriString,
}
IriStringImpl!(PolicyField);

/// The [Preferred-Languages field](https://www.rfc-editor.org/rfc/rfc9116#name-preferred-languages) lists the preferred languages for security reports
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct PreferredLanguagesField {
    /// The set of preferred languages according to [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646)
    pub languages: Vec<LanguageTag<String>>,

    // Cached `Display` output, so that `valuable::Valuable::as_value` can hand out a borrowed string.
    #[cfg_attr(feature = "serde", serde(skip))]
    rendered: String,
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

        let rendered = languages.join(", ");

        Ok(Self { languages, rendered })
    }
}

impl fmt::Display for PreferredLanguagesField {
    /// Formats the language tags as a comma-separated list, for example `en, fr`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rendered)
    }
}

#[cfg(feature = "valuable")]
impl valuable::Valuable for PreferredLanguagesField {
    fn as_value(&self) -> valuable::Value<'_> {
        valuable::Value::String(&self.rendered)
    }

    fn visit(&self, visit: &mut dyn valuable::Visit) {
        visit.visit_value(self.as_value());
    }
}

/// The "Extension" field acts as a catch-all for any fields not explicitly supported by this library
///
/// This feature accommodates [section 2.4 on Extensibility](https://www.rfc-editor.org/rfc/rfc9116#name-extensibility) in the specification.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "valuable", derive(valuable::Valuable))]
pub struct ExtensionField {
    /// Name of the extension field
    pub name: String,
    /// Value of the extension field
    pub value: String,
}

impl ExtensionField {
    pub(crate) fn new(name: String, value: String) -> Self {
        Self { name, value }
    }
}

impl fmt::Display for ExtensionField {
    /// Formats the field as it appears in the file, `Name: value`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uri_field_display() {
        let field = ContactField::new(" https://example.com/security ").unwrap();
        assert_eq!(field.to_string(), "https://example.com/security");
    }

    #[test]
    fn test_expires_field_display() {
        let now = DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z").unwrap().into();
        let field = ExpiresField::new("2020-06-01T02:00:00+02:00", now).unwrap();
        assert_eq!(field.to_string(), "2020-06-01T00:00:00+00:00");
    }

    #[test]
    fn test_preferred_languages_field_display() {
        let field = PreferredLanguagesField::new("en,  FR").unwrap();
        assert_eq!(field.to_string(), "en, fr");
    }

    #[cfg(feature = "valuable")]
    #[test]
    fn test_valuable_matches_display() {
        use valuable::Valuable;

        let now = DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z").unwrap().into();
        let contact = ContactField::new("https://example.com/security").unwrap();
        let expires = ExpiresField::new("2020-06-01T02:00:00+02:00", now).unwrap();
        let languages = PreferredLanguagesField::new("en,  FR").unwrap();

        assert_eq!(contact.as_value().as_str(), Some(contact.to_string().as_str()));
        assert_eq!(expires.as_value().as_str(), Some(expires.to_string().as_str()));
        assert_eq!(languages.as_value().as_str(), Some(languages.to_string().as_str()));
    }

    #[test]
    fn test_extension_field_display() {
        let field = ExtensionField::new("foo".into(), "bar".into());
        assert_eq!(field.to_string(), "foo: bar");
    }
}
