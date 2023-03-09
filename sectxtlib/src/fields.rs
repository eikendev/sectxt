use super::parse_error::ParseError;
use chrono::{DateTime, Utc};
use iri_string::types::IriString;
use oxilangtag::{LanguageTag, LanguageTagParseError};

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

#[derive(Debug, PartialEq)]
pub struct AcknowledgmentsField {
    uri: IriString,
}
IriStringImpl!(AcknowledgmentsField);

#[derive(Debug, PartialEq)]
pub struct CanonicalField {
    uri: IriString,
}
IriStringImpl!(CanonicalField);

#[derive(Debug, PartialEq)]
pub struct ContactField {
    uri: IriString,
}
IriStringImpl!(ContactField);

#[derive(Debug, PartialEq)]
pub struct EncryptionField {
    uri: IriString,
}
IriStringImpl!(EncryptionField);

#[derive(Debug, PartialEq)]
pub struct ExpiresField {
    datetime: DateTime<Utc>,
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

#[derive(Debug, PartialEq)]
pub struct HiringField {
    uri: IriString,
}
IriStringImpl!(HiringField);

#[derive(Debug, PartialEq)]
pub struct PolicyField {
    uri: IriString,
}
IriStringImpl!(PolicyField);

#[derive(Debug, PartialEq)]
pub struct PreferredLanguagesField {
    languages: Vec<LanguageTag<String>>,
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

#[derive(Debug, PartialEq)]
pub struct ExtensionField {
    key: String,
    value: String,
}

impl ExtensionField {
    pub(crate) fn new(key: String, value: String) -> Result<Self, ParseError> {
        Ok(Self { key, value })
    }
}
