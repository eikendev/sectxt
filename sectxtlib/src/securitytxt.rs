use super::field::Field;
use super::field::IriStringVisitor;
use super::parse_error::ParseError;
use super::parsers::body_parser;
use chrono::{DateTime, Utc};
use std::convert::TryFrom;

#[derive(Debug, PartialEq)]
pub struct SecurityTxt {
    pub fields: Vec<Field>,
    pub expires: DateTime<Utc>,
    pub preferred_languages: Option<String>,
}

macro_rules! get_variant {
    ( $variant:path, $vector:expr ) => {
        $vector.iter().filter(|x| matches!(x, $variant(_))).collect()
    };
}

impl SecurityTxt {
    fn check_contact_fields(fields: Vec<&Field>) -> Result<(), ParseError> {
        if fields.is_empty() {
            return Err(ParseError::ContactFieldMissing);
        }

        Ok(())
    }

    fn check_expires(fields: Vec<&Field>) -> Result<DateTime<Utc>, ParseError> {
        if fields.is_empty() {
            return Err(ParseError::ExpiresFieldMissing);
        }
        if fields.len() > 1 {
            return Err(ParseError::ExpiresFieldMultiple);
        }

        // We checked above that this field exists.
        let expires = match fields[0] {
            Field::Expires(time) => time.to_owned(),
            _ => {
                panic!("illegal expires field")
            }
        };
        if expires < Utc::now() {
            return Err(ParseError::ExpiresFieldExpired);
        }

        Ok(expires)
    }

    fn check_preferred_languages(fields: Vec<&Field>) -> Result<Option<String>, ParseError> {
        if fields.len() > 1 {
            return Err(ParseError::PreferredLanguagesFieldMultiple);
        }

        let preferred_languages: Option<String> = match fields.get(0) {
            Some(&Field::PreferredLanguages(languages)) => {
                if languages.is_empty() {
                    return Err(ParseError::IllegalField);
                }

                let languages: Vec<String> = languages.iter().map(|x| x.to_string()).collect();
                Some(languages.join(", "))
            }
            _ => None,
        };

        Ok(preferred_languages)
    }

    fn check_insecure_http(fields: &[Field]) -> Result<(), ParseError> {
        if fields
            .iter()
            .filter_map(|x| x.visit())
            .any(|x| x.scheme_str() == "http")
        {
            return Err(ParseError::InsecureHTTP);
        }

        Ok(())
    }

    pub fn new(fields: Vec<Field>) -> Result<Self, ParseError> {
        let contact_fields: Vec<&Field> = get_variant!(Field::Contact, fields);
        Self::check_contact_fields(contact_fields)?;

        let expires_fields: Vec<&Field> = get_variant!(Field::Expires, fields);
        let expires = Self::check_expires(expires_fields)?;

        let preferred_languages_fields: Vec<&Field> = get_variant!(Field::PreferredLanguages, fields);
        let preferred_languages = Self::check_preferred_languages(preferred_languages_fields)?;

        Self::check_insecure_http(&fields)?;

        Ok(SecurityTxt {
            fields,
            expires,
            preferred_languages,
        })
    }

    pub fn get_contacts(&self) -> Vec<&Field> {
        get_variant!(Field::Contact, self.fields)
    }
}

impl TryFrom<&str> for SecurityTxt {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (_, fields) = body_parser(value)?;
        let fields: Vec<Field> = fields
            .into_iter()
            .flatten()
            .map(|x| x.try_into())
            .collect::<Result<Vec<Field>, Self::Error>>()?;

        SecurityTxt::new(fields)
    }
}
