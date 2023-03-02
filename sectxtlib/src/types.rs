use super::parsers::body_parser;
use chrono::{DateTime, Utc};
use iref::IriBuf;
use oxilangtag::{LanguageTag, LanguageTagParseError};
use std::convert::TryFrom;
use std::convert::TryInto;
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
    #[error("expires field may only be specified once")]
    ExpiresFieldExpired,
    #[error("expires field specifies time in the past")]
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

impl_from!(ParseError, iref::Error, ParseError::Malformed);
impl_from!(ParseError, nom::Err<nom::error::Error<&str>>, ParseError::Malformed);
impl_from!(ParseError, LanguageTagParseError, ParseError::Malformed);

#[derive(Debug)]
pub struct RawField<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

fn parse_preferred_languages(value: &str) -> Result<Vec<LanguageTag<String>>, LanguageTagParseError> {
    value.split(", ").map(LanguageTag::parse_and_normalize).collect()
}

impl TryInto<Field> for RawField<'_> {
    type Error = ParseError;

    fn try_into(self) -> Result<Field, Self::Error> {
        let name = self.name.to_lowercase();

        match &name[..] {
            "acknowledgments" => Ok(Field::Acknowledgments(IriBuf::new(self.value)?)),
            "canonical" => Ok(Field::Canonical(IriBuf::new(self.value)?)),
            "contact" => Ok(Field::Contact(IriBuf::new(self.value)?)),
            "encryption" => Ok(Field::Encryption(IriBuf::new(self.value)?)),
            "expires" => Ok(Field::Expires(self.value.parse()?)),
            "hiring" => Ok(Field::Hiring(IriBuf::new(self.value)?)),
            "policy" => Ok(Field::Policy(IriBuf::new(self.value)?)),
            "preferred-languages" => Ok(Field::PreferredLanguages(parse_preferred_languages(self.value)?)),
            _ => Ok(Field::Extension(name, self.value.to_owned())),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Field {
    Acknowledgments(IriBuf),
    Canonical(IriBuf),
    Contact(IriBuf),
    Encryption(IriBuf),
    Expires(DateTime<Utc>),
    Hiring(IriBuf),
    Policy(IriBuf),
    PreferredLanguages(Vec<LanguageTag<String>>),
    Extension(String, String),
}

trait IriBufVisitor {
    fn visit(&self) -> Option<&IriBuf>;
}

impl IriBufVisitor for Field {
    fn visit(&self) -> Option<&IriBuf> {
        match self {
            Field::Acknowledgments(iribuf)
            | Field::Canonical(iribuf)
            | Field::Contact(iribuf)
            | Field::Encryption(iribuf)
            | Field::Hiring(iribuf)
            | Field::Policy(iribuf) => Some(iribuf),
            Field::Expires(_) | Field::PreferredLanguages(_) | Field::Extension(_, _) => None,
        }
    }
}

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
        if fields.iter().filter_map(|x| x.visit()).any(|x| x.scheme() == "http") {
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
