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

#[derive(Debug, PartialEq)]
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

pub trait IriBufVisitor {
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
    pub(crate) fields: Vec<Field>,
}

macro_rules! count_variant {
    ( $variant:path, $vector:expr ) => {
        $vector.iter().filter(|x| matches!(x, $variant(_))).count()
    };
}

impl SecurityTxt {
    pub fn new(fields: Vec<Field>) -> Result<Self, ParseError> {
        let count = count_variant!(Field::Contact, fields);
        if count == 0 {
            return Err(ParseError::ContactFieldMissing);
        }

        let count = count_variant!(Field::Expires, fields);
        if count == 0 {
            return Err(ParseError::ExpiresFieldMissing);
        }
        if count > 1 {
            return Err(ParseError::ExpiresFieldMultiple);
        }

        let count = count_variant!(Field::PreferredLanguages, fields);
        if count > 1 {
            return Err(ParseError::PreferredLanguagesFieldMultiple);
        }

        // We checked above that this field exists.
        let expires = fields.iter().find(|x| matches!(x, Field::Expires(_))).unwrap();
        if let Field::Expires(time) = expires {
            if time < &Utc::now() {
                return Err(ParseError::ExpiresFieldExpired);
            }
        }

        let planguages = fields.iter().find(|x| matches!(x, Field::PreferredLanguages(_)));
        if let Some(Field::PreferredLanguages(languages)) = planguages {
            if languages.is_empty() {
                return Err(ParseError::IllegalField);
            }
        }

        if fields.iter().filter_map(|x| x.visit()).any(|x| x.scheme() == "http") {
            return Err(ParseError::InsecureHTTP);
        }

        Ok(SecurityTxt { fields })
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
