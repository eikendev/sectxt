use super::Field;

use chrono::DateTime;
use iref::IriBuf;
use oxilangtag::{LanguageTag, LanguageTagParseError};
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
    value.split(", ").map(|x| LanguageTag::parse_and_normalize(x)).collect()
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
            "expires" => Ok(Field::Expires(DateTime::parse_from_str(self.value, "")?)),
            "hiring" => Ok(Field::Hiring(IriBuf::new(self.value)?)),
            "policy" => Ok(Field::Policy(IriBuf::new(self.value)?)),
            "preferred-languages" => Ok(Field::PreferredLanguages(parse_preferred_languages(self.value)?)),
            _ => Ok(Field::Extension(name, self.value.to_owned())),
        }
    }
}
