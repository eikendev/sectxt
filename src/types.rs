use super::parse::ParseError;

use chrono::{DateTime, FixedOffset};
use iref::IriBuf;
use oxilangtag::LanguageTag;
use std::convert::TryFrom;
use std::convert::TryInto;

#[derive(Debug, PartialEq)]
pub enum Field {
    Acknowledgments(IriBuf),
    Canonical(IriBuf),
    Contact(IriBuf),
    Encryption(IriBuf),
    Expires(DateTime<FixedOffset>),
    Hiring(IriBuf),
    Policy(IriBuf),
    PreferredLanguages(Vec<LanguageTag<String>>),
    Extension(String, String),
}

// TODO: Support signed format.

#[derive(Debug, PartialEq)]
pub struct SecurityTxt {
    pub(crate) fields: Vec<Field>,
}

macro_rules! count_variant {
    ( $variant:path, $iterator:expr ) => {
        $iterator.fields.iter().filter(|val| matches!(val, $variant(_))).count()
    };
}

impl SecurityTxt {
    pub fn new(fields: Vec<Field>) -> Result<Self, ParseError> {
        let st = SecurityTxt { fields: fields };

        let count_contacts = count_variant!(Field::Contact, st);
        let count_expires = count_variant!(Field::Expires, st);
        let count_planguages = count_variant!(Field::PreferredLanguages, st);

        // TODO: Preferred-Languages MUST NOT be empty.
        // TODO: https MUST be used for web URLs.

        if count_contacts >= 1 && count_expires <= 1 && count_planguages <= 1 {
            Ok(st)
        } else {
            Err(ParseError::IllegalField)
        }
    }
}

impl TryFrom<&str> for SecurityTxt {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (_, fields) = crate::parse::line_parser(value)?;
        let fields: Vec<Field> = fields
            .into_iter()
            .filter_map(|x| x)
            .map(|x| x.try_into())
            .collect::<Result<Vec<Field>, Self::Error>>()?;

        SecurityTxt::new(fields)
    }
}