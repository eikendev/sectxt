use super::field::Field;
use super::ParseError;
use iref::IriBuf;
use oxilangtag::{LanguageTag, LanguageTagParseError};
use std::convert::TryInto;

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
