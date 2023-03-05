use super::field::Field;
use super::ParseError;
use iri_string::types::IriString;
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
            "acknowledgments" => Ok(Field::Acknowledgments(self.value.parse::<IriString>()?)),
            "canonical" => Ok(Field::Canonical(self.value.parse::<IriString>()?)),
            "contact" => Ok(Field::Contact(self.value.parse::<IriString>()?)),
            "encryption" => Ok(Field::Encryption(self.value.parse::<IriString>()?)),
            "expires" => Ok(Field::Expires(self.value.parse()?)),
            "hiring" => Ok(Field::Hiring(self.value.parse::<IriString>()?)),
            "policy" => Ok(Field::Policy(self.value.parse::<IriString>()?)),
            "preferred-languages" => Ok(Field::PreferredLanguages(parse_preferred_languages(self.value)?)),
            _ => Ok(Field::Extension(name, self.value.to_owned())),
        }
    }
}
