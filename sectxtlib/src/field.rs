use chrono::{DateTime, Utc};
use iri_string::types::IriString;
use oxilangtag::LanguageTag;

#[derive(Debug, PartialEq)]
pub enum Field {
    Acknowledgments(IriString),
    Canonical(IriString),
    Contact(IriString),
    Encryption(IriString),
    Expires(DateTime<Utc>),
    Hiring(IriString),
    Policy(IriString),
    PreferredLanguages(Vec<LanguageTag<String>>),
    Extension(String, String),
}

pub trait IriStringVisitor {
    fn visit(&self) -> Option<&IriString>;
}

impl IriStringVisitor for Field {
    fn visit(&self) -> Option<&IriString> {
        match self {
            Field::Acknowledgments(iri_string)
            | Field::Canonical(iri_string)
            | Field::Contact(iri_string)
            | Field::Encryption(iri_string)
            | Field::Hiring(iri_string)
            | Field::Policy(iri_string) => Some(iri_string),
            Field::Expires(_) | Field::PreferredLanguages(_) | Field::Extension(_, _) => None,
        }
    }
}
