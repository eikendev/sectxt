use chrono::{DateTime, Utc};
use iref::IriBuf;
use oxilangtag::LanguageTag;

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
