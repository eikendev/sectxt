use super::fields::{
    AcknowledgmentsField, CanonicalField, ContactField, EncryptionField, ExpiresField, ExtensionField, HiringField,
    PolicyField, PreferredLanguagesField,
};
use super::parse_error::ParseError;
use super::parsers::body_parser;
use super::raw_field::RawField;
use std::convert::TryFrom;

#[derive(Debug, PartialEq)]
pub struct SecurityTxt {
    pub acknowledgments: Vec<AcknowledgmentsField>,
    pub canonical: Vec<CanonicalField>,
    pub contact: Vec<ContactField>,
    pub encryption: Vec<EncryptionField>,
    pub expires: ExpiresField,
    pub extension: Vec<ExtensionField>,
    pub hiring: Vec<HiringField>,
    pub policy: Vec<PolicyField>,
    pub preferred_languages: Option<PreferredLanguagesField>,
}

impl SecurityTxt {
    fn validate_contact_fields(fields: &Vec<ContactField>) -> Result<(), ParseError> {
        if fields.is_empty() {
            return Err(ParseError::ContactFieldMissing);
        }

        Ok(())
    }

    fn validate_expires(fields: &Vec<ExpiresField>) -> Result<(), ParseError> {
        if fields.is_empty() {
            return Err(ParseError::ExpiresFieldMissing);
        }
        if fields.len() > 1 {
            return Err(ParseError::ExpiresFieldMultiple);
        }

        Ok(())
    }

    fn validate_preferred_languages(fields: &Vec<PreferredLanguagesField>) -> Result<(), ParseError> {
        if fields.len() > 1 {
            return Err(ParseError::PreferredLanguagesFieldMultiple);
        }

        Ok(())
    }

    pub(crate) fn new(fields: Vec<RawField>) -> Result<Self, ParseError> {
        let mut acknowledgments: Vec<AcknowledgmentsField> = vec![];
        let mut canonical: Vec<CanonicalField> = vec![];
        let mut contact: Vec<ContactField> = vec![];
        let mut encryption: Vec<EncryptionField> = vec![];
        let mut expires: Vec<ExpiresField> = vec![];
        let mut extension: Vec<ExtensionField> = vec![];
        let mut hiring: Vec<HiringField> = vec![];
        let mut policy: Vec<PolicyField> = vec![];
        let mut preferred_languages: Vec<PreferredLanguagesField> = vec![];

        for field in fields {
            let name = field.name.to_lowercase();

            match &name[..] {
                "acknowledgments" => acknowledgments.push(AcknowledgmentsField::new(field.value)?),
                "canonical" => canonical.push(CanonicalField::new(field.value)?),
                "contact" => contact.push(ContactField::new(field.value)?),
                "encryption" => encryption.push(EncryptionField::new(field.value)?),
                "expires" => expires.push(ExpiresField::new(field.value)?),
                "hiring" => hiring.push(HiringField::new(field.value)?),
                "policy" => policy.push(PolicyField::new(field.value)?),
                "preferred-languages" => preferred_languages.push(PreferredLanguagesField::new(field.value)?),
                _ => extension.push(ExtensionField::new(name, field.value.to_owned())?),
            }
        }

        Self::validate_contact_fields(&contact)?;
        Self::validate_expires(&expires)?;
        Self::validate_preferred_languages(&preferred_languages)?;

        Ok(SecurityTxt {
            acknowledgments,
            canonical,
            contact,
            encryption,
            expires: expires.pop().unwrap(),
            extension,
            hiring,
            policy,
            preferred_languages: preferred_languages.pop(),
        })
    }
}

impl TryFrom<&str> for SecurityTxt {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let (_, fields) = body_parser(value)?;
        let fields: Vec<RawField> = fields.into_iter().flatten().collect();

        SecurityTxt::new(fields)
    }
}
