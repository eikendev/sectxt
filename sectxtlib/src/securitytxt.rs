use crate::parsers::SecurityTxtParser;
use crate::pgpcleartextmessage::PGPCleartextMessageParser;

use super::fields::{
    AcknowledgmentsField, CanonicalField, ContactField, CsafField, EncryptionField, ExpiresField, ExtensionField,
    HiringField, PolicyField, PreferredLanguagesField,
};
use super::parse_error::ParseError;
use super::raw_field::RawField;
use super::securitytxt_options::SecurityTxtOptions;
use std::cmp::Ordering;
use std::str::FromStr;
use valuable::Valuable;

/// A representation of an [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) security.txt file
#[derive(Debug, PartialEq, Valuable)]
pub struct SecurityTxt {
    /// A collection of "Acknowledgments" fields
    pub acknowledgments: Vec<AcknowledgmentsField>,

    /// A collection of "Canonical" fields
    pub canonical: Vec<CanonicalField>,

    /// A collection of "Contact" fields
    pub contact: Vec<ContactField>,

    /// A collection of "CSAF" fields,
    pub csaf: Vec<CsafField>,

    /// A collection of "Encryption" fields
    pub encryption: Vec<EncryptionField>,

    /// The "Expires" field
    pub expires: ExpiresField,

    /// A collection of "Extension" fields
    pub extension: Vec<ExtensionField>,

    /// A collection of "Hiring" fields
    pub hiring: Vec<HiringField>,

    /// A collection of "Policy" fields
    pub policy: Vec<PolicyField>,

    /// The "Preferred-Languages" field, if available
    pub preferred_languages: Option<PreferredLanguagesField>,
}

impl SecurityTxt {
    fn validate_contact_fields(fields: &[ContactField]) -> Result<(), ParseError> {
        if fields.is_empty() {
            return Err(ParseError::ContactFieldMissing);
        }

        Ok(())
    }

    fn validate_expires(fields: &[ExpiresField]) -> Result<(), ParseError> {
        if fields.is_empty() {
            return Err(ParseError::ExpiresFieldMissing);
        }
        if fields.len() > 1 {
            return Err(ParseError::ExpiresFieldMultiple);
        }

        Ok(())
    }

    fn validate_preferred_languages(fields: &[PreferredLanguagesField]) -> Result<(), ParseError> {
        if fields.len() > 1 {
            return Err(ParseError::PreferredLanguagesFieldMultiple);
        }

        Ok(())
    }

    pub(crate) fn new(fields: Vec<RawField>, options: &SecurityTxtOptions) -> Result<Self, ParseError> {
        let mut acknowledgments: Vec<AcknowledgmentsField> = vec![];
        let mut canonical: Vec<CanonicalField> = vec![];
        let mut contact: Vec<ContactField> = vec![];
        let mut csaf: Vec<CsafField> = vec![];
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
                "csaf" => csaf.push(CsafField::new(field.value)?),
                "encryption" => encryption.push(EncryptionField::new(field.value)?),
                "expires" => expires.push(ExpiresField::new(field.value, options.now)?),
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
            csaf,
            encryption,
            expires: expires.pop().unwrap(), // checked in Self::validate_expires()
            extension,
            hiring,
            policy,
            preferred_languages: preferred_languages.pop(),
        })
    }

    /// Parses a security.txt file as a string according to [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let options = Default::default();
        Self::parse_with(text, &options)
    }

    /// Parses a security.txt file as a string according to [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).
    pub fn parse_with(text: &str, options: &SecurityTxtOptions) -> Result<Self, ParseError> {
        let unsigned_parser = SecurityTxtParser::new(options);

        match unsigned_parser.parse(text) {
            Ok(fields) => {
                let fields: Vec<RawField> = fields.into_iter().flatten().collect();
                Self::new(fields, options)
            }
            _ => {
                let signed_parser = PGPCleartextMessageParser::new(options);
                let msg = signed_parser.parse(text)?;
                let fields = unsigned_parser.parse(&msg.cleartext)?;
                let fields: Vec<RawField> = fields.into_iter().flatten().collect();
                Self::new(fields, options)
            }
        }
    }
}

impl PartialOrd for SecurityTxt {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.expires.partial_cmp(&other.expires)
    }
}

impl FromStr for SecurityTxt {
    type Err = ParseError;

    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}
