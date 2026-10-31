use crate::parsers;
use crate::pgpcleartextmessage;

use super::fields::{
    AcknowledgmentsField, CanonicalField, ContactField, CsafField, EncryptionField, ExpiresField, ExtensionField,
    HiringField, PolicyField, PreferredLanguagesField,
};
use super::parse_error::ParseError;
use super::raw_field::RawField;
use super::securitytxt_options::SecurityTxtOptions;
use std::cmp::Ordering;
use std::str::FromStr;

/// A representation of an [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) security.txt file
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "valuable", derive(valuable::Valuable))]
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
                _ => extension.push(ExtensionField::new(name, field.value.to_owned())),
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
    ///
    /// The `Expires` field is validated against the current time. Use [`SecurityTxt::parse_with`]
    /// to supply a different reference time.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if the text is not a valid security.txt file.
    ///
    /// # Examples
    ///
    /// ```
    /// use sectxtlib::SecurityTxt;
    ///
    /// let text = "Contact: mailto:security@example.com\nExpires: 2999-01-01T00:00:00Z\n";
    /// let sectxt = SecurityTxt::parse(text)?;
    ///
    /// assert_eq!(sectxt.contact[0].uri.as_str(), "mailto:security@example.com");
    /// # Ok::<(), sectxtlib::ParseError>(())
    /// ```
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        Self::parse_with(text, &SecurityTxtOptions::default())
    }

    /// Parses a security.txt file as a string according to [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116),
    /// using the given [`SecurityTxtOptions`].
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] if the text is not a valid security.txt file.
    ///
    /// # Examples
    ///
    /// ```
    /// use chrono::{TimeZone, Utc};
    /// use sectxtlib::{ParseError, SecurityTxt, SecurityTxtOptions};
    ///
    /// let text = "Contact: https://example.com/security\nExpires: 2020-06-01T00:00:00Z\n";
    ///
    /// let before = SecurityTxtOptions::new().with_now(Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap());
    /// assert!(SecurityTxt::parse_with(text, &before).is_ok());
    ///
    /// let after = SecurityTxtOptions::new().with_now(Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap());
    /// assert_eq!(SecurityTxt::parse_with(text, &after), Err(ParseError::ExpiresFieldExpired));
    /// ```
    pub fn parse_with(text: &str, options: &SecurityTxtOptions) -> Result<Self, ParseError> {
        // The grammar in RFC 9116 is `body = signed / unsigned`, and a signed body always opens
        // with the cleartext header. Deciding up front means a malformed unsigned file reports
        // the unsigned parser's error instead of the signed parser's.
        if pgpcleartextmessage::is_signed(text) {
            let msg = pgpcleartextmessage::parse(text)?;
            let fields = parsers::parse(&msg.cleartext)?;
            Self::new(fields.into_iter().flatten().collect(), options)
        } else {
            let fields = parsers::parse(text)?;
            Self::new(fields.into_iter().flatten().collect(), options)
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
