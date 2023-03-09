mod fields;
mod parse_error;
mod parsers;
mod raw_field;
mod securitytxt;

pub use parse_error::ParseError;
pub use securitytxt::SecurityTxt;

#[cfg(test)]
mod tests {
    use crate::fields::{AcknowledgmentsField, ContactField, ExpiresField, PreferredLanguagesField};

    use super::*;

    use std::{convert::TryFrom, vec};

    const URL: &str = "https://securitytxt.org/";
    const INSECURE_URL: &str = "http://securitytxt.org/";
    const EXPIRES: &str = "2345-01-01T08:19:03.000Z";

    fn expires_dt() -> ExpiresField {
        ExpiresField::new(EXPIRES).unwrap()
    }

    #[test]
    fn test_contact_and_expires() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_comment() {
        let file = format!("# this is a comment\n#\nContact: {URL}\nExpires: {EXPIRES}\n#\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_newlines() {
        let file = format!("\n\n\nContact: {URL}\nExpires: {EXPIRES}\n\n\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_acknowledgements() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nAcknowledgments: {URL}\n");
        let sec = SecurityTxt {
            acknowledgments: vec![AcknowledgmentsField::new(URL).unwrap()],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_contact_missing() {
        let file = format!("Expires: {EXPIRES}\n");

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::ContactFieldMissing));
    }

    #[test]
    fn test_expires_missing() {
        let file = format!("Contact: {URL}\n");

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::ExpiresFieldMissing));
    }

    #[test]
    fn test_trailing_content() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nfoo");

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::Malformed));
    }

    #[test]
    fn test_preferred_languages() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nPreferred-Languages: en\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: Some(PreferredLanguagesField::new("en").unwrap()),
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_preferred_languages_multiple() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nPreferred-Languages: en\nPreferred-Languages: de\n");

        assert_eq!(
            SecurityTxt::try_from(&file[..]),
            Err(ParseError::PreferredLanguagesFieldMultiple)
        );
    }

    #[test]
    fn test_expires_multiple() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nExpires: {EXPIRES}\n");

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::ExpiresFieldMultiple));
    }

    #[test]
    fn test_insecure_http() {
        let file = format!("Contact: {INSECURE_URL}\nExpires: {EXPIRES}\n");

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::InsecureHTTP));
    }

    #[test]
    fn test_signed_contact() {
        let file = format!(
            "\
            -----BEGIN PGP SIGNED MESSAGE-----\n\
            Hash: SHA256\n\n\
            Contact: {URL}\n\
            Expires: {EXPIRES}\n\
            -----BEGIN PGP SIGNATURE-----\n\
            Version: GnuPG v2.2\n\n\
            abcdefABCDEF/+==\n\
            -----END PGP SIGNATURE-----\n"
        );
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }
}
