mod fields;
mod parse_error;
mod parsers;
mod raw_field;
mod securitytxt;
mod securitytxt_options;

pub use fields::{
    AcknowledgmentsField, CanonicalField, ContactField, EncryptionField, ExpiresField, ExtensionField, HiringField,
    PolicyField, PreferredLanguagesField,
};
pub use parse_error::ParseError;
pub use securitytxt::SecurityTxt;
pub use securitytxt_options::SecurityTxtOptions;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::{fs, path::PathBuf};

    const URL: &str = "https://securitytxt.org/";
    const INSECURE_URL: &str = "http://securitytxt.org/";
    const EXPIRES: &str = "2030-01-01T08:19:03.000Z";

    fn now_dt() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2023-01-01T08:19:03.000Z").unwrap().into()
    }

    fn expires_dt() -> ExpiresField {
        ExpiresField::new(EXPIRES, now_dt()).unwrap()
    }

    fn get_tests_dir(category: &str) -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(format!("resources/test/{category}"));
        d
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

        assert_eq!(file.parse(), Ok(sec));
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

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_newlines() {
        let file = format!("\n\n\nContact: {URL}\n\n\nExpires: {EXPIRES}\n\n\n");
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

        assert_eq!(file.parse(), Ok(sec));
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

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_contact_missing() {
        let file = format!("Expires: {EXPIRES}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::ContactFieldMissing));
    }

    #[test]
    fn test_expires_missing() {
        let file = format!("Contact: {URL}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::ExpiresFieldMissing));
    }

    #[test]
    fn test_trailing_content() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nfoo");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::Malformed));
    }

    #[test]
    fn test_preferred_languages() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nPreferred-Languages: en, fr\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: Some(PreferredLanguagesField::new("en, fr").unwrap()),
        };

        assert_eq!(file.parse::<SecurityTxt>(), Ok(sec));
    }

    #[test]
    fn test_preferred_languages_multiple() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nPreferred-Languages: en\nPreferred-Languages: de\n");

        assert_eq!(
            file.parse::<SecurityTxt>(),
            Err(ParseError::PreferredLanguagesFieldMultiple)
        );
    }

    #[test]
    fn test_expires_multiple() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nExpires: {EXPIRES}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::ExpiresFieldMultiple));
    }

    #[test]
    fn test_insecure_http() {
        let file = format!("Contact: {INSECURE_URL}\nExpires: {EXPIRES}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::InsecureHTTP));
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

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_category_valid() {
        let paths = get_tests_dir("valid").read_dir().unwrap();

        for path in paths {
            let buf = fs::read_to_string(path.unwrap().path()).unwrap();
            let txt = buf.parse::<SecurityTxt>();
            assert_eq!(txt.is_ok(), true);
        }
    }
}
