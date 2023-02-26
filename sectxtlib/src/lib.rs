mod parsers;
mod types;

pub use parsers::body_parser;
pub use types::ParseError;
pub use types::{Field, SecurityTxt};

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::{DateTime, Utc};
    use iref::IriBuf;
    use oxilangtag::LanguageTag;
    use std::convert::TryFrom;

    const URL: &str = "https://securitytxt.org/";
    const EXPIRES: &str = "2345-01-01T08:19:03.000Z";

    fn expires_dt() -> DateTime<Utc> {
        EXPIRES.parse().unwrap()
    }

    #[test]
    fn test_contact_and_expires() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\n");
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap()), Field::Expires(expires_dt())],
            expires_pos: Some(1),
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_comment() {
        let file = format!("# this is a comment\n#\nContact: {URL}\nExpires: {EXPIRES}\n#\n");
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap()), Field::Expires(expires_dt())],
            expires_pos: Some(1),
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_newlines() {
        let file = format!("\n\n\nContact: {URL}\nExpires: {EXPIRES}\n\n\n");
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap()), Field::Expires(expires_dt())],
            expires_pos: Some(1),
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_acknowledgements() {
        let file = format!("Contact: {URL}\nExpires: {EXPIRES}\nAcknowledgments: {URL}\n");
        let sec = SecurityTxt {
            fields: vec![
                Field::Contact(IriBuf::new(URL).unwrap()),
                Field::Expires(expires_dt()),
                Field::Acknowledgments(IriBuf::new(URL).unwrap()),
            ],
            expires_pos: Some(1),
            planguages_pos: None,
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
            fields: vec![
                Field::Contact(IriBuf::new(URL).unwrap()),
                Field::Expires(expires_dt()),
                Field::PreferredLanguages(vec![LanguageTag::parse_and_normalize("en").unwrap()]),
            ],
            expires_pos: Some(1),
            planguages_pos: Some(2),
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
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap()), Field::Expires(expires_dt())],
            expires_pos: Some(1),
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }
}
