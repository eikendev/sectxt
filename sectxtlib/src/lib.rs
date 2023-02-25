mod parsers;
mod types;

pub use parsers::body_parser;
pub use types::ParseError;
pub use types::{Field, SecurityTxt};

#[cfg(test)]
mod tests {
    use super::*;

    use iref::IriBuf;
    use oxilangtag::LanguageTag;
    use std::convert::TryFrom;

    const URL: &str = "https://securitytxt.org/";

    #[test]
    fn test_contact() {
        let file = format!("Contact: {URL}\n");
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
            expires_pos: None,
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_comment() {
        let file = format!("# this is a comment\n#\nContact: {URL}\n#\n");
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
            expires_pos: None,
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_newlines() {
        let file = format!("\n\n\nContact: {URL}\n\n\n");
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
            expires_pos: None,
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_acknowledgements() {
        let file = format!("Contact: {URL}\nAcknowledgments: {URL}\n");
        let sec = SecurityTxt {
            fields: vec![
                Field::Contact(IriBuf::new(URL).unwrap()),
                Field::Acknowledgments(IriBuf::new(URL).unwrap()),
            ],
            expires_pos: None,
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_missing_contact() {
        let file = format!("Acknowledgments: {URL}\n");

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::IllegalField));
    }

    #[test]
    fn test_trailing_content() {
        let file = format!("Contact: {URL}\nfoo");

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::Malformed));
    }

    #[test]
    fn test_preferred_languages() {
        let file = format!("Contact: {URL}\nPreferred-Languages: en\n");
        let sec = SecurityTxt {
            fields: vec![
                Field::Contact(IriBuf::new(URL).unwrap()),
                Field::PreferredLanguages(vec![LanguageTag::parse_and_normalize("en").unwrap()]),
            ],
            expires_pos: None,
            planguages_pos: Some(1),
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_signed_contact() {
        let file = format!(
            "\
            -----BEGIN PGP SIGNED MESSAGE-----\n\
            Hash: SHA256\n\n\
            Contact: {URL}\n\
            -----BEGIN PGP SIGNATURE-----\n\
            Version: GnuPG v2.2\n\n\
            abcdefABCDEF/+==\n\
            -----END PGP SIGNATURE-----\n"
        );
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
            expires_pos: None,
            planguages_pos: None,
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }
}
