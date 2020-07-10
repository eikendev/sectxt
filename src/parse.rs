mod parsers;
mod types;

pub use super::types::{Field, SecurityTxt};

pub use parsers::body_parser;
pub use types::ParseError;

#[cfg(test)]
mod tests {
    use super::*;

    use iref::IriBuf;
    use oxilangtag::LanguageTag;
    use std::convert::TryFrom;

    const URL: &str = "https://securitytxt.org/";

    #[test]
    fn test_contact() {
        let file = format!("Contact: {}\n", URL);
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_comment() {
        let file = format!("# this is a comment\n#\nContact: {}\n#\n", URL);
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_newlines() {
        let file = format!("\n\n\nContact: {}\n\n\n", URL);
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_acknowledgements() {
        let file = format!("Contact: {}\nAcknowledgments: {}\n", URL, URL);
        let sec = SecurityTxt {
            fields: vec![
                Field::Contact(IriBuf::new(URL).unwrap()),
                Field::Acknowledgments(IriBuf::new(URL).unwrap()),
            ],
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_missing_contact() {
        let file = format!("Acknowledgments: {}\n", URL);

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::IllegalField));
    }

    #[test]
    fn test_trailing_content() {
        let file = format!("Contact: {}\nfoo", URL);

        assert_eq!(SecurityTxt::try_from(&file[..]), Err(ParseError::Malformed));
    }

    #[test]
    fn test_preferred_languages() {
        let file = format!("Contact: {}\nPreferred-Languages: en\n", URL);
        let sec = SecurityTxt {
            fields: vec![
                Field::Contact(IriBuf::new(URL).unwrap()),
                Field::PreferredLanguages(vec![LanguageTag::parse_and_normalize("en").unwrap()]),
            ],
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }

    #[test]
    fn test_signed_contact() {
        let file = format!("\
            -----BEGIN PGP SIGNED MESSAGE-----\n\
            Hash: SHA256\n\n\
            Contact: {}\n\
            -----BEGIN PGP SIGNATURE-----\n\
            Version: GnuPG v2.2\n\n\
            abcdefABCDEF/+==\n\
            -----END PGP SIGNATURE-----\n", URL);
        println!("{}", file);
        let sec = SecurityTxt {
            fields: vec![Field::Contact(IriBuf::new(URL).unwrap())],
        };

        assert_eq!(SecurityTxt::try_from(&file[..]), Ok(sec));
    }
}
