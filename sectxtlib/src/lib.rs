//! Parse and validate [security.txt](https://securitytxt.org/) files as specified in
//! [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).
//!
//! A `security.txt` file tells security researchers how to report vulnerabilities to an
//! organization. This crate turns the text of such a file into a [`SecurityTxt`] value and
//! rejects files that violate the RFC: missing `Contact` or `Expires` fields, an `Expires`
//! date in the past, duplicate single-instance fields, `http://` links, or syntax errors.
//! Both plain files and files wrapped in an OpenPGP cleartext signature are accepted.
//!
//! # Examples
//!
//! The simplest way to parse a file is through [`str::parse`]. The `Expires` field is
//! validated against the current time:
//!
//! ```
//! use sectxtlib::SecurityTxt;
//!
//! let text = "Contact: https://example.com/security\nExpires: 2999-01-01T00:00:00Z\n";
//! let sectxt: SecurityTxt = text.parse()?;
//!
//! assert_eq!(sectxt.contact.len(), 1);
//! assert_eq!(sectxt.contact[0].uri.as_str(), "https://example.com/security");
//! # Ok::<(), sectxtlib::ParseError>(())
//! ```
//!
//! Invalid files produce a [`ParseError`]:
//!
//! ```
//! use sectxtlib::{ParseError, SecurityTxt};
//!
//! let text = "Expires: 2999-01-01T00:00:00Z\n";
//! let result: Result<SecurityTxt, _> = text.parse();
//!
//! assert_eq!(result, Err(ParseError::ContactFieldMissing));
//! ```
//!
//! To validate a file against a different point in time, use [`SecurityTxt::parse_with`] and
//! [`SecurityTxtOptions`]:
//!
//! ```
//! use chrono::{TimeZone, Utc};
//! use sectxtlib::{SecurityTxt, SecurityTxtOptions};
//!
//! let text = "Contact: https://example.com/security\nExpires: 2020-06-01T00:00:00Z\n";
//! let options = SecurityTxtOptions {
//!     now: Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap(),
//!     ..Default::default()
//! };
//!
//! let sectxt = SecurityTxt::parse_with(text, &options)?;
//! assert_eq!(sectxt.expires.datetime, Utc.with_ymd_and_hms(2020, 6, 1, 0, 0, 0).unwrap());
//! # Ok::<(), sectxtlib::ParseError>(())
//! ```

mod fields;
mod parse_error;
mod parsers;
mod pgpcleartextmessage;
mod raw_field;
mod securitytxt;
mod securitytxt_options;

pub use fields::{
    AcknowledgmentsField, CanonicalField, ContactField, CsafField, EncryptionField, ExpiresField, ExtensionField,
    HiringField, PolicyField, PreferredLanguagesField,
};
pub use parse_error::ParseError;
pub use securitytxt::SecurityTxt;
pub use securitytxt_options::SecurityTxtOptions;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Datelike, Duration, SecondsFormat, TimeZone, Utc};
    use std::{fs, path::PathBuf};

    const URL: &str = "https://securitytxt.org/";
    const INSECURE_URL: &str = "http://securitytxt.org/";

    fn some_datetime() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2023-01-01T08:19:03.000Z").unwrap().into()
    }

    fn future_expires_str() -> String {
        (Utc::now() + Duration::days(365)).to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    fn expires_dt(expires: &str) -> ExpiresField {
        ExpiresField::new(expires, some_datetime()).unwrap()
    }

    fn get_parse_options() -> SecurityTxtOptions {
        SecurityTxtOptions {
            now: some_datetime(),
            strict: true,
        }
    }

    fn get_tests_dir(category: &str) -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(format!("resources/test/{category}"));
        d
    }

    #[test]
    fn test_contact_and_expires() {
        let expires = future_expires_str();
        let file = format!("Contact: {URL}\nExpires: {expires}\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            csaf: vec![],
            encryption: vec![],
            expires: expires_dt(&expires),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_comment() {
        let expires = future_expires_str();
        let file = format!("# this is a comment\n#\nContact: {URL}\nExpires: {expires}\n#\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            csaf: vec![],
            encryption: vec![],
            expires: expires_dt(&expires),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_newlines() {
        let expires = future_expires_str();
        let file = format!("\n\n\nContact: {URL}\n\n\nExpires: {expires}\n\n\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            csaf: vec![],
            encryption: vec![],
            expires: expires_dt(&expires),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_acknowledgements() {
        let expires = future_expires_str();
        let file = format!("Contact: {URL}\nExpires: {expires}\nAcknowledgments: {URL}\n");
        let sec = SecurityTxt {
            acknowledgments: vec![AcknowledgmentsField::new(URL).unwrap()],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            csaf: vec![],
            encryption: vec![],
            expires: expires_dt(&expires),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_csaf() {
        let expires = future_expires_str();
        let file = format!("Contact: {URL}\nExpires: {expires}\nCSAF: {URL}\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            csaf: vec![CsafField::new(URL).unwrap()],
            encryption: vec![],
            expires: expires_dt(&expires),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(file.parse(), Ok(sec));
    }

    #[test]
    fn test_contact_missing() {
        let expires = future_expires_str();
        let file = format!("Expires: {expires}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::ContactFieldMissing));
    }

    #[test]
    fn test_expires_missing() {
        let file = format!("Contact: {URL}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::ExpiresFieldMissing));
    }

    #[test]
    fn test_trailing_content() {
        let expires = future_expires_str();
        let file = format!("Contact: {URL}\nExpires: {expires}\nfoo");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::Malformed));
    }

    #[test]
    fn test_preferred_languages() {
        let expires = future_expires_str();
        let file = format!("Contact: {URL}\nExpires: {expires}\nPreferred-Languages: en, fr\n");
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap()],
            csaf: vec![],
            encryption: vec![],
            expires: expires_dt(&expires),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: Some(PreferredLanguagesField::new("en, fr").unwrap()),
        };

        assert_eq!(file.parse::<SecurityTxt>(), Ok(sec));
    }

    #[test]
    fn test_preferred_languages_multiple() {
        let expires = future_expires_str();
        let file = format!("Contact: {URL}\nExpires: {expires}\nPreferred-Languages: en\nPreferred-Languages: de\n");

        assert_eq!(
            file.parse::<SecurityTxt>(),
            Err(ParseError::PreferredLanguagesFieldMultiple)
        );
    }

    #[test]
    fn test_expires_multiple() {
        let expires = future_expires_str();
        let file = format!("Contact: {URL}\nExpires: {expires}\nExpires: {expires}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::ExpiresFieldMultiple));
    }

    #[test]
    fn test_insecure_http() {
        let expires = future_expires_str();
        let file = format!("Contact: {INSECURE_URL}\nExpires: {expires}\n");

        assert_eq!(file.parse::<SecurityTxt>(), Err(ParseError::InsecureHTTP));
    }

    #[test]
    fn test_signed_contact() {
        let expires = future_expires_str();
        let file = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\r
Hash: SHA256\r
\r
Contact: {URL}
Contact: {URL}\r
Expires: {expires}\r
-----BEGIN PGP SIGNATURE-----\r
Version: GnuPG v2.2\r
\r
abcdefABCDEF/+==\r
-----END PGP SIGNATURE-----\r
"
        );
        let sec = SecurityTxt {
            acknowledgments: vec![],
            canonical: vec![],
            contact: vec![ContactField::new(URL).unwrap(), ContactField::new(URL).unwrap()],
            csaf: vec![],
            encryption: vec![],
            expires: expires_dt(&expires),
            extension: vec![],
            hiring: vec![],
            policy: vec![],
            preferred_languages: None,
        };

        assert_eq!(file.parse(), Ok(sec));
    }

    fn _test_category(category: &str) {
        let paths = get_tests_dir(category).read_dir().unwrap();

        for path in paths {
            let buf = fs::read_to_string(path.unwrap().path()).unwrap();
            let parse_options = get_parse_options();
            let txt = SecurityTxt::parse_with(&buf, &parse_options);
            assert_eq!(txt.is_ok(), true);
        }
    }

    #[test]
    fn test_category_valid_unsigned() {
        _test_category("valid_unsigned")
    }

    #[test]
    fn test_category_valid_signed() {
        _test_category("valid_signed")
    }

    #[test]
    fn test_category_gen_unsigned() {
        _test_category("gen_unsigned")
    }

    #[test]
    fn test_expires_non_z_time() {
        let next_year = Utc::now().year() + 1;
        let test_times = [
            (
                format!("{next_year}-08-30T00:00:00+00:00"),
                Utc.with_ymd_and_hms(next_year, 8, 30, 0, 0, 0),
            ),
            (
                format!("{next_year}-08-30T12:34:56+00:00"),
                Utc.with_ymd_and_hms(next_year, 8, 30, 12, 34, 56),
            ),
            (
                format!("{next_year}-08-30T02:00:00+02:00"),
                Utc.with_ymd_and_hms(next_year, 8, 30, 0, 0, 0),
            ),
            (
                format!("{next_year}-08-30T02:00:00-02:00"),
                Utc.with_ymd_and_hms(next_year, 8, 30, 4, 0, 0),
            ),
        ];

        for (expires_str, expected_dt) in &test_times {
            let file = format!("Contact: {URL}\nExpires: {expires_str}\n");
            let sec = SecurityTxt {
                acknowledgments: vec![],
                canonical: vec![],
                contact: vec![ContactField::new(URL).unwrap()],
                csaf: vec![],
                encryption: vec![],
                expires: ExpiresField::new(expires_str, some_datetime()).unwrap(),
                extension: vec![],
                hiring: vec![],
                policy: vec![],
                preferred_languages: None,
            };

            let parsed: SecurityTxt = file.parse().unwrap();
            assert_eq!(parsed, sec);
            let expected_dt = expected_dt.single().unwrap();
            assert_eq!(parsed.expires.datetime.timestamp(), expected_dt.timestamp());
            assert_eq!(
                parsed.expires.datetime.timestamp_subsec_millis(),
                expected_dt.timestamp_subsec_millis()
            );
        }
    }
}
