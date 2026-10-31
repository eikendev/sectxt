use super::parse_error::ParseError;

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{line_ending, none_of, one_of},
    combinator::{all_consuming, opt, peek, recognize},
    multi::{many0, many1, many1_count, separated_list1},
    sequence::{delimited, preceded, separated_pair, terminated},
};

#[derive(Debug, PartialEq)]
pub(crate) struct PGPSignature<'a> {
    pub signature: &'a str,
    pub keys: Vec<(&'a str, &'a str)>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct PGPCleartextMessage<'a> {
    pub hash_armor_headers: Vec<Vec<&'a str>>,
    pub cleartext: String,
    pub signature: PGPSignature<'a>,
}

const CLEARTEXT_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";

/// Returns whether the text opens with the OpenPGP cleartext header, which is how the
/// grammar in RFC 9116 distinguishes a signed body from an unsigned one.
pub(crate) fn is_signed(text: &str) -> bool {
    text.starts_with(CLEARTEXT_HEADER)
}

/// Parses an OpenPGP cleartext signed message and returns its parts.
///
/// The signature is not verified.
pub(crate) fn parse(text: &str) -> Result<PGPCleartextMessage<'_>, ParseError> {
    let (_, msg) = signed_parser(text)?;
    Ok(msg)
}

// RFC 9116 writes CRLF in the signed grammar, but section 2.2 of the same RFC and erratum 7743
// allow a bare LF as well. Real-world files use both, so both are accepted everywhere.
fn eol_parser(i: &str) -> IResult<&str, &str> {
    line_ending.parse(i)
}

// signed           =  cleartext-header
//                     1*(hash-header)
//                     CRLF
//                     cleartext
//                     signature
fn signed_parser(i: &str) -> IResult<&str, PGPCleartextMessage<'_>> {
    let (_, (_, hash_armor_headers, _, cleartext, signature)) = all_consuming((
        cleartext_header_parser,
        many1(hash_header_parser),
        eol_parser,
        cleartext_parser,
        signature_parser,
    ))
    .parse(i)?;

    Ok((
        i,
        PGPCleartextMessage {
            hash_armor_headers,
            cleartext,
            signature,
        },
    ))
}

// cleartext-header =  %s"-----BEGIN PGP SIGNED MESSAGE-----" CRLF
fn cleartext_header_parser(i: &str) -> IResult<&str, &str> {
    terminated(tag(CLEARTEXT_HEADER), eol_parser).parse(i)
}

// hash-header      =  %s"Hash: " hash-alg *("," hash-alg) CRLF
fn hash_header_parser(i: &str) -> IResult<&str, Vec<&str>> {
    delimited(tag("Hash: "), separated_list1(tag(","), hash_alg_parser), eol_parser).parse(i)
}

// hash-alg         =  token
//                       ; imported from RFC 2045; see RFC 4880 Section
//                       ; 10.3.3 for a pointer to the registry of
//                       ; valid values
fn hash_alg_parser(i: &str) -> IResult<&str, &str> {
    token_parser(i)
}

// < Section 5.1 of [RFC2045] >
// token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
//             or tspecials>
fn token_parser(i: &str) -> IResult<&str, &str> {
    take_while1(is_token_char).parse(i)
}

// cleartext        =  *((line-dash / line-from / line-nodash) [CR] LF)
// EOL is handled in branches.
fn cleartext_parser(i: &str) -> IResult<&str, String> {
    let (i, lines) = many0(alt((line_dash_parser, line_nodash_parser))).parse(i)?;
    Ok((i, lines.join("")))
}

// line-dash        =  ("- ") "-" *UTF8-char-not-cr
//                        ; MUST include initial "- "
fn line_dash_parser(i: &str) -> IResult<&str, &str> {
    preceded(
        tag("- "),
        recognize((one_of("-"), take_while(|x| x != '\r' && x != '\n'), line_ending)),
    )
    .parse(i)
}

// line-nodash      =  ["- "] *UTF8-char-not-cr
//                       ; MAY include initial "- "
fn line_nodash_parser(i: &str) -> IResult<&str, &str> {
    preceded(
        opt(tag("- ")),
        recognize((peek(none_of("-")), take_while(|x| x != '\r' && x != '\n'), line_ending)),
    )
    .parse(i)
}

// signature        =  armor-header
//                     armor-keys
//                     CRLF
//                     signature-data
//                     armor-tail
fn signature_parser(i: &str) -> IResult<&str, PGPSignature<'_>> {
    let (i, (_, keys, _, signature, _)) = (
        armor_header_parser,
        armor_keys_parser,
        eol_parser,
        signature_data_parser,
        armor_tail_parser,
    )
        .parse(i)?;

    Ok((i, PGPSignature { signature, keys }))
}

// armor-header     =  %s"-----BEGIN PGP SIGNATURE-----" CRLF
fn armor_header_parser(i: &str) -> IResult<&str, &str> {
    terminated(tag("-----BEGIN PGP SIGNATURE-----"), eol_parser).parse(i)
}

// armor-keys       =  *(token ": " *( VCHAR / WSP ) CRLF)
//                       ; Armor Header Keys from RFC 4880
fn armor_keys_parser(i: &str) -> IResult<&str, Vec<(&str, &str)>> {
    many0(terminated(
        separated_pair(token_parser, tag(": "), take_while(|x| is_vchar(x) || is_wsp(x))),
        eol_parser,
    ))
    .parse(i)
}

// armor-tail       =  %s"-----END PGP SIGNATURE-----" CRLF
fn armor_tail_parser(i: &str) -> IResult<&str, &str> {
    terminated(tag("-----END PGP SIGNATURE-----"), eol_parser).parse(i)
}

// signature-data   =  1*(1*(ALPHA / DIGIT / "=" / "+" / "/") CRLF)
//                       ; base64; see RFC 4648
//                       ; includes RFC 4880 checksum
fn signature_data_parser(i: &str) -> IResult<&str, &str> {
    recognize(many1_count(terminated(take_while1(is_signature_data_char), eol_parser))).parse(i)
}

// < Section 5.1 of [RFC2045] >
// tspecials :=  "(" / ")" / "<" / ">" / "@" /
//               "," / ";" / ":" / "\" / <">
//               "/" / "[" / "]" / "?" / "="
//               ; Must be in quoted-string,
//               ; to use within parameter values
fn is_token_char(i: char) -> bool {
    let tspecials = "()<>@,;:\\\"/[]?=";
    i != ' ' && !i.is_ascii_control() && !tspecials.contains(i)
}

fn is_signature_data_char(i: char) -> bool {
    matches!(i, 'a'..='z' | 'A'..='Z' | '0'..='9' | '=' | '+' | '/')
}

// VCHAR            =  %x21-7E
//                       ; visible (printing) characters
fn is_vchar(i: char) -> bool {
    matches!(i, '\x21'..='\x7E')
}

// WSP              =  SP / HTAB
//                       ; white space
fn is_wsp(i: char) -> bool {
    i == ' ' || i == '\t'
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE_DATA: &str = "iHUEARYKAB0WIQSsP2kEdoKDVFpSg6u3rK+YCkjapwUCY9qRaQAKCRC3rK+YCkja\r
pwALAP9LEHSYMDW4h8QRHg4MwCzUdnbjBLIvpq4QTo3dIqCUPwEA31MsEf95OKCh\r
MTHYHajOzjwpwlQVrjkK419igx4imgk=\r
=KONn\r
";

    #[test]
    fn test_is_signed() {
        assert!(is_signed("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"));
        assert!(!is_signed("Contact: https://example.com\n"));
        assert!(!is_signed("\n-----BEGIN PGP SIGNED MESSAGE-----\n"));
    }

    #[test]
    fn test_parse() {
        let txt = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\r
Hash: SHA512\r
\r
Test\r
- Test\r
-----BEGIN PGP SIGNATURE-----\r
\r
{SIGNATURE_DATA}-----END PGP SIGNATURE-----\r
"
        );
        let msg = PGPCleartextMessage {
            hash_armor_headers: vec![vec!["SHA512"]],
            cleartext: "Test\r\nTest\r\n".into(),
            signature: PGPSignature {
                signature: SIGNATURE_DATA,
                keys: vec![],
            },
        };
        assert_eq!(parse(&txt), Ok(msg));
    }

    #[test]
    fn test_parse_lf_only() {
        let signature_data = SIGNATURE_DATA.replace("\r\n", "\n");
        let txt = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nTest\n-----BEGIN PGP SIGNATURE-----\n\n{signature_data}-----END PGP SIGNATURE-----\n"
        );
        let msg = parse(&txt).unwrap();
        assert_eq!(msg.cleartext, "Test\n");
        assert_eq!(msg.signature.signature, signature_data);
    }

    #[test]
    fn test_hash_header_parser() {
        let test_vector = vec![
            ("Hash: SHA512\r\n", vec!["SHA512"]),
            ("Hash: SHA512\n", vec!["SHA512"]),
            ("Hash: SHA256,SHA512\r\n", vec!["SHA256", "SHA512"]),
        ];

        for (input, result) in test_vector {
            assert_eq!(hash_header_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_token_parser() {
        let test_vector = vec![("SHA512\r\n", "SHA512", "\r\n")];

        for (input, result, leftover) in test_vector {
            assert_eq!(token_parser(input), Ok((leftover, result)));
        }
    }

    #[test]
    fn test_line_dash_parser() {
        let test_vector = vec![("- -test\r\n", "-test\r\n")];

        for (input, result) in test_vector {
            assert_eq!(line_dash_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_line_nodash_parser() {
        let test_vector = vec![("test\r\n", "test\r\n")];

        for (input, result) in test_vector {
            assert_eq!(line_nodash_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_signature_parser() {
        let input = format!(
            "-----BEGIN PGP SIGNATURE-----\r
\r
{SIGNATURE_DATA}-----END PGP SIGNATURE-----\r
"
        );
        let signature = PGPSignature {
            signature: SIGNATURE_DATA,
            keys: vec![],
        };

        assert_eq!(signature_parser(&input), Ok(("", signature)));
    }

    #[test]
    fn test_armor_header_parser() {
        let input = "-----BEGIN PGP SIGNATURE-----\r\n";
        assert_eq!(armor_header_parser(input), Ok(("", "-----BEGIN PGP SIGNATURE-----")));
    }

    #[test]
    fn test_armor_tail_parser() {
        let input = "-----END PGP SIGNATURE-----\r\n";
        assert_eq!(armor_tail_parser(input), Ok(("", "-----END PGP SIGNATURE-----")));
    }

    #[test]
    fn test_armor_keys_parser() {
        let test_vector = vec![
            ("", vec![]),
            ("test: \r\n", vec![("test", "")]),
            ("test: test\r\n", vec![("test", "test")]),
        ];

        for (input, result) in test_vector {
            assert_eq!(armor_keys_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_signature_data_parser() {
        let test_vector = vec![
            "iHUEARYKAB0WIQSsP2kEdoKDVFpSg6u3rK+YCkjapwUCY9qRaQAKCRC3rK+YCkja\r\npwALAP9LEHSYMDW4h8QRHg4MwCzUdnbjBLIvpq4QTo3dIqCUPwEA31MsEf95OKCh\r\nMTHYHajOzjwpwlQVrjkK419igx4imgk\r\n=KONn\r\n",
        ];

        for input in test_vector {
            assert_eq!(signature_data_parser(input), Ok(("", input)));
        }
    }
}
