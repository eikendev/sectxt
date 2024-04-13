use crate::SecurityTxtOptions;

use super::parse_error::ParseError;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{line_ending, none_of, one_of},
    combinator::{all_consuming, opt, peek, recognize},
    multi::{many0, many1, many1_count, separated_list1},
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
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

impl<'a> PGPCleartextMessage<'a> {}

pub(crate) struct PGPCleartextMessageParser {
    options: SecurityTxtOptions,
}

impl PGPCleartextMessageParser {
    pub fn new(options: &SecurityTxtOptions) -> Self {
        Self {
            options: options.clone(),
        }
    }

    pub fn parse<'a>(&'a self, text: &'a str) -> Result<PGPCleartextMessage, ParseError> {
        let (_, msg) = self.signed_parser(text)?;
        Ok(msg)
    }

    fn lf_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        match self.options.strict {
            true => line_ending(i),
            false => tag("\n")(i),
        }
    }

    // signed           =  cleartext-header
    //                     1*(hash-header)
    //                     CRLF
    //                     cleartext
    //                     signature
    fn signed_parser<'a>(&'a self, i: &'a str) -> IResult<&str, PGPCleartextMessage> {
        let (_, (_, hash_armor_headers, _, cleartext, signature)) = all_consuming(tuple((
            |x| self.cleartext_header_parser(x),
            many1(|x| self.hash_header_parser(x)),
            |x| self.lf_parser(x),
            |x| self.cleartext_parser(x),
            |x| self.signature_parser(x),
        )))(i)?;

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
    fn cleartext_header_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        terminated(tag("-----BEGIN PGP SIGNED MESSAGE-----"), |x| self.lf_parser(x))(i)
    }

    // hash-header      =  %s"Hash: " hash-alg *("," hash-alg) CRLF
    fn hash_header_parser<'a>(&'a self, i: &'a str) -> IResult<&str, Vec<&str>> {
        delimited(
            tag("Hash: "),
            separated_list1(tag(","), |x| self.hash_alg_parser(x)),
            |x| self.lf_parser(x),
        )(i)
    }

    // hash-alg         =  token
    //                       ; imported from RFC 2045; see RFC 4880 Section
    //                       ; 10.3.3 for a pointer to the registry of
    //                       ; valid values
    fn hash_alg_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        self.token_parser(i)
    }

    // < Section 5.1 of [RFC2045] >
    // token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
    //             or tspecials>
    fn token_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        take_while1(is_token_char)(i)
    }

    // cleartext        =  *((line-dash / line-from / line-nodash) [CR] LF)
    // EOL is handled in branches.
    fn cleartext_parser<'a>(&'a self, i: &'a str) -> IResult<&str, String> {
        let (i, lines) = many0(alt((|x| self.line_dash_parser(x), |x| self.line_nodash_parser(x))))(i)?;
        Ok((i, lines.join("")))
    }

    // line-dash        =  ("- ") "-" *UTF8-char-not-cr
    //                        ; MUST include initial "- "
    fn line_dash_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        preceded(
            tag("- "),
            recognize(tuple((
                one_of("-"),
                take_while(|x| x != '\r' && x != '\n'),
                line_ending,
            ))),
        )(i)
    }

    // line-nodash      =  ["- "] *UTF8-char-not-cr
    //                       ; MAY include initial "- "
    fn line_nodash_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        preceded(
            opt(tag("- ")),
            recognize(tuple((
                peek(none_of("-")),
                take_while(|x| x != '\r' && x != '\n'),
                line_ending,
            ))),
        )(i)
    }

    // signature        =  armor-header
    //                     armor-keys
    //                     CRLF
    //                     signature-data
    //                     armor-tail
    fn signature_parser<'a>(&'a self, i: &'a str) -> IResult<&str, PGPSignature> {
        let (i, (_, keys, _, signature, _)) = tuple((
            |x| self.armor_header_parser(x),
            |x| self.armor_keys_parser(x),
            |x| self.lf_parser(x),
            |x| self.signature_data_parser(x),
            |x| self.armor_tail_parser(x),
        ))(i)?;

        Ok((i, PGPSignature { signature, keys }))
    }

    // armor-header     =  %s"-----BEGIN PGP SIGNATURE-----" CRLF
    fn armor_header_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        terminated(tag("-----BEGIN PGP SIGNATURE-----"), |x| self.lf_parser(x))(i)
    }

    // armor-keys       =  *(token ": " *( VCHAR / WSP ) CRLF)
    //                       ; Armor Header Keys from RFC 4880
    fn armor_keys_parser<'a>(&'a self, i: &'a str) -> IResult<&str, Vec<(&str, &str)>> {
        many0(terminated(
            separated_pair(
                |x| self.token_parser(x),
                tag(": "),
                take_while(|x| is_vchar(x) || is_wsp(x)),
            ),
            |x| self.lf_parser(x),
        ))(i)
    }

    // armor-tail       =  %s"-----END PGP SIGNATURE-----" CRLF
    fn armor_tail_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        terminated(tag("-----END PGP SIGNATURE-----"), |x| self.lf_parser(x))(i)
    }

    // signature-data   =  1*(1*(ALPHA / DIGIT / "=" / "+" / "/") CRLF)
    //                       ; base64; see RFC 4648
    //                       ; includes RFC 4880 checksum
    fn signature_data_parser<'a>(&'a self, i: &'a str) -> IResult<&str, &str> {
        recognize(many1_count(terminated(take_while1(is_signature_data_char), |x| {
            self.lf_parser(x)
        })))(i)
    }
}

// < Section 5.1 of [RFC2045] >
// tspecials :=  "(" / ")" / "<" / ">" / "@" /
//               "," / ";" / ":" / "\" / <">
//               "/" / "[" / "]" / "?" / "="
//               ; Must be in quoted-string,
//               ; to use within parameter values
fn is_token_char(i: char) -> bool {
    let tspecials = "()<>@,;:\\\"/[]?=";
    i != ' ' && !i.is_ascii_control() && tspecials.find(i).is_none()
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
    fn test_parse() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
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
        assert_eq!(signed_parser.parse(&txt), Ok(msg));
    }

    #[test]
    fn test_hash_header_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let test_vector = vec![
            ("Hash: SHA512\r\n", vec!["SHA512"]),
            ("Hash: SHA256,SHA512\r\n", vec!["SHA256", "SHA512"]),
        ];

        for (input, result) in test_vector {
            assert_eq!(signed_parser.hash_header_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_token_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let test_vector = vec![("SHA512\r\n", "SHA512", "\r\n")];

        for (input, result, leftover) in test_vector {
            assert_eq!(signed_parser.token_parser(input), Ok((leftover, result)));
        }
    }

    #[test]
    fn test_line_dash_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let test_vector = vec![("- -test\r\n", "-test\r\n")];

        for (input, result) in test_vector {
            assert_eq!(signed_parser.line_dash_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_line_nodash_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let test_vector = vec![("test\r\n", "test\r\n")];

        for (input, result) in test_vector {
            assert_eq!(signed_parser.line_nodash_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_signature_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
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

        assert_eq!(signed_parser.signature_parser(&input), Ok(("", signature)));
    }

    #[test]
    fn test_armor_header_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let input = "-----BEGIN PGP SIGNATURE-----\r\n";
        assert_eq!(
            signed_parser.armor_header_parser(input),
            Ok(("", "-----BEGIN PGP SIGNATURE-----"))
        );
    }

    #[test]
    fn test_armor_tail_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let input = "-----END PGP SIGNATURE-----\r\n";
        assert_eq!(
            signed_parser.armor_tail_parser(input),
            Ok(("", "-----END PGP SIGNATURE-----"))
        );
    }

    #[test]
    fn test_armor_keys_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let test_vector = vec![
            ("", vec![]),
            ("test: \r\n", vec![("test", "")]),
            ("test: test\r\n", vec![("test", "test")]),
        ];

        for (input, result) in test_vector {
            assert_eq!(signed_parser.armor_keys_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_signature_data_parser() {
        let signed_parser = PGPCleartextMessageParser::new(&Default::default());
        let test_vector = vec![
            "iHUEARYKAB0WIQSsP2kEdoKDVFpSg6u3rK+YCkjapwUCY9qRaQAKCRC3rK+YCkja\r\npwALAP9LEHSYMDW4h8QRHg4MwCzUdnbjBLIvpq4QTo3dIqCUPwEA31MsEf95OKCh\r\nMTHYHajOzjwpwlQVrjkK419igx4imgk\r\n=KONn\r\n",
        ];

        for input in test_vector {
            assert_eq!(signed_parser.signature_data_parser(input), Ok(("", input)));
        }
    }
}
