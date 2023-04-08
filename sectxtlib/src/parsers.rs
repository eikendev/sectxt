use super::raw_field::RawField;
use super::signature::PGPSignature;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    character::complete::{char, crlf, none_of, one_of, satisfy},
    combinator::{all_consuming, map, opt, recognize},
    multi::{many0, many0_count, many1, many1_count, separated_list1},
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult,
};

// body             =  signed / unsigned
pub(crate) fn body_parser(i: &str) -> IResult<&str, Vec<Option<RawField>>> {
    all_consuming(alt((unsigned_parser, signed_parser)))(i)
}

// unsigned       =  *line (contact-field eol) ; one or more required
//                   *line (expires-field eol) ; exactly one required
//                   *line [lang-field eol] *line ; exactly one optional
//                   ; order of fields within the file is not important
//                   ; except that if contact-field appears more
//                   ; than once, the order of those indicates
//                   ; priority (see Section 3.5.3)
fn unsigned_parser(i: &str) -> IResult<&str, Vec<Option<RawField>>> {
    many1(line_parser)(i)
}

// line             =  [ (field / comment) ] eol
fn line_parser(i: &str) -> IResult<&str, Option<RawField>> {
    let field_parser_opt = map(field_parser, Some);
    let comment_parser_opt = map(comment_parser, |_| None);

    let (i, raw_field) = terminated(opt(alt((comment_parser_opt, field_parser_opt))), eol_parser)(i)?;
    let flattened = raw_field.flatten();
    Ok((i, flattened))
}

// eol              =  *WSP [CR] LF
fn eol_parser(i: &str) -> IResult<&str, &str> {
    recognize(tuple((take_while(is_wsp), opt(cr_parser), lf_parser)))(i)
}

// field            =  ; optional fields
//                     ack-field /
//                     can-field /
//                     contact-field / ; optional repeated instances
//                     encryption-field /
//                     hiring-field /
//                     policy-field /
//                     ext-field
fn field_parser(i: &str) -> IResult<&str, RawField> {
    ext_name_parser(i)
}

// fs               =  ":"
fn fs_parser(i: &str) -> IResult<&str, char> {
    char(':')(i)
}

// comment          =  "#" *(WSP / VCHAR / %x80-FFFFF)
fn comment_parser(i: &str) -> IResult<&str, &str> {
    let matcher = |x| is_wsp(x) || is_vchar(x) || x >= '\u{80}';
    preceded(char('#'), take_while(matcher))(i)
}

// ack-field        =  "Acknowledgments" fs SP uri
// can-field        =  "Canonical" fs SP uri
// contact-field    =  "Contact" fs SP uri
// expires-field    =  "Expires" fs SP date-time
// encryption-field =  "Encryption" fs SP uri
// hiring-field     =  "Hiring" fs SP uri
// lang-field       =  "Preferred-Languages" fs SP lang-values
// policy-field     =  "Policy" fs SP uri
// date-time        =  < imported from Section 5.6 of [RFC3339] >
// lang-tag         =  < Language-Tag from Section 2.1 of [RFC5646] >
// lang-values      =  lang-tag *(*WSP "," *WSP lang-tag)
// uri              =  < URI as per Section 3 of [RFC3986] >

// ext-field        =  field-name fs SP unstructured
fn ext_name_parser(i: &str) -> IResult<&str, RawField> {
    let (i, (name, _, _, value)) = tuple((field_name_parser, fs_parser, sp_parser, unstructured_parser))(i)?;
    Ok((i, RawField { name, value }))
}

// field-name       =  < imported from Section 3.6.8 of [RFC5322] >
// field-name       =  1*ftext
fn field_name_parser(i: &str) -> IResult<&str, &str> {
    take_while1(is_ftext_char)(i)
}

// field-name       =  < imported from Section 3.6.8 of [RFC5322] >
// ftext            =  %d33-57 /          ; Printable US-ASCII
//                     %d59-126           ;  characters not including
//                                        ;  ":".
fn is_ftext_char(i: char) -> bool {
    match i {
        '\x21'..='\x39' => true, // %d33-57
        '\x3B'..='\x7E' => true, // %d59-126
        _ => false,
    }
}

// < imported from [RFC5322] >
// unstructured     =   *([FWS] VCHAR) *WSP
// Ommitted obsolete part.
fn unstructured_parser(i: &str) -> IResult<&str, &str> {
    recognize(terminated(
        recognize(many0_count(preceded(opt(fws_parser), satisfy(is_vchar)))),
        take_while(is_wsp),
    ))(i)
}

// < imported from [RFC5322] >
// FWS              =   [*WSP CRLF] 1*WSP
// Ommitted obsolete part.
fn fws_parser(i: &str) -> IResult<&str, &str> {
    recognize(preceded(
        opt(tuple((take_while(is_wsp), crlf_parser))),
        take_while1(is_wsp),
    ))(i)
}

// CR               =  %x0D
//                       ; carriage return
fn is_cr(i: char) -> bool {
    i == '\r'
}
fn cr_parser(i: &str) -> IResult<&str, char> {
    satisfy(is_cr)(i)
}

// CRLF             =  CR LF
//                       ; Internet standard newline
fn crlf_parser(i: &str) -> IResult<&str, &str> {
    crlf(i)
}

// LF               =  %x0A
//                       ; linefeed
fn is_lf(i: char) -> bool {
    i == '\n'
}
fn lf_parser(i: &str) -> IResult<&str, char> {
    satisfy(is_lf)(i)
}

// SP               =  %x20
fn sp_parser(i: &str) -> IResult<&str, char> {
    char(' ')(i)
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

// signed           =  cleartext-header
//                     1*(hash-header)
//                     CRLF
//                     cleartext
//                     signature
fn signed_parser(i: &str) -> IResult<&str, Vec<Option<RawField>>> {
    let (_, (_, _, _, cleartext, _)) = all_consuming(tuple((
        cleartext_header_parser,
        many1_count(hash_header_parser),
        crlf_parser,
        cleartext_parser,
        signature_parser,
    )))(i)?;

    all_consuming(unsigned_parser)(cleartext)
}

// cleartext-header =  %s"-----BEGIN PGP SIGNED MESSAGE-----" CRLF
fn cleartext_header_parser(i: &str) -> IResult<&str, &str> {
    terminated(tag("-----BEGIN PGP SIGNED MESSAGE-----"), crlf_parser)(i)
}

// hash-header      =  %s"Hash: " hash-alg *("," hash-alg) CRLF
fn hash_header_parser(i: &str) -> IResult<&str, Vec<&str>> {
    delimited(tag("Hash: "), separated_list1(tag(","), hash_alg_parser), crlf_parser)(i)
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
    take_while1(is_token_char)(i)
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

// cleartext        =  *((line-dash / line-from / line-nodash) [CR] LF)
fn cleartext_parser(i: &str) -> IResult<&str, &str> {
    recognize(many0_count(tuple((
        alt((line_dash_parser, line_nodash_parser)),
        opt(cr_parser),
        lf_parser,
    ))))(i)
}

// line-dash        =  ("- ") "-" *UTF8-char-not-cr
//                        ; MUST include initial "- "
fn line_dash_parser(i: &str) -> IResult<&str, &str> {
    preceded(
        tag("- "),
        recognize(tuple((one_of("-"), take_while(|x| x != '\r' && x != '\n')))),
    )(i)
}

// line-nodash      =  ["- "] *UTF8-char-not-cr
//                       ; MAY include initial "- "
fn line_nodash_parser(i: &str) -> IResult<&str, &str> {
    preceded(
        opt(tag("- ")),
        recognize(opt(tuple((none_of("-"), take_while(|x| x != '\r' && x != '\n'))))),
    )(i)
}

// signature        =  armor-header
//                     armor-keys
//                     CRLF
//                     signature-data
//                     armor-tail
fn signature_parser(i: &str) -> IResult<&str, PGPSignature> {
    let (i, (_, keys, _, signature, _)) = tuple((
        armor_header_parser,
        armor_keys_parser,
        crlf_parser,
        signature_data_parser,
        armor_tail_parser,
    ))(i)?;

    Ok((i, PGPSignature { signature, keys }))
}

// armor-header     =  %s"-----BEGIN PGP SIGNATURE-----" CRLF
fn armor_header_parser(i: &str) -> IResult<&str, &str> {
    terminated(tag("-----BEGIN PGP SIGNATURE-----"), crlf_parser)(i)
}

// armor-keys       =  *(token ": " *( VCHAR / WSP ) CRLF)
//                       ; Armor Header Keys from RFC 4880
fn armor_keys_parser(i: &str) -> IResult<&str, Vec<(&str, &str)>> {
    many0(terminated(
        separated_pair(token_parser, tag(": "), take_while(|x| is_vchar(x) || is_wsp(x))),
        crlf_parser,
    ))(i)
}

// armor-tail       =  %s"-----END PGP SIGNATURE-----" CRLF
fn armor_tail_parser(i: &str) -> IResult<&str, &str> {
    terminated(tag("-----END PGP SIGNATURE-----"), crlf_parser)(i)
}

// signature-data   =  1*(1*(ALPHA / DIGIT / "=" / "+" / "/") CRLF)
//                       ; base64; see RFC 4648
//                       ; includes RFC 4880 checksum
fn signature_data_parser(i: &str) -> IResult<&str, &str> {
    recognize(many1_count(terminated(
        take_while1(is_signature_data_char),
        crlf_parser,
    )))(i)
}
fn is_signature_data_char(i: char) -> bool {
    matches!(i, 'a'..='z' | 'A'..='Z' | '0'..='9' | '=' | '+' | '/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn get_tests_dir(category: &str) -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(format!("resources/test/{category}"));
        d
    }

    fn run_tests_from_dir(dir: &str) {
        let paths = get_tests_dir(dir).read_dir().unwrap();

        for path in paths {
            let file = path.unwrap().path();
            println!("Input file: {:?}", file);
            let buf = fs::read_to_string(file).unwrap();
            let txt = body_parser(&buf);
            assert_eq!(txt.is_ok(), true);
        }
    }

    #[test]
    fn test_category_gen_unsigned() {
        run_tests_from_dir("gen_unsigned")
    }

    #[test]
    fn test_line_parser() {
        let test_vector = vec![
            ("\n", None),
            ("\t \r\n", None),
            ("# This is a comment.\n", None),
            (
                "foo: bar\r\n",
                Some(RawField {
                    name: "foo",
                    value: "bar",
                }),
            ),
        ];

        for (input, result) in test_vector {
            assert_eq!(line_parser(input), Ok(("", result)));
        }
    }

    #[test]
    fn test_cleartext_parser() {
        let test_vector = vec![("- -\r\n", "-")];

        for (input, result) in test_vector {
            assert_eq!(cleartext_parser(input), Ok(("", result)));
        }
    }
}
