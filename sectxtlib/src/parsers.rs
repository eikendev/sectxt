use crate::{ParseError, SecurityTxtOptions};

use super::raw_field::RawField;

use nom::{
    branch::alt,
    bytes::complete::{take_while, take_while1},
    character::complete::{char, crlf, satisfy},
    combinator::{all_consuming, map, opt, recognize},
    multi::{many0_count, many1},
    sequence::{preceded, terminated},
    IResult, Parser,
};

pub(crate) struct SecurityTxtParser {
    _options: SecurityTxtOptions,
}

impl SecurityTxtParser {
    pub fn new(options: &SecurityTxtOptions) -> Self {
        Self {
            _options: options.clone(),
        }
    }

    pub fn parse<'a>(&'a self, text: &'a str) -> Result<Vec<Option<RawField<'a>>>, ParseError> {
        let (_, msg) = self.body_parser(text)?;
        Ok(msg)
    }

    // body             =  signed / unsigned
    // signed is handled separately.
    fn body_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, Vec<Option<RawField<'a>>>> {
        all_consuming(|x| self.unsigned_parser(x)).parse(i)
    }

    // unsigned       =  *line (contact-field eol) ; one or more required
    //                   *line (expires-field eol) ; exactly one required
    //                   *line [lang-field eol] *line ; exactly one optional
    //                   ; order of fields within the file is not important
    //                   ; except that if contact-field appears more
    //                   ; than once, the order of those indicates
    //                   ; priority (see Section 3.5.3)
    fn unsigned_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, Vec<Option<RawField<'a>>>> {
        many1(|x| self.line_parser(x)).parse(i)
    }

    // line             =  [ (field / comment) ] eol
    fn line_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, Option<RawField<'a>>> {
        let field_parser_opt = map(|x| self.field_parser(x), Some);
        let comment_parser_opt = map(|x| self.comment_parser(x), |_| None);

        let (i, raw_field) =
            terminated(opt(alt((comment_parser_opt, field_parser_opt))), |x| self.eol_parser(x)).parse(i)?;
        let flattened = raw_field.flatten();
        Ok((i, flattened))
    }

    // eol              =  *WSP [CR] LF
    fn eol_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, &'a str> {
        recognize((take_while(is_wsp), opt(|x| self.cr_parser(x)), |x| self.lf_parser(x))).parse(i)
    }

    // field            =  ; optional fields
    //                     ack-field /
    //                     can-field /
    //                     contact-field / ; optional repeated instances
    //                     encryption-field /
    //                     hiring-field /
    //                     policy-field /
    //                     ext-field
    fn field_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, RawField<'a>> {
        self.ext_name_parser(i)
    }

    // fs               =  ":"
    fn fs_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, char> {
        char(':').parse(i)
    }

    // comment          =  "#" *(WSP / VCHAR / %x80-FFFFF)
    fn comment_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, &'a str> {
        let matcher = |x| is_wsp(x) || is_vchar(x) || x >= '\u{80}';
        preceded(char('#'), take_while(matcher)).parse(i)
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
    fn ext_name_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, RawField<'a>> {
        let (i, (name, _, _, value)) = (
            |x| self.field_name_parser(x),
            |x| self.fs_parser(x),
            |x| self.sp_parser(x),
            |x| self.unstructured_parser(x),
        )
            .parse(i)?;
        Ok((i, RawField { name, value }))
    }

    // field-name       =  < imported from Section 3.6.8 of [RFC5322] >
    // field-name       =  1*ftext
    fn field_name_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, &'a str> {
        take_while1(is_ftext_char).parse(i)
    }

    // < imported from [RFC5322] >
    // unstructured     =   *([FWS] VCHAR) *WSP
    // Ommitted obsolete part.
    fn unstructured_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, &'a str> {
        recognize(terminated(
            recognize(many0_count(preceded(opt(|x| self.fws_parser(x)), satisfy(is_vchar)))),
            take_while(is_wsp),
        ))
        .parse(i)
    }

    // < imported from [RFC5322] >
    // FWS              =   [*WSP CRLF] 1*WSP
    // Ommitted obsolete part.
    fn fws_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, &'a str> {
        recognize(preceded(
            opt((take_while(is_wsp), |x| self.crlf_parser(x))),
            take_while1(is_wsp),
        ))
        .parse(i)
    }

    fn cr_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, char> {
        satisfy(is_cr).parse(i)
    }

    // CRLF             =  CR LF
    //                       ; Internet standard newline
    fn crlf_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, &'a str> {
        crlf.parse(i)
    }

    fn lf_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, char> {
        satisfy(is_lf).parse(i)
    }

    // SP               =  %x20
    fn sp_parser<'a>(&'a self, i: &'a str) -> IResult<&'a str, char> {
        char(' ').parse(i)
    }
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

// CR               =  %x0D
//                       ; carriage return
fn is_cr(i: char) -> bool {
    i == '\r'
}

// LF               =  %x0A
//                       ; linefeed
fn is_lf(i: char) -> bool {
    i == '\n'
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
    use std::{fs, path::PathBuf};

    fn get_tests_dir(category: &str) -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(format!("resources/test/{category}"));
        d
    }

    fn run_tests_from_dir(dir: &str) {
        let unsigned_parser = SecurityTxtParser::new(&Default::default());
        let paths = get_tests_dir(dir).read_dir().unwrap();

        for path in paths {
            let file = path.unwrap().path();
            println!("Input file: {:?}", file);
            let buf = fs::read_to_string(file).unwrap();
            let txt = unsigned_parser.parse(&buf);
            assert!(txt.is_ok());
        }
    }

    #[test]
    fn test_category_gen_unsigned() {
        run_tests_from_dir("gen_unsigned")
    }

    #[test]
    fn test_line_parser() {
        let unsigned_parser = SecurityTxtParser::new(&Default::default());
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
            assert_eq!(unsigned_parser.line_parser(input), Ok(("", result)));
        }
    }
}
