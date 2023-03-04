use super::raw_field::RawField;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while},
    character::complete::{char, line_ending, not_line_ending},
    combinator::all_consuming,
    multi::{many0, many1},
    sequence::{delimited, tuple},
    IResult,
};

pub fn body_parser(i: &str) -> IResult<&str, Vec<Option<RawField>>> {
    all_consuming(alt((signed_parser, unsigned_parser)))(i)
}

fn signed_parser(i: &str) -> IResult<&str, Vec<Option<RawField>>> {
    delimited(sign_header_parser, unsigned_parser, sign_footer_parser)(i)
}

fn cleartext_header_parser(i: &str) -> IResult<&str, &str> {
    tag("-----BEGIN PGP SIGNED MESSAGE-----\n")(i)
}

fn hash_armor_header_parser(i: &str) -> IResult<&str, &str> {
    delimited(tag("Hash: "), not_line_ending, line_ending)(i)
}

fn hash_armor_headers_parser(i: &str) -> IResult<&str, Vec<&str>> {
    many0(hash_armor_header_parser)(i)
}

fn sign_header_parser(i: &str) -> IResult<&str, Vec<&str>> {
    delimited(cleartext_header_parser, hash_armor_headers_parser, line_ending)(i)
}

fn armor_header_parser(i: &str) -> IResult<&str, &str> {
    tag("-----BEGIN PGP SIGNATURE-----\n")(i)
}

fn signature_parser(i: &str) -> IResult<&str, &str> {
    take_until("-----END PGP SIGNATURE-----\n")(i)
}

fn armor_tail_parser(i: &str) -> IResult<&str, &str> {
    tag("-----END PGP SIGNATURE-----\n")(i)
}

fn sign_footer_parser(i: &str) -> IResult<&str, &str> {
    delimited(armor_header_parser, signature_parser, armor_tail_parser)(i)
}

fn unsigned_parser(i: &str) -> IResult<&str, Vec<Option<RawField>>> {
    many1(line_parser)(i)
}

fn line_parser(i: &str) -> IResult<&str, Option<RawField>> {
    alt((field_parser, comment_parser, eol_parser))(i)
}

fn is_field_name_char(c: char) -> bool {
    c.is_ascii() && !c.is_control() && (c != ':') && (c != ' ')
}

fn field_parser(i: &str) -> IResult<&str, Option<RawField>> {
    let (i, (name, _, value, _)) = tuple((take_while(is_field_name_char), tag(": "), not_line_ending, line_ending))(i)?;
    Ok((i, Some(RawField { name, value })))
}

fn comment_parser(i: &str) -> IResult<&str, Option<RawField>> {
    let (i, _) = tuple((char('#'), not_line_ending, line_ending))(i)?;
    Ok((i, None))
}

fn eol_parser(i: &str) -> IResult<&str, Option<RawField>> {
    let (i, _) = line_ending(i)?;
    Ok((i, None))
}
