use super::types::RawField;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while},
    character::complete::{char, line_ending, not_line_ending},
    combinator::all_consuming,
    multi::many1,
    sequence::tuple,
    IResult,
};

fn is_field_name_char(c: char) -> bool {
    c.is_ascii() && !c.is_control() && !(c == ':') && !(c == ' ')
}

fn field_line_parser(i: &str) -> IResult<&str, Option<RawField>> {
    let (i, (name, _, value, _)) = tuple((take_while(is_field_name_char), tag(": "), not_line_ending, line_ending))(i)?;

    Ok((i, Some(RawField { name, value })))
}

fn comment_line_parser(i: &str) -> IResult<&str, Option<RawField>> {
    let (i, _) = tuple((char('#'), not_line_ending, line_ending))(i)?;

    Ok((i, None))
}

fn eol_line_parser(i: &str) -> IResult<&str, Option<RawField>> {
    let (i, _) = line_ending(i)?;

    Ok((i, None))
}

pub fn line_parser(i: &str) -> IResult<&str, Vec<Option<RawField>>> {
    let one_line = alt((field_line_parser, comment_line_parser, eol_line_parser));

    all_consuming(many1(one_line))(i)
}
