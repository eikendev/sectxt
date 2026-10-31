use thiserror::Error;

/// The reason a security.txt file was rejected
///
/// Parsing stops at the first problem, so a file with several problems reports only one of them.
/// Field names are reported as they appear in RFC 9116, for example `Contact`.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ParseError {
    /// The file does not follow the grammar in [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)
    #[error("invalid syntax on line {line}")]
    Malformed {
        /// The 1-based line on which parsing stopped
        line: usize,
    },
    /// A field's value is not a valid URI
    #[error("field {field} has an invalid URI")]
    InvalidUri {
        /// The name of the offending field
        field: &'static str,
        /// The underlying URI error
        #[source]
        source: iri_string::validate::Error,
    },
    /// The "Expires" field is not a valid [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) date and time
    #[error("field Expires has an invalid date and time")]
    InvalidDatetime {
        /// The underlying date and time error
        #[source]
        source: chrono::format::ParseError,
    },
    /// The "Preferred-Languages" field contains a tag that is not a valid
    /// [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646) language tag
    #[error("field Preferred-Languages has an invalid language tag {tag:?}")]
    InvalidLanguageTag {
        /// The offending tag, as written in the file
        tag: String,
    },
    /// The file has no "Contact" field, which the RFC requires at least once
    #[error("field Contact must be specified")]
    ContactFieldMissing,
    /// The file has no "Expires" field, which the RFC requires exactly once
    #[error("field Expires must be specified")]
    ExpiresFieldMissing,
    /// The "Expires" field lies before the reference time, so the file is stale
    #[error("field Expires specifies a time in the past")]
    ExpiresFieldExpired,
    /// The "Expires" field appears more than once
    #[error("field Expires may only be specified once")]
    ExpiresFieldMultiple,
    /// The "Preferred-Languages" field appears more than once
    #[error("field Preferred-Languages may only be specified once")]
    PreferredLanguagesFieldMultiple,
    /// A field links to a web URI with the `http` scheme, which the RFC forbids
    #[error("field {field} must use HTTPS")]
    InsecureHTTP {
        /// The name of the offending field
        field: &'static str,
    },
}

impl ParseError {
    /// Builds a [`ParseError::Malformed`] from a nom error, locating the line on which the
    /// parser stopped. `text` is the complete input the parser ran on.
    pub(crate) fn malformed(text: &str, err: &nom::Err<nom::error::Error<&str>>) -> Self {
        let remaining = match err {
            nom::Err::Error(e) | nom::Err::Failure(e) => e.input,
            nom::Err::Incomplete(_) => "",
        };
        let consumed = text.len().saturating_sub(remaining.len());
        let line = text[..consumed].matches('\n').count() + 1;

        Self::Malformed { line }
    }

    /// Shifts the line number of a [`ParseError::Malformed`] by `offset` lines. Used when the
    /// parsed text was embedded in a larger document.
    pub(crate) fn offset_line(self, offset: usize) -> Self {
        match self {
            Self::Malformed { line } => Self::Malformed { line: line + offset },
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed_line() {
        let text = "a\nb\nc";
        let err = nom::Err::Error(nom::error::Error::new(&text[4..], nom::error::ErrorKind::Tag));
        assert_eq!(ParseError::malformed(text, &err), ParseError::Malformed { line: 3 });

        let err = nom::Err::Error(nom::error::Error::new(text, nom::error::ErrorKind::Tag));
        assert_eq!(ParseError::malformed(text, &err), ParseError::Malformed { line: 1 });
    }

    #[test]
    fn test_offset_line() {
        assert_eq!(
            ParseError::Malformed { line: 2 }.offset_line(3),
            ParseError::Malformed { line: 5 }
        );
        assert_eq!(
            ParseError::ContactFieldMissing.offset_line(3),
            ParseError::ContactFieldMissing
        );
    }
}
