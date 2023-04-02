#[derive(Debug, PartialEq)]
pub(crate) struct RawField<'a> {
    pub name: &'a str,
    pub value: &'a str,
}
