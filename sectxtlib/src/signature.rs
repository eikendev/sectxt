#[derive(Debug, PartialEq)]
pub(crate) struct PGPSignature<'a> {
    pub signature: &'a str,
    pub keys: Vec<(&'a str, &'a str)>,
}
