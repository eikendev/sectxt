use argh::FromArgs;

#[derive(FromArgs)]
/// A tool for working with security.txt files.
pub struct Settings {
    /// number of simultaneous domains to process
    #[argh(option, default = "30")]
    pub threads: usize,

    /// seconds to wait before giving up a domain
    #[argh(option, default = "3")]
    pub timeout: u64,

    /// whether to be strict with line endings or more relaxed
    #[argh(switch)]
    pub strict: bool,

    /// only print domains for which the run was successful
    #[argh(switch, short = 'q')]
    pub quiet: bool,

    /// print statistics before exit
    #[argh(switch)]
    pub print_stats: bool,
}
