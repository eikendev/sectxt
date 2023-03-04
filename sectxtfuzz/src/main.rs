use afl::*;
use sectxtlib::SecurityTxt;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = SecurityTxt::try_from(s);
        }
    });
}
