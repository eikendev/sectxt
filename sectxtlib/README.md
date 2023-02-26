# sectxtlib

<p align="center">
	<a href="https://github.com/eikendev/sectxt/actions"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/eikendev/sectxt/main.yml?branch=main"/></a>&nbsp;
	<a href="https://github.com/eikendev/sectxt/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/eikendev/sectxt"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxtlib"><img alt="Version" src="https://img.shields.io/crates/v/sectxtlib"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxtlib"><img alt="Downloads" src="https://img.shields.io/crates/d/sectxtlib"/></a>&nbsp;
</p>

## 📄&nbsp;Usage

This library can be used to parse a [security.txt file](https://securitytxt.org/).
Check out how [sectxt](https://github.com/eikendev/sectxt) uses it for example:
```rust
async fn is_securitytxt(r: reqwest::Response) -> bool {
    if r.status() == reqwest::StatusCode::OK {
        if let Ok(s) = r.text().await {
            return SecurityTxt::try_from(&s[..]).is_ok();
        }
    }

    false
}
```
