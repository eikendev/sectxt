<div align="center">
	<h1>sectxt</h1>
	<h4 align="center">
		The <a href="https://securitytxt.org/">security.txt standard</a> helps us make the Internet more secure.
	</h4>
	<p>sectxt lets you work with security.txt files on the command line.</p>
</div>

<p align="center">
	<a href="https://github.com/eikendev/sectxt/actions"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/eikendev/sectxt/release.yaml?branch=main"/></a>&nbsp;
	<a href="https://github.com/eikendev/sectxt/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/eikendev/sectxt"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxt"><img alt="Version" src="https://img.shields.io/crates/v/sectxt"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxt"><img alt="Downloads" src="https://img.shields.io/crates/d/sectxt"/></a>&nbsp;
</p>

## 🚀&nbsp;Installation

Prebuilt Linux binaries are attached to each [release](https://github.com/eikendev/sectxt/releases) and can be installed with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall):

```bash
cargo binstall sectxt
```

On other platforms there is no prebuilt binary, and `cargo binstall` falls back to building from source. Build from source directly instead:

```bash
RUSTFLAGS="--cfg tracing_unstable" cargo install sectxt
```

The flag is required when building from source; please refer to [issue #15](https://github.com/eikendev/sectxt/issues/15) for details.

## 📄&nbsp;Usage

Feed `sectxt` a list of domains and it tells you which of them implement [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) correctly.
```bash
sectxt < domains.txt
```

## 👮&nbsp;Acknowledgments

The idea was ~~shamelessly stolen from~~ inspired by [haksecuritytxt](https://github.com/hakluke/haksecuritytxt).
The main motivation was to play around with [Rust](https://www.rust-lang.org/)'s new `async`/`await` syntax and learn something new.
Besides, `sectxt` enforces stricter checks against the [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).
