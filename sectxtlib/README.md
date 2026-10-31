<div align="center">
	<h1>sectxtlib</h1>
	<h4 align="center">
		The <a href="https://securitytxt.org/">security.txt standard</a> helps us make the Internet more secure.
	</h4>
	<p>sectxtlib parses and validates security.txt files as specified in RFC 9116.</p>
</div>

<p align="center">
	<a href="https://github.com/eikendev/sectxt/actions"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/eikendev/sectxt/pr.yaml?branch=main"/></a>&nbsp;
	<a href="https://github.com/eikendev/sectxt/blob/main/LICENSE"><img alt="License" src="https://img.shields.io/github/license/eikendev/sectxt"/></a>&nbsp;
	<a href="https://docs.rs/sectxtlib/latest/sectxtlib/"><img alt="Docs" src="https://img.shields.io/docsrs/sectxtlib"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxtlib"><img alt="Version" src="https://img.shields.io/crates/v/sectxtlib"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxtlib"><img alt="Downloads" src="https://img.shields.io/crates/d/sectxtlib"/></a>&nbsp;
</p>

## 📄&nbsp;Usage

```rust
use sectxtlib::SecurityTxt;

let text = "Contact: https://example.com/security\nExpires: 2999-01-01T00:00:00Z\n";
let sectxt: SecurityTxt = text.parse()?;

assert_eq!(sectxt.contact[0].uri.as_str(), "https://example.com/security");
```

Invalid files are rejected with a `ParseError` that names the violated rule.
Enable the `serde` feature to serialize the parsed file.

See [the documentation](https://docs.rs/sectxtlib/latest/sectxtlib/) for more examples.
