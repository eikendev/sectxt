<div align="center">
	<h1>sectxt</h1>
	<h4 align="center">
		The <a href="https://securitytxt.org/">security.txt standard</a> helps us make the Internet more secure.
	</h4>
	<p>sectxt lets you work with security.txt files on the command line.</p>
</div>

<p align="center">
	<a href="https://github.com/eikendev/sectxt/actions"><img alt="Build status" src="https://img.shields.io/github/workflow/status/eikendev/sectxt/Main"/></a>&nbsp;
	<a href="https://github.com/eikendev/sectxt/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/eikendev/sectxt"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxt"><img alt="Version" src="https://img.shields.io/crates/v/sectxt"/></a>&nbsp;
	<a href="https://crates.io/crates/sectxt"><img alt="Downloads" src="https://img.shields.io/crates/d/sectxt"/></a>&nbsp;
</p>

## 🚀&nbsp;Installation

```bash
cargo install sectxt
```

## 📄&nbsp;Usage

This tool can be used to determine the adoption of the [security.txt standard](https://securitytxt.org/) among several domains.
You feed it a list of domains and it will tell you which of them implement the standard already.
```bash
sectxt < domains.txt
```

The idea was ~~shamelessly stolen from~~ inspired by [haksecuritytxt](https://github.com/hakluke/haksecuritytxt).
So why did I recreate a tool that already exists?
Admittedly, the main motivation was to play around with [Rust](https://www.rust-lang.org/)'s new `async`/`await` syntax and learn something new.
Besides, I wanted to enforce stricter checks for the standard, i.e., the server must answer with the correct `Content-Type` header, which leads to more accurate results.

### Example

Moz maintains a [list of popular websites](https://moz.com/top500).
Running `./scripts/checktop500` downloads that list, and runs `sectxt` against it.
As a result, you will see which of these websites deploy a `security.txt` file.

For the shell script to run you need to install [xsv](https://github.com/BurntSushi/xsv), which is another convenient utility by [BurntSushi](https://github.com/BurntSushi).
