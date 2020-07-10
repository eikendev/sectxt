[![Build status](https://img.shields.io/travis/eikendev/sectxt/master)](https://travis-ci.com/github/eikendev/sectxt/builds/)
[![License](https://img.shields.io/crates/l/sectxt)](https://crates.io/crates/sectxt)
[![Version](https://img.shields.io/crates/v/sectxt)](https://crates.io/crates/sectxt)
[![Downloads](https://img.shields.io/crates/d/sectxt)](https://crates.io/crates/sectxt)

## About

This tool can be used to determine the adoption of the [security.txt standard](https://securitytxt.org/) among several domains.
You feed it a list of domains and it will tell you which of them implement the standard already.
```bash
sectxt < domains.txt
```

The idea was ~~shamelessly stolen from~~ inspired by [haksecuritytxt](https://github.com/hakluke/haksecuritytxt).
So why did I recreate a tool that already exists?
Admittedly, the main motivation was to play around with [Rust](https://www.rust-lang.org/)'s new `async`/`await` syntax and learn something new.
Besides, I wanted to enforce stricter checks for the standard, i.e., the server must answer with the correct `Content-Type` header, which leads to more accurate results.

## Usage

Mozilla maintains a [list of popular websites](https://moz.com/top500).
Running `./checktop500` downloads that list, and runs `sectxt` against it.
As a result, you will see which of these websites deploy a `security.txt` file.

For the shell script to run you need to install [xsv](https://github.com/BurntSushi/xsv), which is another convenient utility by [BurntSushi](https://github.com/BurntSushi).
