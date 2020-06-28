[![Build status](https://img.shields.io/travis/eikendev/sectxtcov/master)](https://travis-ci.org/github/eikendev/sectxtcov/builds/)
[![License](https://img.shields.io/crates/l/sectxtcov)](https://crates.io/crates/sectxtcov)
[![Version](https://img.shields.io/crates/v/sectxtcov)](https://crates.io/crates/sectxtcov)
[![Downloads](https://img.shields.io/crates/d/sectxtcov)](https://crates.io/crates/sectxtcov)

## About

This tool can be used to determine the coverage of the [security.txt standard](https://securitytxt.org/) among several domains.
You feed it a list of domains and it will tell you how many of them implement the standard already.
```bash
sectxtcov < domains.txt
```

The idea was ~~shamelessly stolen from~~ inspired by [haksecuritytxt](https://github.com/hakluke/haksecuritytxt).
So why did I recreate a tool that already exists?
Admittedly, the main motivation was to play around with [Rust](https://www.rust-lang.org/)'s new `async`/`await` syntax and learn something new.
Besides, I wanted to enforce stricter checks for the standard, i.e., the server must answer with the correct `Content-Type` header, which leads to more accurate results.

## Usage

Mozilla maintains a [list of popular websites](https://moz.com/top500).
Running `./checktop500` downloads that list, and runs `sectxtcov` against it.
As a result, you will see how many of these websites deploy a `security.txt` file.

For the script to run you need to install [xsv](https://github.com/BurntSushi/xsv), which is another convenient utility by [BurntSushi](https://github.com/BurntSushi).
