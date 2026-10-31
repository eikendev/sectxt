# Changelog

All notable changes to this project are documented below.

## [0.5.0](https://github.com/eikendev/sectxt/compare/sectxtlib-v0.4.2...sectxtlib-v0.5.0) - 2026-10-31

### Bug Fixes

- export CsafField from sectxtlib

### Documentation

- fix README badges and add usage example
- *(sectxtlib)* document ParseError and options
- *(sectxtlib)* add crate docs and examples

### Features

- *(sectxtlib)* [**breaking**] report line and field in errors
- *(sectxtlib)* [**breaking**] add SecurityTxt::is_signed
- *(sectxtlib)* [**breaking**] drop PartialOrd for SecurityTxt
- [**breaking**] drop strict option, add option setters
- *(sectxtlib)* put valuable behind a feature
- *(sectxtlib)* add Clone, Eq and serde support
- *(sectxtlib)* implement Display for field types

## [0.4.2](https://github.com/eikendev/sectxt/compare/sectxtlib-v0.4.1...sectxtlib-v0.4.2) - 2026-09-20

### Bug Fixes

- require nom 8 and bound chrono to 0.4

### Features

- move workspace to Rust edition 2024

## [0.4.1](https://github.com/eikendev/sectxt/compare/sectxtlib-v0.4.0...sectxtlib-v0.4.1) - 2026-09-19

### Build

- prepare packaging for automated releases
