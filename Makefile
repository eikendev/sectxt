TARGET_DIR := ./target
FUZZ_DIR := ./fuzz

.PHONY: build
build: build_bin docs

.PHONY: build_bin
build_bin:
	cargo build -p sectxtlib
	cargo build -p sectxt

.PHONY: docs
docs:
	cargo doc -p sectxtlib

.PHONY: test
test:
	cargo fmt -p sectxtlib --check
	cargo fmt -p sectxt --check
	cargo clippy -p sectxtlib --all-features -- -D warnings
	cargo clippy -p sectxt --all-features -- -D warnings
	cargo test

.PHONY: setup
setup:
	rustup update
	rustup component add clippy
	rustup component add rustfmt
	rustup show
	cargo install cargo-afl

.PHONY: publish
publish:
	cargo publish -p sectxtlib
	cargo publish -p sectxt

.PHONY: fuzz
fuzz:
	cargo afl build -p sectxtfuzz
	AFL_SKIP_CPUFREQ=1 cargo afl fuzz -i $(FUZZ_DIR)/_examples -o $(FUZZ_DIR)/afl $(TARGET_DIR)/debug/sectxtfuzz
