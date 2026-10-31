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
	RUSTDOCFLAGS="-D warnings" cargo doc -p sectxtlib --all-features --no-deps

.PHONY: test
test: docs
	cargo fmt -p sectxtlib --check
	cargo fmt -p sectxt --check
	cargo clippy -p sectxtlib --all-features --all-targets -- -D warnings
	cargo clippy -p sectxt --all-features -- -D warnings
	cargo test -p sectxtlib --all-features
	cargo test -p sectxt

.PHONY: setup
setup:
	rustup update
	rustup component add clippy
	rustup component add rustfmt
	rustup show

.PHONY: setup_fuzz
setup_fuzz: setup
	cargo install cargo-afl

.PHONY: publish_check
publish_check:
	cargo publish --dry-run --locked --workspace

.PHONY: fuzz
fuzz: setup_fuzz
	cargo afl build -p sectxtfuzz
	AFL_SKIP_CPUFREQ=1 cargo afl fuzz -i $(FUZZ_DIR)/_examples -o $(FUZZ_DIR)/afl $(TARGET_DIR)/debug/sectxtfuzz
