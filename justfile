# peer-observer-agents justfile

export PATH := env("HOME") / ".cargo/bin:" + env("PATH")

# Run tests
test:
    cargo test

# Build debug binary
build:
    cargo build

# Build release binary
build-release:
    cargo build --release

# Run clippy lints (strict: all targets and features)
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Check formatting
fmt-check:
    cargo fmt --check

# Format code
fmt:
    cargo fmt

# Run all checks (fmt, clippy)
check: fmt-check clippy

# Build via nix flake
nix-build:
    nix build

# Clean build artifacts
clean:
    cargo clean

# Show current version from Cargo.toml
version:
    @grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'

# Run quality gates (check + test). Nix build runs in CI only (Linux targets).
pre-release: check test

# Tag a release (bump type: major, minor, patch)
release bump:
    ./scripts/release.sh {{bump}}

# Dry-run a release to see what would happen
release-dry-run bump:
    ./scripts/release.sh {{bump}} --dry-run
