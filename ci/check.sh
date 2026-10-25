#!/usr/bin/env bash
# Format, lint, and test. Runs anywhere with cargo and python3; CI runs it in the container.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
