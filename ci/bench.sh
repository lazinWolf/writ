#!/usr/bin/env bash
# Builds writ in release mode and measures per-call proxy overhead.
# Extra arguments go to bench_wrap.py, e.g. `ci/container.sh ci/bench.sh --calls 20000`.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release --locked -p writ-cli
python3 ci/bench_wrap.py "${CARGO_TARGET_DIR:-target}/release/writ" "$@"
