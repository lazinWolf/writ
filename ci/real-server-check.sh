#!/usr/bin/env bash
# Builds writ and checks it against the MCP reference server from npm.
# Downloads and runs third-party code: use `ci/container.sh ci/real-server-check.sh`.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release --locked -p writ-cli
python3 ci/real_server_check.py "${CARGO_TARGET_DIR:-target}/release/writ"
