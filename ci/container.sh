#!/usr/bin/env bash
# Runs a command inside the writ dev container, e.g. `ci/container.sh ci/check.sh`.
# CONTAINER_ENGINE=docker selects Docker instead of Podman.
set -euo pipefail
cd "$(dirname "$0")/.."

engine="${CONTAINER_ENGINE:-podman}"
image="${WRIT_IMAGE:-writ-dev}"

"$engine" build --quiet --file ci/Containerfile --tag "$image" . >/dev/null
exec "$engine" run --rm \
    --volume writ-cargo:/cargo \
    --volume writ-target:/target \
    "$image" "$@"
