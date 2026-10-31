#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
E2E_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
ARCHIVE="${E2E_DIR}/../dockerfiles/stripe-roa-system.zip"

if docker image inspect stripe-testbed:latest >/dev/null 2>&1 \
    && docker image inspect stripe-routinator:latest >/dev/null 2>&1; then
    echo "custom Krill and Routinator images already exist"
    exit 0
fi

if [ ! -f "${ARCHIVE}" ]; then
    echo "missing source archive: ${ARCHIVE}" >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d /tmp/daroa-images.XXXXXX)
trap 'rm -rf "${BUILD_DIR}"' EXIT
unzip -q "${ARCHIVE}" -d "${BUILD_DIR}"

if ! docker image inspect stripe-testbed:latest >/dev/null 2>&1; then
    docker build \
        -t stripe-testbed:latest \
        "${BUILD_DIR}/dockerfiles/testbed"
fi

if ! docker image inspect stripe-routinator:latest >/dev/null 2>&1; then
    sed -i \
        's/default = \\[ \"socks\", \"ui\"\\]/default = [ \"socks\"]/' \
        "${BUILD_DIR}/dockerfiles/stripe-roa-routinator/routinator/Cargo.toml"
    docker build \
        -t stripe-routinator:latest \
        "${BUILD_DIR}/dockerfiles/stripe-roa-routinator"
fi
