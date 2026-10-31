#!/bin/bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
E2E_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
ARCHIVE="${E2E_DIR}/../dockerfiles/stripe-roa-system.zip"
PATCH_FILE="${E2E_DIR}/patches/routinator-legacy-safe-rtr.patch"

bash "${SCRIPT_DIR}/build-images.sh"

if docker image inspect stripe-routinator-staged:latest >/dev/null 2>&1; then
    echo "staged legacy-safe Routinator image already exists"
    exit 0
fi

if [ ! -f "${ARCHIVE}" ]; then
    echo "missing source archive: ${ARCHIVE}" >&2
    exit 1
fi

build_dir=$(mktemp -d /tmp/daroa-staged-images.XXXXXX)
trap 'rm -rf "${build_dir}"' EXIT
unzip -q "${ARCHIVE}" -d "${build_dir}"

source_root="${build_dir}/dockerfiles/stripe-roa-routinator"
patch -d "${source_root}" -p1 < "${PATCH_FILE}"
sed -i \
    's/default = \[ "socks", "ui"\]/default = [ "socks"]/' \
    "${source_root}/routinator/Cargo.toml"

docker build \
    -t stripe-routinator-staged:latest \
    "${source_root}"
