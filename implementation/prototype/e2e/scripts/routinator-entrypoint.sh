#!/bin/bash
set -euo pipefail

mkdir -p <home>/tals <home>/rpki-cache
rm -f <home>/tals/krill.tal

for _ in $(seq 1 90); do
    if wget -q --no-check-certificate \
        -O <home>/tals/krill.tal https://krill/ta/ta.tal; then
        break
    fi
    sleep 1
done

if [ ! -s <home>/tals/krill.tal ]; then
    echo "failed to download the Krill TAL" >&2
    exit 1
fi

exec routinator \
    --extra-tals-dir=<home>/tals \
    --disable-rsync \
    --validation-threads=2 \
    server \
    --rtr 0.0.0.0:3323 \
    --http 0.0.0.0:3333 \
    --refresh 2
