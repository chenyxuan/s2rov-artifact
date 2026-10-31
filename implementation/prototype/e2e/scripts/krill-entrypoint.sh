#!/bin/bash
set -euo pipefail

: "${KRILL_CLI_TOKEN:?KRILL_CLI_TOKEN must be set}"

mkdir -p <home>/data <home>/data/rsync_cer /run/nginx
sed "s/__ADMIN_TOKEN__/${KRILL_CLI_TOKEN}/" \
    /opt/s2rov/krill.conf.template > <home>/data/krill.conf
rm -f <home>/data/krill.pid

if [ ! -s /etc/pki/CA/server.crt ] || [ ! -s /etc/pki/CA/server.key ]; then
    server_ip=$(hostname -i | cut -d " " -f1)
    /etc/pki/CA/generate_ca.sh "${server_ip}" krill \
        > <home>/data/tls-bootstrap.log 2>&1
fi

nginx
rsync --daemon
exec krill -c <home>/data/krill.conf
