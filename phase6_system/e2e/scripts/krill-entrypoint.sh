#!/bin/bash
set -euo pipefail

: "${KRILL_CLI_TOKEN:?KRILL_CLI_TOKEN must be set}"

mkdir -p /home/cnic/data /home/cnic/data/rsync_cer /run/nginx
sed "s/__ADMIN_TOKEN__/${KRILL_CLI_TOKEN}/" \
    /opt/daroa/krill.conf.template > /home/cnic/data/krill.conf
rm -f /home/cnic/data/krill.pid

if [ ! -s /etc/pki/CA/server.crt ] || [ ! -s /etc/pki/CA/server.key ]; then
    server_ip=$(hostname -i | cut -d " " -f1)
    /etc/pki/CA/generate_ca.sh "${server_ip}" krill \
        > /home/cnic/data/tls-bootstrap.log 2>&1
fi

nginx
rsync --daemon
exec krill -c /home/cnic/data/krill.conf
