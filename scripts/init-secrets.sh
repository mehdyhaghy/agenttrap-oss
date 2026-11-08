#!/bin/sh
# Creates local secrets for the single-node deployment. Never commit them.
#
# The secrets/ directory is 0700, so other host users cannot read anything in
# it. The files themselves are 0644 because Docker bind-mounts them with host
# permissions, and the hub runs as an unprivileged user (uid 65532).
set -eu
cd "$(dirname "$0")/.."
mkdir -p secrets
chmod 700 secrets
[ -f secrets/db_password ] || openssl rand -hex 24 > secrets/db_password
[ -f secrets/admin_token ] || openssl rand -hex 32 > secrets/admin_token
if [ ! -f secrets/tls/dev.crt ]; then
  mkdir -p secrets/tls
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
    -subj "/CN=demogpu.example" -addext "subjectAltName=DNS:demogpu.example,DNS:*.demogpu.example" \
    -keyout secrets/tls/dev.key -out secrets/tls/dev.crt 2>/dev/null
fi
chmod 644 secrets/db_password secrets/admin_token secrets/tls/dev.crt secrets/tls/dev.key
if ! grep -q '^DB_PASSWORD=' .env 2>/dev/null; then
  (umask 077; echo "DB_PASSWORD=$(cat secrets/db_password)" >> .env)
fi
echo "secrets ready in ./secrets and .env"
