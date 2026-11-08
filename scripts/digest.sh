#!/bin/sh
# Sends (or with --dry-run prints) the daily findings digest through the
# Mailjet Send API. Runs a one-off container on the host network: the host
# can reach the hub admin API (10.90.0.5) and api.mailjet.com, so no container
# network gains internet access. Configure in .env: DIGEST_TO, DIGEST_FROM,
# DIGEST_MAILJET_API_KEY and DIGEST_MAILJET_SECRET_FILE (the secret key in a
# file inside secrets/).
set -eu
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
secret_mount=""
secret_env=""
if [ -n "${DIGEST_MAILJET_SECRET_FILE:-}" ]; then
  secret_mount="-v ${DIGEST_MAILJET_SECRET_FILE}:/run/secrets/mailjet_secret:ro"
  secret_env="-e DIGEST_MAILJET_SECRET_FILE=/run/secrets/mailjet_secret"
fi
# shellcheck disable=SC2086
exec docker run --rm --network host \
  -v "$PWD/secrets/admin_token:/run/secrets/admin_token:ro" $secret_mount \
  -e AGENTTRAP_ADMIN_TOKEN_FILE=/run/secrets/admin_token $secret_env \
  -e DIGEST_TO -e DIGEST_FROM -e DIGEST_FROM_NAME -e DIGEST_MAILJET_API_KEY \
  agenttrap:dev digest "$@"
