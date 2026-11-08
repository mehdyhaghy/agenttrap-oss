#!/bin/sh
# Mails DIGEST_TO when events stop reaching the hub (and when they resume;
# state in state/ingest-alert.json), then forwards new contact-form
# submissions through Mailjet, with Reply-To set to the sender. Runs every few minutes from cron in a one-off
# container on the host network (same reach as digest.sh). Forwarded
# submissions are remembered in state/notify.json so none is sent twice.
set -eu
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
state=/opt/agenttrap/state
mkdir -p "$state"
chown 65532:65532 "$state"
chmod 0700 "$state"
secret_mount=""
secret_env=""
if [ -n "${DIGEST_MAILJET_SECRET_FILE:-}" ]; then
  secret_mount="-v ${DIGEST_MAILJET_SECRET_FILE}:/run/secrets/mailjet_secret:ro"
  secret_env="-e DIGEST_MAILJET_SECRET_FILE=/run/secrets/mailjet_secret"
fi
# shellcheck disable=SC2086
exec docker run --rm --network host \
  -v "$PWD/secrets/admin_token:/run/secrets/admin_token:ro" $secret_mount \
  -v "$state:/state" \
  -e AGENTTRAP_ADMIN_TOKEN_FILE=/run/secrets/admin_token $secret_env \
  -e DIGEST_TO -e DIGEST_FROM -e DIGEST_FROM_NAME -e DIGEST_MAILJET_API_KEY \
  agenttrap:dev notify "$@"
