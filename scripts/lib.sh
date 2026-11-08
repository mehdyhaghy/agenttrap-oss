# Shared helpers for backup.sh and restore.sh (sourced from the app directory).

# ROOT holds the server's data outside the app checkout (pingap config with
# the Let's Encrypt certificate, notifier state).
ROOT=${AGENTTRAP_ROOT:-/opt/agenttrap}
# Docker volumes that hold state the database does not.
STATE_VOLUMES="hubdata spokedata bootstrap"
# Any local image with a tar works; this one exists wherever the stack runs.
TAR_IMAGE=agenttrap-postgres:dev

# vol NAME prints the Docker volume name compose uses for NAME; project
# prints the compose project name.
vol() {
  docker compose config --format json </dev/null |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["volumes"][sys.argv[1]]["name"])' "$1"
}
project() {
  docker compose config --format json </dev/null | python3 -c 'import json, sys; print(json.load(sys.stdin)["name"])'
}

# save_volume NAME FILE archives a volume's contents with owners and modes.
save_volume() {
  out_dir=$(cd "$(dirname "$2")" && pwd)
  docker run --rm --entrypoint tar -v "$(vol "$1"):/v:ro" -v "$out_dir:/out" "$TAR_IMAGE" \
    -czf "/out/$(basename "$2")" -C /v . </dev/null
}

# load_volume NAME FILE replaces a volume's contents with an archive.
load_volume() {
  in_dir=$(cd "$(dirname "$2")" && pwd)
  name=$(vol "$1")
  # Labelled as compose would, so compose adopts the volume without warnings.
  docker volume create --label "com.docker.compose.project=$(project)" \
    --label "com.docker.compose.volume=$1" "$name" >/dev/null
  docker run --rm --entrypoint sh -v "$name:/v" -v "$in_dir:/in:ro" "$TAR_IMAGE" \
    -c "find /v -mindepth 1 -delete && tar -xzpf '/in/$(basename "$2")' -C /v" </dev/null
}
