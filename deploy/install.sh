#!/bin/sh
set -eu

umask 077
INSTALL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"
VALIDATOR="$INSTALL_DIR/validate_env.py"

fail() {
  printf '%s\n' "install failed: $*" >&2
  exit 1
}

require_root() {
  [ "$(id -u)" -eq 0 ] || fail "run this command as root"
}

require_platform() {
  [ "$(uname -s)" = "Linux" ] || fail "only Linux is supported"
  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

require_commands() {
  for command_name in docker curl openssl python3 systemctl systemd-run getent groupadd install awk; do
    command -v "$command_name" >/dev/null 2>&1 || fail "missing prerequisite: $command_name"
  done
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
}

env_value() {
  python3 "$VALIDATOR" "$ENV_FILE" --get "$1"
}

compose() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

prepare() {
  require_root
  require_platform
  [ ! -e "$ENV_FILE" ] || fail "$ENV_FILE already exists; use repair or update"
  [ -f "$INSTALL_DIR/.env.template" ] || fail "release environment template is missing"
  getent group vpnenus-updater >/dev/null 2>&1 || groupadd --system vpnenus-updater
  updater_gid=$(getent group vpnenus-updater | awk -F: '{print $3}')
  [ -n "$updater_gid" ] || fail "could not resolve updater socket group"
  backup_key=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
  control_token=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
  [ "${#backup_key}" -ge 43 ] || fail "secure key generation failed"
  [ "${#control_token}" -ge 43 ] || fail "secure control-token generation failed"
  python3 - "$INSTALL_DIR/.env.template" "$ENV_FILE" "$backup_key" "$control_token" "$updater_gid" <<'PY'
import os, sys
source, target, key, control_token, updater_gid = sys.argv[1:]
with open(source, "r", encoding="utf-8") as handle:
    data = handle.read()
if data.count("__BACKUP_KEY__") != 1:
    raise SystemExit("release template backup-key marker is invalid")
if data.count("__CONTROL_TOKEN__") != 1:
    raise SystemExit("release template control-token marker is invalid")
if data.count("__UPDATER_GID__") != 1:
    raise SystemExit("release template updater-group marker is invalid")
data = data.replace("__BACKUP_KEY__", key).replace("__CONTROL_TOKEN__", control_token).replace("__UPDATER_GID__", updater_gid)
pending = target + ".tmp"
with open(pending, "x", encoding="utf-8", newline="\n") as handle:
    handle.write(data)
os.chmod(pending, 0o600)
os.replace(pending, target)
PY
  chmod 0600 "$ENV_FILE"
  ln -sfn "$INSTALL_DIR/watcherctl" /usr/local/sbin/vpn-enus-watcher
  printf '%s\n' "Prepared VPNЭНУС Watcher."
  if [ "${LOKI_WATCHER_BOOTSTRAP:-0}" != "1" ]; then
    printf '%s\n' "Edit only the OPERATOR INPUT section in $ENV_FILE"
    printf '%s\n' "Then run: sudo vpn-enus-watcher install"
  fi
}

configure_from_environment() {
  [ -n "${LOKI_WATCHER_DASHBOARD_USERNAME:-}" ] || fail "LOKI_WATCHER_DASHBOARD_USERNAME is required for one-command bootstrap"
  [ -n "${LOKI_WATCHER_DASHBOARD_PASSWORD:-}" ] || fail "LOKI_WATCHER_DASHBOARD_PASSWORD is required for one-command bootstrap"
  [ -n "${LOKI_WATCHER_PUBLIC_SNI:-}" ] || fail "LOKI_WATCHER_PUBLIC_SNI is required for one-command bootstrap"
  input_file=$(mktemp "$INSTALL_DIR/.operator-input.XXXXXX")
  trap 'rm -f -- "$input_file"' EXIT HUP INT TERM
  {
    printf '%s\n' "LOKI_WATCHER_DASHBOARD_USERNAME=$LOKI_WATCHER_DASHBOARD_USERNAME"
    printf '%s\n' "LOKI_WATCHER_DASHBOARD_PASSWORD=$LOKI_WATCHER_DASHBOARD_PASSWORD"
    printf '%s\n' "LOKI_WATCHER_PUBLIC_SNI=$LOKI_WATCHER_PUBLIC_SNI"
  } >"$input_file"
  chmod 0600 "$input_file"
  python3 - "$ENV_FILE" "$input_file" <<'PY'
import os, sys, uuid
target, input_path = sys.argv[1:]
updates = {}
with open(input_path, "r", encoding="utf-8") as source:
    for raw in source:
        key, value = raw.rstrip("\n").split("=", 1)
        if not value or "\r" in value or "\n" in value:
            raise SystemExit(f"operator value is invalid: {key}")
        updates[key] = value
with open(target, "r", encoding="utf-8") as source:
    lines = source.readlines()
counts = {key: 0 for key in updates}
output = []
for line in lines:
    key = line.split("=", 1)[0]
    if key in updates:
        output.append(f"{key}={updates[key]}\n")
        counts[key] += 1
    else:
        output.append(line)
if any(count != 1 for count in counts.values()):
    raise SystemExit("operator fields are missing or duplicated in the release template")
pending = f"{target}.{uuid.uuid4().hex}.tmp"
with open(pending, "x", encoding="utf-8", newline="\n") as destination:
    destination.writelines(output)
    destination.flush()
    os.fsync(destination.fileno())
os.chmod(pending, 0o600)
os.replace(pending, target)
PY
  rm -f -- "$input_file"
  trap - EXIT HUP INT TERM
  python3 "$VALIDATOR" "$ENV_FILE"
}

install_updater() {
  updater_root=/opt/vpnenus-updater
  profile_dir=/etc/vpnenus-updater/profiles.d
  state_root=/var/lib/vpnenus-updater
  getent group vpnenus-updater >/dev/null 2>&1 || groupadd --system vpnenus-updater
  updater_gid=$(getent group vpnenus-updater | awk -F: '{print $3}')
  [ -n "$updater_gid" ] || fail "could not resolve updater socket group"
  python3 - "$ENV_FILE" "$updater_gid" <<'PY'
import os, sys, uuid
path, gid = sys.argv[1:]
with open(path, "r", encoding="utf-8") as source:
    lines = source.readlines()
found = 0
output = []
for line in lines:
    if line.startswith("LOKI_WATCHER_UPDATER_GID="):
        output.append(f"LOKI_WATCHER_UPDATER_GID={gid}\n")
        found += 1
    else:
        output.append(line)
if found != 1:
    raise SystemExit("updater group field is missing or duplicated")
pending = f"{path}.{uuid.uuid4().hex}.tmp"
with open(pending, "x", encoding="utf-8", newline="\n") as target:
    target.writelines(output)
    target.flush()
    os.fsync(target.fileno())
os.chmod(pending, 0o600)
os.replace(pending, path)
PY
  install -d -o root -g root -m 0755 "$updater_root"
  install -d -o root -g root -m 0700 "$profile_dir" "$state_root"
  for updater_file in updater_daemon.py updater_client.py updater_common.py updater_self_update.py local_updater.py validate_env.py; do
    [ -f "$INSTALL_DIR/$updater_file" ] || fail "missing updater component: $updater_file"
    install -o root -g root -m 0755 "$INSTALL_DIR/$updater_file" "$updater_root/$updater_file"
  done
  [ -f "$INSTALL_DIR/vpnenus-updater.service" ] || fail "updater systemd unit is missing"
  install -o root -g root -m 0644 "$INSTALL_DIR/vpnenus-updater.service" /etc/systemd/system/vpnenus-updater.service
  profile_pending="$profile_dir/.watcher.json.tmp"
  rm -f -- "$profile_pending"
  python3 - "$INSTALL_DIR" "$ENV_FILE" "$profile_pending" <<'PY'
import json, os, sys
install_dir, env_path, target = sys.argv[1:]
sys.path.insert(0, install_dir)
from validate_env import validate
values = validate(env_path)
profile = {
    "schemaVersion": 1,
    "serviceId": "watcher",
    "installDir": install_dir,
    "apiHost": "127.0.0.1",
    "apiPort": int(values["LOKI_WATCHER_API_PORT"]),
    "controlToken": values["LOKI_WATCHER_LOCAL_CONTROL_TOKEN"],
}
with open(target, "x", encoding="utf-8") as output:
    json.dump(profile, output, separators=(",", ":"))
os.chmod(target, 0o600)
PY
  chown root:root "$profile_pending"
  mv -f -- "$profile_pending" "$profile_dir/watcher.json"
  systemctl daemon-reload
  systemctl enable --now vpnenus-updater.service
  systemctl restart vpnenus-updater.service
  attempts=0
  while [ "$attempts" -lt 20 ]; do
    if python3 "$updater_root/updater_client.py" --service watcher status >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 1
  done
  journalctl -u vpnenus-updater.service --no-pager -n 100 >&2 || true
  fail "privileged updater did not become healthy"
}

wait_for_health() {
  api_port=$(env_value LOKI_WATCHER_API_PORT)
  attempts=0
  while [ "$attempts" -lt 60 ]; do
    if curl --fail --silent --show-error --max-time 3 "http://127.0.0.1:${api_port}/health" >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 2
  done
  return 1
}

install_service() {
  require_root
  require_platform
  require_commands
  [ -f "$ENV_FILE" ] || fail "run prepare first"
  chmod 0600 "$ENV_FILE"
  python3 "$VALIDATOR" "$ENV_FILE"
  install_updater
  compose config --quiet
  for image_key in LOKI_WATCHER_API_IMAGE LOKI_WATCHER_WEB_IMAGE LOKI_WATCHER_WORKER_IMAGE; do
    docker pull "$(env_value "$image_key")"
  done
  compose up -d --no-build
  if ! wait_for_health; then
    compose ps >&2 || true
    compose logs --no-color --tail 100 api web worker backup >&2 || true
    fail "loopback health did not become ready within 120 seconds"
  fi
  printf '%s\n' "VPNЭНУС Watcher is healthy."
  compose ps
}

status_service() {
  require_commands
  [ -f "$ENV_FILE" ] || fail "installation is not prepared"
  python3 "$VALIDATOR" "$ENV_FILE"
  compose ps
  if wait_for_health; then
    printf '%s\n' "health: ok"
  else
    printf '%s\n' "health: unavailable"
    exit 1
  fi
}

case "${1:-}" in
  bootstrap) prepare; configure_from_environment; install_service ;;
  prepare) prepare ;;
  install) install_service ;;
  repair) install_service ;;
  status) status_service ;;
  *) fail "usage: install.sh bootstrap|prepare|install|repair|status" ;;
esac
