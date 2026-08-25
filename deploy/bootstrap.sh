#!/bin/sh
set -eu

umask 077
REPOSITORY="psewdon1m-loki/watcher"
INSTALL_DIR="/opt/vpnenus-watcher"
MAX_MANIFEST_BYTES=1048576
MAX_BUNDLE_BYTES=134217728

fail() {
  printf '%s\n' "bootstrap failed: $*" >&2
  exit 1
}

read_secret() {
  prompt=$1
  printf '%s' "$prompt" >/dev/tty
  terminal_state=$(stty -g </dev/tty)
  trap 'stty "$terminal_state" </dev/tty; exit 1' HUP INT TERM
  stty -echo </dev/tty
  IFS= read -r secret_value </dev/tty
  stty "$terminal_state" </dev/tty
  trap - HUP INT TERM
  printf '\n' >/dev/tty
}

prompt_operator_input() {
  if [ -z "${LOKI_WATCHER_DASHBOARD_USERNAME:-}" ]; then
    [ -r /dev/tty ] || fail "set LOKI_WATCHER_DASHBOARD_USERNAME for non-interactive installation"
    printf '%s' "Watcher operator username: " >/dev/tty
    IFS= read -r LOKI_WATCHER_DASHBOARD_USERNAME </dev/tty
  fi
  if [ -z "${LOKI_WATCHER_DASHBOARD_PASSWORD:-}" ]; then
    [ -r /dev/tty ] || fail "set LOKI_WATCHER_DASHBOARD_PASSWORD for non-interactive installation"
    read_secret "Watcher operator password (at least 16 characters): "
    LOKI_WATCHER_DASHBOARD_PASSWORD=$secret_value
    read_secret "Repeat operator password: "
    [ "$LOKI_WATCHER_DASHBOARD_PASSWORD" = "$secret_value" ] || fail "operator passwords do not match"
  fi
  if [ -z "${LOKI_WATCHER_PUBLIC_SNI:-}" ]; then
    [ -r /dev/tty ] || fail "set LOKI_WATCHER_PUBLIC_SNI for non-interactive installation"
    printf '%s' "Public Watcher hostname (for example watcher.example.com): " >/dev/tty
    IFS= read -r LOKI_WATCHER_PUBLIC_SNI </dev/tty
  fi
  [ "${#LOKI_WATCHER_DASHBOARD_USERNAME}" -ge 3 ] || fail "operator username is too short"
  [ "${#LOKI_WATCHER_DASHBOARD_PASSWORD}" -ge 16 ] || fail "operator password must contain at least 16 characters"
  case "$LOKI_WATCHER_PUBLIC_SNI" in *.*) ;; *) fail "public hostname must be a DNS name" ;; esac
  export LOKI_WATCHER_DASHBOARD_USERNAME LOKI_WATCHER_DASHBOARD_PASSWORD LOKI_WATCHER_PUBLIC_SNI
}

install_prerequisites() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl python3 unzip openssl coreutils gawk passwd
    command -v docker >/dev/null 2>&1 || apt-get install -y docker.io
    if ! docker compose version >/dev/null 2>&1; then
      if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
        apt-get install -y docker-compose-v2
      elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
        apt-get install -y docker-compose-plugin
      else
        fail "Docker Compose v2 is unavailable from this distribution repository"
      fi
    fi
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl python3 unzip openssl coreutils gawk shadow-utils docker docker-compose-plugin
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl python3 unzip openssl coreutils gawk shadow-utils docker docker-compose-plugin
  else
    fail "supported package manager not found; install Docker Compose v2, curl, Python 3, unzip and OpenSSL"
  fi
  systemctl enable --now docker
}

[ "$(id -u)" -eq 0 ] || fail "run through sudo"
[ "$(uname -s)" = "Linux" ] || fail "only Linux is supported"
case "$(uname -m)" in x86_64|amd64|aarch64|arm64) ;; *) fail "unsupported architecture" ;; esac
[ ! -e "$INSTALL_DIR" ] || fail "$INSTALL_DIR already exists; use vpn-enus-watcher update or repair"
prompt_operator_input
install_prerequisites
for command_name in curl python3 sha256sum unzip openssl getent groupadd awk; do
  command -v "$command_name" >/dev/null 2>&1 || fail "missing prerequisite: $command_name"
done

work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT HUP INT TERM
releases_path="$work_dir/releases.json"
curl --proto '=https' --tlsv1.2 --fail --show-error --location \
  --connect-timeout 10 --max-time 60 --retry 3 --max-filesize "$MAX_MANIFEST_BYTES" \
  "https://api.github.com/repos/$REPOSITORY/releases?per_page=100" -o "$releases_path"

python3 - "$releases_path" "$work_dir/selection.json" <<'PY'
import json, re, sys
source, target = sys.argv[1:]
with open(source, "r", encoding="utf-8") as handle:
    releases = json.load(handle)
candidates = []
for release in releases:
    tag = str(release.get("tag_name") or "")
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", tag)
    if not match or release.get("draft") or release.get("prerelease"):
        continue
    asset = next((item for item in release.get("assets", []) if item.get("name") == "vpn-enus-watcher-release.json"), None)
    if asset:
        candidates.append((tuple(map(int, match.groups())), tag, asset.get("browser_download_url")))
if not candidates:
    raise SystemExit("no stable release with a release manifest was found")
_, tag, url = sorted(candidates)[-1]
with open(target, "w", encoding="utf-8") as handle:
    json.dump({"tag": tag, "url": url}, handle)
PY

manifest_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["url"])' "$work_dir/selection.json")
selected_tag=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag"])' "$work_dir/selection.json")
case "$manifest_url" in https://github.com/*|https://objects.githubusercontent.com/*) ;; *) fail "manifest host is not allow-listed" ;; esac
curl --proto '=https' --tlsv1.2 --fail --show-error --location \
  --connect-timeout 10 --max-time 60 --retry 3 --max-filesize "$MAX_MANIFEST_BYTES" \
  "$manifest_url" -o "$work_dir/manifest.json"

python3 - "$work_dir/manifest.json" "$selected_tag" "$work_dir/bundle-selection.json" <<'PY'
import json, re, sys
path, selected_tag, output = sys.argv[1:]
with open(path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)
version = selected_tag.removeprefix("v")
if (
    manifest.get("schemaVersion") != 1
    or manifest.get("componentRole") != "watcher-control-plane"
    or manifest.get("version") != version
    or manifest.get("channel") != "stable"
    or manifest.get("databaseSchemaGeneration") != 3
):
    raise SystemExit("release manifest identity does not match the selected tag")
bundle = manifest.get("bundle") or {}
url, digest, size = bundle.get("url"), bundle.get("sha256"), bundle.get("bytes")
if not isinstance(url, str) or not url.startswith(("https://github.com/", "https://objects.githubusercontent.com/")):
    raise SystemExit("bundle host is not allow-listed")
if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
    raise SystemExit("bundle digest is invalid")
if not isinstance(size, int) or size <= 0 or size > 134217728:
    raise SystemExit("bundle size is invalid")
images = manifest.get("images") or {}
for name in ("api", "web", "worker"):
    if not re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+@sha256:[0-9a-f]{64}", str(images.get(name) or "")):
        raise SystemExit(f"immutable image is invalid: {name}")
compose_digest = manifest.get("composeSha256")
if not isinstance(compose_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", compose_digest):
    raise SystemExit("Compose digest is invalid")
with open(output, "w", encoding="utf-8") as handle:
    json.dump({"url": url, "sha256": digest, "bytes": size, "composeSha256": compose_digest}, handle)
PY

bundle_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["url"])' "$work_dir/bundle-selection.json")
bundle_sha=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$work_dir/bundle-selection.json")
bundle_size=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bytes"])' "$work_dir/bundle-selection.json")
[ "$bundle_size" -le "$MAX_BUNDLE_BYTES" ] || fail "bundle exceeds the bootstrap limit"
curl --proto '=https' --tlsv1.2 --fail --show-error --location \
  --connect-timeout 10 --max-time 300 --retry 3 --max-filesize "$MAX_BUNDLE_BYTES" \
  "$bundle_url" -o "$work_dir/bundle.zip"
printf '%s  %s\n' "$bundle_sha" "$work_dir/bundle.zip" | sha256sum --check --status || fail "bundle checksum mismatch"

python3 - "$work_dir/bundle.zip" "$INSTALL_DIR" "$work_dir/bundle-selection.json" <<'PY'
import hashlib, json, os, pathlib, shutil, stat, sys, tempfile, zipfile
archive_path, target, selection_path = sys.argv[1:]
allowed = {
    "docker-compose.yml", ".env.template", "install.sh", "watcherctl", "recovery_tool.py", "validate_env.py",
    "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py",
    "vpnenus-updater.service", "RELEASE.txt",
}
parent = os.path.dirname(target)
pending = tempfile.mkdtemp(prefix=".vpnenus-watcher-", dir=parent)
try:
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)) or set(names) != allowed or sum(item.file_size for item in infos) > 134217728:
            raise SystemExit("bundle archive limits or member allow-list failed")
        for info in infos:
            path = pathlib.PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if path.is_absolute() or ".." in path.parts or "/" in info.filename or "\\" in info.filename or stat.S_ISLNK(mode):
                raise SystemExit("unsafe bundle member")
            destination = os.path.join(pending, info.filename)
            with archive.open(info) as source, open(destination, "xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            os.chmod(destination, 0o700 if info.filename in {"install.sh", "watcherctl", "recovery_tool.py", "local_updater.py", "updater_daemon.py", "updater_client.py", "updater_common.py", "updater_self_update.py"} else 0o600)
    with open(os.path.join(pending, "docker-compose.yml"), "rb") as source:
        compose_digest = hashlib.sha256(source.read()).hexdigest()
    with open(selection_path, "r", encoding="utf-8") as source:
        expected_digest = json.load(source)["composeSha256"]
    if compose_digest != expected_digest:
        raise SystemExit("release Compose digest mismatch")
    os.replace(pending, target)
except BaseException:
    shutil.rmtree(pending, ignore_errors=True)
    raise
PY

LOKI_WATCHER_BOOTSTRAP=1 "$INSTALL_DIR/install.sh" bootstrap
