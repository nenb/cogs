#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
state=${COGS_INSECURE_STATE_DIR:-"$repo/.cogs-dev/insecure-sandbox"}
image=${COGS_INSECURE_IMAGE:-cogs-insecure-sandbox:dev}
profile=insecure-container
operation=${1:-}
generation=${COGS_INSECURE_GENERATION:-}
original_revision=${COGS_INSECURE_ORIGINAL_REVISION:-$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)}
state_root="$repo/.cogs-dev"
state_name=${state#"$state_root/"}
state_id=$(printf '%s' "$state" | openssl dgst -sha256 2>/dev/null | awk '{print substr($NF,1,12)}')
container_name="cogs-insecure-$generation"
volume_name=''
lock="${state}.lock"
sentinel="$state/.cogs-insecure-owner"
authority="$state/authority"
intents="$state/intents"
inventory="$state/inventory"
locator="$state"
http_proxy=${COGS_HTTP_PROXY:-http://proxy.invalid:3128}
https_proxy=${COGS_HTTPS_PROXY:-$http_proxy}
lock_held=false
lock_owner=""
create_active=false
volume_acquired=false
container_acquired=false
container_id=''
container_pending=false
custody_bound=false
custody_identity=''
lock_identity=''

emit() {
  printf '{"version":"cogs.dev-driver/v1alpha1","profile":"%s","authority":"functional-only","command":"%s","result":"%s","generation":"%s"}\n' \
    "$profile" "$operation" "$1" "$generation"
}

fail() {
  printf '%s\n' "$1" >&2
  return 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}
durable_file() {
  COGS_DURABLE_CONTENT=$3 python3 -I - "$1" "$2" <<'PY'
import os, stat, sys
mode, path = sys.argv[1:]
data = os.environ["COGS_DURABLE_CONTENT"].encode()
parent, name = os.path.split(path)
dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
flags = os.O_WRONLY | os.O_NOFOLLOW
if mode == "new":
    flags |= os.O_CREAT | os.O_EXCL
else:
    flags |= os.O_APPEND
    s = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        raise SystemExit("unsafe durable journal")
fd = os.open(name, flags, 0o600, dir_fd=dfd)
with os.fdopen(fd, "wb") as f:
    f.write(data)
    f.flush()
    os.fsync(f.fileno())
os.fsync(dfd)
os.close(dfd)
pfd = os.open(os.path.dirname(parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
os.fsync(pfd); os.close(pfd)
PY
}
persist_new() { durable_file new "$1" "$2"; }
append_durable() { durable_file append "$1" "$2"; }
mode_octal() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

release_lock() {
  [[ "$lock_held" == true ]] || return 0
  python3 -I - "$lock" "$lock_identity" "$lock_owner" <<'PY'
import os,stat,sys
path,identity,owner=sys.argv[1:]
fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); info=os.fstat(fd)
if f'{info.st_dev}:{info.st_ino}'!=identity or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
    raise SystemExit('lock identity changed')
member=os.open('owner',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd); info=os.fstat(member)
if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or os.read(member,256)!=(owner+'\n').encode():
    raise SystemExit('lock owner changed')
os.close(member)
if set(os.listdir(fd)) not in ({'owner'},{'owner','docker-tool'}): raise SystemExit('foreign lock inventory')
if 'docker-tool' in os.listdir(fd):
    tool=os.open('docker-tool',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
    if set(os.listdir(tool))!={'home','config','buildx'}: raise SystemExit('foreign tool inventory')
    for name in ('home','config','buildx'):
        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=tool)
        if os.listdir(child): raise SystemExit('tool retirement uncertain')
        os.close(child)
    for name in ('home','config','buildx'): os.rmdir(name,dir_fd=tool)
    os.close(tool); os.rmdir('docker-tool',dir_fd=fd)
os.unlink('owner',dir_fd=fd); os.fsync(fd); os.close(fd); os.rmdir(path)
parent=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(parent); os.close(parent)
PY
  [[ $? == 0 ]] || return 1
  lock_held=false
}
mark_cleanup_required() {
  [[ "$custody_bound" == true ]] || return 0
  validate_custody identity || return 1
  append_durable "$intents" $'cleanup-required\t'"$operation"$'\n' || true
}

finish_failure() {
  local status=$1
  trap - ERR INT TERM HUP
  if (( BASH_SUBSHELL > 0 )); then exit "$status"; fi
  mark_cleanup_required || status=1
  if [[ "$create_active" == true ]]; then rollback_partial || status=1; fi
  if ! release_lock; then
    printf 'insecure-container lock release failed; retained exact owner lock\n' >&2
    status=1
  fi
  emit fail
  exit "$status"
}

on_error() { finish_failure "$?"; }
on_signal() { finish_failure 130; }

if [[ ! "$operation" =~ ^(create|verify|reset|destroy)$ ]]; then
  printf 'usage: %s create|verify|reset|destroy\n' "$0" >&2
  exit 2
fi
if [[ ! "$generation" =~ ^[a-f0-9]{32}$ ]]; then
  printf 'COGS_INSECURE_GENERATION must be exactly 32 lowercase hexadecimal characters\n' >&2
  exit 1
fi
if [[ ! "$original_revision" =~ ^[a-f0-9]{40}$ ]]; then
  printf 'COGS_INSECURE_ORIGINAL_REVISION must identify a 40-character lowercase revision\n' >&2
  exit 1
fi
if [[ "$state" != "$state_root/"* || -z "$state_name" || "$state_name" == */* \
    || ! "$state_name" =~ ^[A-Za-z0-9._-]+$ || -L "$state_root" || -L "$state" ]]; then
  printf 'insecure-container state directory must be one non-symlink child of %s\n' "$state_root" >&2
  exit 1
fi

trap on_error ERR
trap on_signal INT TERM HUP

select_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout_command=timeout
  elif command -v gtimeout >/dev/null 2>&1; then
    timeout_command=gtimeout
  else
    fail 'required command is missing: timeout (or gtimeout)'
  fi
}

bounded() {
  local duration=$1
  shift
  "$timeout_command" --signal=TERM --kill-after=5s "$duration" "$@"
}

acquire_lock() {
  if [[ ! -e "$state_root" ]]; then mkdir "$state_root"; fi
  verify_private_dir "$state_root"
  if ! mkdir "$lock" 2>/dev/null; then
    fail 'another insecure-container lifecycle command holds the state lock'
  fi
  chmod 0700 "$lock"
  lock_owner="$generation:$$:$RANDOM"
  lock_identity=$(stat -c '%d:%i' "$lock" 2>/dev/null || stat -f '%d:%i' "$lock")
  persist_new "$lock/owner" "$lock_owner"$'\n'
  lock_held=true
}

verify_private_dir() {
  local path=$1 mode owner
  [[ -d "$path" && ! -L "$path" && "$(realpath "$path")" == "$path" ]] || fail 'insecure-container docker state is invalid'
  mode=$(mode_octal "$path")
  owner=$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path")
  [[ "$owner:$mode:directory" == "$(id -u):700:directory" ]] || fail 'insecure-container docker state is invalid'
}

init_docker_tool_state() {
  docker_root="$lock/docker-tool"
  docker_home="$docker_root/home"
  docker_config="$docker_root/config"
  buildx_config="$docker_root/buildx"
  verify_private_dir "$lock"
  mkdir "$docker_root" "$docker_home" "$docker_config" "$buildx_config"
  chmod 0700 "$docker_root" "$docker_home" "$docker_config" "$buildx_config"
  verify_private_dir "$docker_root"
  verify_private_dir "$docker_home"
  verify_private_dir "$docker_config"
  verify_private_dir "$buildx_config"
  docker_command=(env "HOME=$docker_home" "DOCKER_CONFIG=$docker_config" "BUILDX_CONFIG=$buildx_config" docker)
}

initialize_authority() {
  [[ ! -e "$state" ]] || fail 'insecure-container state already exists; refusing adoption'
  mkdir "$state"
  chmod 0700 "$state"
  local device inode body
  read -r device inode < <(stat -c '%d %i' "$state" 2>/dev/null || stat -f '%d %i' "$state")
  body=$(printf 'cogs.insecure-authority/v1\tgeneration=%s\tprofile=%s\trevision=%s\tlocator=%s\tdevice=%s\tinode=%s\tnonce=%s\n' \
    "$generation" "$profile" "$original_revision" "$locator" "$device" "$inode" "$generation")
  persist_new "$authority" "$body"$'\n'
  persist_new "$sentinel" "$generation"$'\n'
  persist_new "$intents" $'cogs.insecure-intents/v1\n'
  persist_new "$inventory" $'cogs.insecure-inventory/v1\n'
}

validate_custody() {
  local observed
  observed=$(COGS_EXPECTED_IDENTITY=$custody_identity COGS_EXPECTED_GENERATION=$generation COGS_EXPECTED_PROFILE=$profile \
  COGS_EXPECTED_REVISION=$original_revision COGS_EXPECTED_LOCATOR=$locator \
  python3 -I - "$state" "${1:-full}" <<'PY'
import os, stat, sys
root = sys.argv[1]
st = os.lstat(root)
if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.getuid():
    raise SystemExit("invalid authority directory")
def read(name, limit=65536):
    p = os.path.join(root, name)
    s = os.lstat(p)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600:
        raise SystemExit("invalid authority file")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    opened = os.fstat(fd)
    if (opened.st_dev,opened.st_ino) != (s.st_dev,s.st_ino): raise SystemExit('custody file changed')
    with os.fdopen(fd, 'rb') as stream: data = stream.read(limit + 1)
    if len(data) > limit or not data.endswith(b"\n") or b"\0" in data or b"\r" in data:
        raise SystemExit("invalid authority bytes")
    return data
E, gen = os.environ, os.environ["COGS_EXPECTED_GENERATION"]
if read(".cogs-insecure-owner", 33) != (gen + "\n").encode():
    raise SystemExit("foreign generation sentinel")
expected = (f"cogs.insecure-authority/v1\tgeneration={gen}\tprofile={E['COGS_EXPECTED_PROFILE']}\t" +
    f"revision={E['COGS_EXPECTED_REVISION']}\tlocator={E['COGS_EXPECTED_LOCATOR']}\tdevice={st.st_dev}\t" +
    f"inode={st.st_ino}\tnonce={gen}\n").encode()
if read("authority", 8192) != expected:
    raise SystemExit("immutable authority binding mismatch")
identity = f'{st.st_dev}:{st.st_ino}'
if E['COGS_EXPECTED_IDENTITY'] and E['COGS_EXPECTED_IDENTITY'] != identity:
    raise SystemExit('retained directory replaced')
if sys.argv[2] == 'identity':
    print(identity); raise SystemExit(0)
for name, header in (("intents", "cogs.insecure-intents/v1"), ("inventory", "cogs.insecure-inventory/v1")):
    lines = read(name).decode("ascii").splitlines()
    if not lines or lines[0] != header or any(not line for line in lines):
        raise SystemExit("malformed lifecycle journal")
    if name == "intents":
        pending = None
        for line in lines[1:]:
            fields = line.split("\t")
            if len(fields) != 3 or fields[0] not in ("pending", "complete"):
                raise SystemExit("cleanup-required or malformed lifecycle intent")
            if fields[0] == "pending" and pending is None:
                pending = fields[1:]
            elif fields[0] == "complete" and pending == fields[1:]:
                pending = None
            else:
                raise SystemExit("pending lifecycle command requires recovery")
        if pending is not None:
            raise SystemExit("pending lifecycle command requires recovery")
print(identity)
PY
) || return 1
  custody_identity=$observed
  custody_bound=true
}

record_intent() { append_durable "$intents" "$1"$'\t'"$2"$'\t'"$3"$'\n'; }
record_inventory() { append_durable "$inventory" "$1"$'\n'; }

validate_complete_inventory() {
  inventory_lines=()
  while IFS= read -r line; do inventory_lines+=("$line"); done < "$inventory"
  [[ ${#inventory_lines[@]} -eq 3 && "${inventory_lines[0]}" == 'cogs.insecure-inventory/v1' ]] \
    || fail 'insecure-container exact inventory is incomplete or has extra entries'
  local -a volume_fields container_fields
  IFS=$'\t' read -r -a volume_fields <<<"${inventory_lines[1]}"
  IFS=$'\t' read -r -a container_fields <<<"${inventory_lines[2]}"
  [[ ${#volume_fields[@]} -eq 3 && "${volume_fields[0]}:${volume_fields[1]}" == 'volume:acquired' \
      && "${volume_fields[2]}" =~ ^[A-Za-z0-9_.-]{1,255}$ ]] || fail 'insecure-container volume inventory is invalid'
  volume_name=${volume_fields[2]}
  [[ ${#container_fields[@]} -eq 4 && "${container_fields[0]}" == container && "${container_fields[1]}" == acquired \
      && "${container_fields[2]}" =~ ^[a-f0-9]{64}$ && "${container_fields[3]}" == "$container_name" ]] \
    || fail 'insecure-container container inventory is invalid'
  container_id=${container_fields[2]}
  [[ -f "$state/container" && ! -L "$state/container" && "$(<"$state/container")" == "$container_id" ]] \
    || fail 'insecure-container container locator does not match inventory'
  [[ -f "$state/volume" && ! -L "$state/volume" && "$(<"$state/volume")" == "$volume_name" ]] \
    || fail 'insecure-container volume locator does not match inventory'
}

verify_tsx() {
  require realpath
  tsx_bin="$repo/node_modules/.bin/tsx"
  tsx_real=$(realpath "$tsx_bin")
  [[ "$tsx_real" == "$repo/node_modules/tsx/dist/cli.mjs" ]] || fail 'repo-local tsx executable is not canonical'
  [[ -f "$tsx_real" && -x "$tsx_real" ]] || fail 'repo-local tsx executable is missing or not executable'
  local mode
  mode=$(mode_octal "$tsx_real")
  [[ "$mode" =~ ^[0-7]+$ && $((8#$mode & 0022)) -eq 0 ]] || fail 'repo-local tsx executable is writable by group or other'
}

verify_control_key_inventory() {
  local control="$state/control" entries first second key_file
  verify_private_dir "$control"
  entries=$(find "$control" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ')
  [[ "$entries" == 'client_ed25519_key client_ed25519_key.pub ' ]] || fail 'insecure-container control inventory is invalid'
  for key_file in "$control/client_ed25519_key" "$control/client_ed25519_key.pub"; do
    [[ -f "$key_file" && ! -L "$key_file" && "$(realpath "$key_file")" == "$key_file" ]] \
      || fail 'insecure-container control inventory is invalid'
  done
  first=$(mode_octal "$control/client_ed25519_key")
  second=$(mode_octal "$control/client_ed25519_key.pub")
  [[ "$first" == 600 && "$second" == 600 ]] || fail 'insecure-container control inventory is invalid'
}

assert_container_name_available() {
  local listing
  listing=$(bounded 30s "${docker_command[@]}" container ls --all --quiet --no-trunc --filter "name=^/${container_name}$") \
    || fail 'could not query container-name competitors'
  [[ -z "$listing" ]] || fail 'refusing to adopt or delete a pre-existing container competitor'
}

# Preserve exact raw command receipts before Bash can strip trailing LF/NUL.
exact_line() {
  python3 -I -c 'import sys
b=sys.stdin.buffer.read(4097)
if len(b)>4096 or not b.endswith(b"\n") or b.count(b"\n")!=1 or any(c<32 or c>126 for c in b[:-1]):
 raise SystemExit("malformed Docker receipt")
sys.stdout.write(b[:-1].decode("ascii"))'
}
exact_empty() {
  python3 -I -c 'import sys
if sys.stdin.buffer.read(1): raise SystemExit("resource absence not proven")'
}

validate_container_ownership() {
  local observed
  observed=$(bounded 30s "${docker_command[@]}" container inspect --format \
    '{{.Id}} {{.Name}} {{index .Config.Labels "dev.cogs.profile"}} {{index .Config.Labels "dev.cogs.state"}} {{index .Config.Labels "dev.cogs.generation"}} {{index .Config.Labels "dev.cogs.revision"}}' "$container_id" | exact_line)
  [[ "$observed" == "$container_id /$container_name $profile $state_id $generation $original_revision" ]] \
    || fail 'refusing to operate on a container without exact ID, name, and authority labels'
}

validate_volume_ownership() {
  local observed
  observed=$(bounded 30s "${docker_command[@]}" volume inspect --format \
    '{{.Name}} {{index .Labels "dev.cogs.profile"}} {{index .Labels "dev.cogs.state"}} {{index .Labels "dev.cogs.generation"}} {{index .Labels "dev.cogs.revision"}}' "$volume_name" | exact_line)
  [[ "$observed" == "$volume_name $profile $state_id $generation $original_revision" ]] \
    || fail 'refusing to operate on a volume without exact authority labels'
}

retire_exact() {
  local kind=$1 target=$2 output listing
  [[ "$custody_bound" == true ]] && validate_custody identity || return 1
  if [[ "$kind" == container ]]; then
    validate_container_ownership || return 1
  else
    validate_volume_ownership || return 1
  fi
  record_inventory "$kind"$'\tretiring\t'"$target" || return 1
  record_intent pending "$kind-remove" "$target" || return 1
  if [[ "$kind" == container ]]; then
    output=$(bounded 45s "${docker_command[@]}" container rm --force "$target" | exact_line) || return 1
    [[ "$output" == "$target" ]] || return 1
    listing=$(bounded 30s "${docker_command[@]}" container ls --all --quiet --no-trunc --filter "id=$target" | exact_empty) || return 1
  else
    output=$(bounded 45s "${docker_command[@]}" volume rm --force "$target" | exact_line) || return 1
    [[ "$output" == "$target" ]] || return 1
    listing=$(bounded 30s "${docker_command[@]}" volume ls --quiet --filter "name=^${target}$" | exact_empty) || return 1
  fi
  [[ -z "$listing" ]] || return 1
  record_intent complete "$kind-remove" "$target" || return 1
  record_inventory "$kind"$'\tretired\t'"$target" || return 1
}

rollback_partial() {
  # A lost run response may have left a container using the volume. Never
  # retire dependencies on absence/name discovery, or after uncertain stop.
  [[ "$container_pending" == false ]] || return 1
  if [[ "$container_acquired" == true ]]; then retire_exact container "$container_id" || return 1; fi
  if [[ "$volume_acquired" == true ]]; then retire_exact volume "$volume_name" || return 1; fi
}

ssh_options() {
  SSH_OPTIONS=(
    -F /dev/null
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ConnectionAttempts=1
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=1
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$state/known_hosts"
    -o IdentitiesOnly=yes
    -o IdentityAgent=none
    -o ForwardAgent=no
    -o ClearAllForwardings=yes
    -i "$state/control/client_ed25519_key"
    -p "$port"
  )
  SFTP_OPTIONS=(
    -F /dev/null
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=1
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$state/known_hosts"
    -o IdentitiesOnly=yes
    -o IdentityAgent=none
    -o ClearAllForwardings=yes
    -i "$state/control/client_ed25519_key"
    -P "$port"
  )
}

create() {
  require ssh-keygen
  require openssl
  initialize_authority
  validate_custody
  create_active=true
  assert_container_name_available

  local input="$state/input" control="$state/control" ca_private output
  mkdir "$control" "$input"
  chmod 0700 "$control" "$input"

  record_intent pending image-build "$image"
  bounded 10m "${docker_command[@]}" build --pull=false --tag "$image" \
    --file "$repo/dev/insecure-sandbox/Dockerfile" "$repo" >&2
  record_intent complete image-build "$image"
  assert_container_name_available

  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-host -f "$input/ssh_host_ed25519_key"
  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-client -f "$control/client_ed25519_key"
  cp "$control/client_ed25519_key.pub" "$input/client_ed25519_key.pub"
  chmod 0600 "$control/client_ed25519_key.pub" "$input/client_ed25519_key.pub"
  verify_control_key_inventory

  if [[ ! "$http_proxy" =~ ^https?://[A-Za-z0-9.-]+:([0-9]{1,5})$ ]] \
      || (( 10#${BASH_REMATCH[1]:-0} < 1 || 10#${BASH_REMATCH[1]:-0} > 65535 )); then
    fail 'COGS_HTTP_PROXY must be a non-credentialed HTTP(S) host and port'
  fi
  if [[ ! "$https_proxy" =~ ^https?://[A-Za-z0-9.-]+:([0-9]{1,5})$ ]] \
      || (( 10#${BASH_REMATCH[1]:-0} < 1 || 10#${BASH_REMATCH[1]:-0} > 65535 )); then
    fail 'COGS_HTTPS_PROXY must be a non-credentialed HTTP(S) host and port'
  fi

  if [[ -n "${COGS_PUBLIC_CA_FILE:-}" ]]; then
    [[ -f "$COGS_PUBLIC_CA_FILE" && ! -L "$COGS_PUBLIC_CA_FILE" ]] || fail 'configured public CA must be a regular, non-symlink file'
    [[ $(wc -c < "$COGS_PUBLIC_CA_FILE") -le 1048576 ]] || fail 'configured public CA exceeds the one-megabyte limit'
    if grep -Eq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$COGS_PUBLIC_CA_FILE"; then
      fail 'configured public CA contains private key material'
    fi
    openssl x509 -in "$COGS_PUBLIC_CA_FILE" -out "$input/egress-ca.crt"
  else
    ca_private="$control/ephemeral-ca.key"
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
      -subj '/CN=Cogs Insecure Driver Public CA' \
      -keyout "$ca_private" -out "$input/egress-ca.crt" >/dev/null 2>&1
    rm -- "$ca_private"
  fi

  record_intent pending volume-create "$generation"
  output=$(bounded 30s "${docker_command[@]}" volume create \
    --label dev.cogs.profile="$profile" --label dev.cogs.state="$state_id" \
    --label dev.cogs.generation="$generation" --label dev.cogs.revision="$original_revision" | exact_line)
  [[ "$output" =~ ^[A-Za-z0-9_.-]{1,255}$ ]] || fail 'volume create returned a malformed or lost acquisition response'
  volume_name=$output
  validate_volume_ownership
  record_intent complete volume-create "$generation"
  record_inventory $'volume\tacquired\t'"$volume_name"
  persist_new "$state/volume" "$volume_name"$'\n'
  volume_acquired=true

  container_pending=true
  record_intent pending container-run "$container_name"
  output=$(bounded 45s "${docker_command[@]}" run --detach \
    --name "$container_name" --hostname sandbox \
    --label dev.cogs.profile="$profile" --label dev.cogs.authority=functional-only \
    --label dev.cogs.state="$state_id" --label dev.cogs.generation="$generation" \
    --label dev.cogs.revision="$original_revision" \
    --read-only --tmpfs /run:rw,nosuid,nodev,noexec,size=32m,mode=0700 \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m --tmpfs /shared:rw,nosuid,nodev,noexec,size=8m,mode=0700 \
    --tmpfs /user:rw,nosuid,nodev,noexec,size=8m,mode=0700 \
    --mount "type=bind,src=$input,dst=/run/cogs-input,readonly" \
    --mount "type=volume,src=$volume_name,dst=/workspace" \
    --add-host host.docker.internal:host-gateway --publish 127.0.0.1::2222 \
    --env COGS_PROFILE="$profile" --env HTTP_PROXY="$http_proxy" --env HTTPS_PROXY="$https_proxy" \
    --env NO_PROXY="127.0.0.1,localhost" --env SSL_CERT_FILE=/run/cogs-runtime/egress-ca.crt \
    "$image" | exact_line)
  [[ "$output" =~ ^[a-f0-9]{64}$ ]] || fail 'container run returned a malformed or lost acquisition response'
  container_id=$output
  validate_container_ownership
  record_intent complete container-run "$container_name"
  record_inventory $'container\tacquired\t'"$container_id"$'\t'"$container_name"
  persist_new "$state/container" "$container_id"$'\n'
  container_acquired=true
  container_pending=false

  local running deadline
  sleep 1
  running=$(bounded 30s "${docker_command[@]}" inspect --format '{{.State.Running}}' "$container_id")
  if [[ "$running" != true ]]; then
    bounded 15s "${docker_command[@]}" logs "$container_id" >&2 || true
    fail 'insecure-container stopped during startup'
  fi
  port=$(bounded 30s "${docker_command[@]}" port "$container_id" 2222/tcp | awk -F: 'NR == 1 {print $NF}')
  [[ "$port" =~ ^[0-9]+$ ]] || fail 'failed to discover SSH port'
  printf '[127.0.0.1]:%s %s\n' "$port" "$(awk 'NF >= 2 {print $1 " " $2; exit}' "$input/ssh_host_ed25519_key.pub")" > "$state/known_hosts"
  printf '%s\n' "$port" > "$state/port"

  ssh_options
  deadline=$((SECONDS + 30))
  until bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 true >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      bounded 15s "${docker_command[@]}" logs "$container_id" >&2 || true
      fail 'insecure-container SSH readiness timed out'
    fi
    running=$(bounded 30s "${docker_command[@]}" inspect --format '{{.State.Running}}' "$container_id")
    [[ "$running" == true ]] || fail 'insecure-container stopped before SSH became ready'
    sleep 1
  done
  file_custody capture
  create_active=false
}

verify_runtime_identity() {
  local running mount published
  validate_container_ownership
  validate_volume_ownership
  running=$(bounded 30s "${docker_command[@]}" inspect --format '{{.State.Running}}' "$container_id")
  [[ "$running" == true ]] || fail 'recorded insecure-container is not running'
  mount=$(bounded 30s "${docker_command[@]}" inspect --format '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Name}}{{end}}{{end}}' "$container_id")
  [[ "$mount" == "$volume_name" ]] || fail 'recorded workspace volume is not mounted in the container'
  published=$(bounded 30s "${docker_command[@]}" port "$container_id" 2222/tcp)
  [[ "$published" == "127.0.0.1:$port" ]] || fail 'recorded SSH endpoint is not the loopback-published container port'
}

verify_skill_roots() {
  bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 '
    for skill_parent in /shared /user; do
      test -d "$skill_parent" &&
      test ! -L "$skill_parent" &&
      test "$(realpath -e "$skill_parent")" = "$skill_parent" &&
      test "$(stat -c "%u:%g:%a:%F" "$skill_parent")" = "0:0:700:directory"
    done
    for skill_root in /shared/skills /user/skills; do
      test -d "$skill_root" &&
      test ! -L "$skill_root" &&
      test "$(realpath -e "$skill_root")" = "$skill_root" &&
      test "$(stat -c "%u:%g:%a:%F" "$skill_root")" = "0:0:700:directory"
    done
  ' >/dev/null || fail 'guest skill roots are not provisioned'
}

verify() {
  require ssh
  require ssh-keygen
  require sftp
  require cmp
  verify_tsx
  validate_custody
  validate_complete_inventory
  file_custody check
  verify_control_key_inventory
  [[ -s "$state/port" ]] || fail 'insecure-container state is absent or incomplete'
  port=$(<"$state/port")
  [[ "$port" =~ ^[0-9]+$ ]] || fail 'insecure-container SSH port is invalid'
  verify_runtime_identity
  ssh_options
  verify_skill_roots

  local observed transfer="$state/control/sftp-control.txt" roundtrip="$state/control/sftp-roundtrip.txt" host_fingerprint
  host_fingerprint=$(ssh-keygen -q -lf "$state/input/ssh_host_ed25519_key.pub" -E sha256 | awk 'NR == 1 {print $2}')
  [[ "$host_fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || fail 'insecure-container host fingerprint is invalid'
  bounded 20s "$tsx_bin" "$repo/dev/insecure-sandbox/ssh-adapter-smoke.ts" \
    "127.0.0.1:$port" "$state/control/client_ed25519_key" "$host_fingerprint" \
    >/dev/null || fail 'production SSH adapter smoke failed'

  observed=$(bounded 20s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
    'test "$(id -u)" = 0 && test "$COGS_PROFILE" = insecure-container && test -n "$HTTP_PROXY" && test -n "$HTTPS_PROXY" && test -r "$SSL_CERT_FILE" && printf verified')
  [[ "$observed" == verified ]] || fail 'SSH contract returned an unexpected result'

  printf 'sftp-positive-control\n' > "$transfer"
  (
    cd "$state/control"
    bounded 20s sftp "${SFTP_OPTIONS[@]}" -b - root@127.0.0.1 >/dev/null <<EOF
put sftp-control.txt /workspace/sftp-control-$state_id.txt
get /workspace/sftp-control-$state_id.txt sftp-roundtrip.txt
rm /workspace/sftp-control-$state_id.txt
EOF
  ) || fail 'SFTP contract verification failed'
  cmp "$transfer" "$roundtrip" || fail 'SFTP round-trip mismatch'
  rm -f "$transfer" "$roundtrip"

  local wrong_host="$state/control/wrong_host_key" mismatch_log="$state/control/host-mismatch.log"
  ssh-keygen -q -t ed25519 -N '' -C wrong-host-positive-control -f "$wrong_host"
  printf '[127.0.0.1]:%s %s\n' "$port" "$(awk 'NF >= 2 {print $1 " " $2; exit}' "$wrong_host.pub")" > "$state/control/wrong_known_hosts"
  if bounded 12s ssh \
      -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$state/control/wrong_known_hosts" \
      -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes \
      -i "$state/control/client_ed25519_key" -p "$port" root@127.0.0.1 true \
      >/dev/null 2>"$mismatch_log"; then
    fail 'host-key mismatch positive control unexpectedly succeeded'
  fi
  grep -Eq 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' "$mismatch_log" \
    || fail 'host-key mismatch did not fail for host-key verification'
  rm -f "$wrong_host" "$wrong_host.pub" "$state/control/wrong_known_hosts" "$mismatch_log"
  bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 true >/dev/null

  local wrong_client="$state/control/wrong_client_key" auth_log="$state/control/client-auth.log"
  ssh-keygen -q -t ed25519 -N '' -C wrong-client-positive-control -f "$wrong_client"
  if bounded 12s ssh \
      -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$state/known_hosts" \
      -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes \
      -i "$wrong_client" -p "$port" root@127.0.0.1 \
      'touch /workspace/unknown-client-side-effect' >/dev/null 2>"$auth_log"; then
    fail 'unknown controller key positive control unexpectedly authenticated'
  fi
  grep -Fq 'Permission denied (publickey)' "$auth_log" || fail 'unknown controller key did not fail as public-key authentication denial'
  rm -f "$wrong_client" "$wrong_client.pub" "$auth_log"
  observed=$(bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
    'test ! -e /workspace/unknown-client-side-effect && printf healthy')
  [[ "$observed" == healthy ]] || fail 'SSH endpoint was not healthy after negative controls'
  file_custody check
}

reset() {
  validate_custody
  validate_complete_inventory
  file_custody check
  validate_container_ownership
  validate_volume_ownership
  local output
  record_intent pending container-restart "$container_id"
  output=$(bounded 45s "${docker_command[@]}" container restart "$container_id" | exact_line)
  [[ "$output" == "$container_id" ]] || fail 'container restart returned a malformed or lost response'
  validate_container_ownership
  record_intent complete container-restart "$container_id"
  verify
}

file_custody() {
  validate_custody identity || return 1
  python3 -I - "$state" "$1" "$custody_identity" <<'PY'
import hashlib,json,os,stat,sys
root,action,identity=sys.argv[1:]; record='files.owner'
top={'.cogs-insecure-owner','authority','intents','inventory','container','volume','port','known_hosts','input','control'}
children={'input':{'ssh_host_ed25519_key','ssh_host_ed25519_key.pub','client_ed25519_key.pub','egress-ca.crt'},
          'control':{'client_ed25519_key','client_ed25519_key.pub'}}
rfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); info=os.fstat(rfd)
if f'{info.st_dev}:{info.st_ino}'!=identity: raise SystemExit('directory changed')
if set(os.listdir(rfd)) != top | (set() if action=='capture' else {record}): raise SystemExit('foreign state inventory')
def file(fd,name):
    handle=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd); s=os.fstat(handle)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        raise SystemExit('unsafe state member')
    with os.fdopen(handle,'rb') as stream: data=stream.read(1048577)
    if len(data)>1048576: raise SystemExit('oversized state member')
    marker=[s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode)]
    return marker if name in ('intents','inventory') else marker+[hashlib.sha256(data).hexdigest()]
values={}; held={}
for directory,names in children.items():
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rfd); held[directory]=fd
    s=os.fstat(fd)
    if s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700 or set(os.listdir(fd))!=names:
        raise SystemExit('foreign key inventory')
    values[directory]=[s.st_dev,s.st_ino]
    for name in sorted(names): values[directory+'/'+name]=file(fd,name)
for name in sorted(top-children.keys()): values[name]=file(rfd,name)
if action=='capture':
    fd=os.open(record,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=rfd)
    with os.fdopen(fd,'w') as out:
        json.dump(values,out,sort_keys=True,separators=(',',':')); out.write('\n'); out.flush(); os.fsync(out.fileno())
    os.fsync(rfd)
else:
    file(rfd,record)
    fd=os.open(record,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=rfd)
    with os.fdopen(fd,'r') as stream: text=stream.read(65537)
    if len(text)>65536 or text!=json.dumps(values,sort_keys=True,separators=(',',':'))+'\n':
        raise SystemExit('retained file acquisition changed')
    if action=='remove':
        # Validate the complete inventory before the first unlink. No recursive
        # deletion, no discovery/adoption and no unlink of unknown helper residue.
        for directory,names in children.items():
            fd=held[directory]
            for name in sorted(names):
                if file(fd,name)!=values[directory+'/'+name]: raise SystemExit('key replaced')
                os.unlink(name,dir_fd=fd)
            os.fsync(fd); os.rmdir(directory,dir_fd=rfd)
        for name in sorted(top-children.keys()):
            if file(rfd,name)!=values[name]: raise SystemExit('file replaced')
            os.unlink(name,dir_fd=rfd)
        os.unlink(record,dir_fd=rfd); os.fsync(rfd)
        s=os.lstat(root)
        if f'{s.st_dev}:{s.st_ino}'!=identity: raise SystemExit('directory replaced during retirement')
        os.rmdir(root)
        parent=os.open(os.path.dirname(root),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(parent); os.close(parent)
    elif action!='check': raise SystemExit('invalid file owner operation')
for fd in held.values(): os.close(fd)
os.close(rfd)
PY
}

destroy() {
  [[ -e "$state" ]] || fail 'insecure-container authority is absent; destroy cannot claim success'
  validate_custody
  validate_complete_inventory
  file_custody check
  retire_exact container "$container_id"
  retire_exact volume "$volume_name"
  inventory_lines=()
  while IFS= read -r line; do inventory_lines+=("$line"); done < "$inventory"
  [[ ${#inventory_lines[@]} -eq 7 \
      && "${inventory_lines[3]}" == "container"$'\t'"retiring"$'\t'"$container_id" \
      && "${inventory_lines[4]}" == "container"$'\t'"retired"$'\t'"$container_id" \
      && "${inventory_lines[5]}" == "volume"$'\t'"retiring"$'\t'"$volume_name" \
      && "${inventory_lines[6]}" == "volume"$'\t'"retired"$'\t'"$volume_name" ]] \
    || fail 'resource retirement inventory is not exact'
  file_custody remove
}

require python3
require openssl
require docker
select_timeout
acquire_lock
init_docker_tool_state
"$operation"
if ! release_lock; then
  fail 'insecure-container lock release failed; retained exact owner lock'
fi
emit pass
