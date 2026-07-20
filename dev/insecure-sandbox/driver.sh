#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state=${COGS_INSECURE_STATE_DIR:-"$repo/.cogs-dev/insecure-sandbox"}
image=${COGS_INSECURE_IMAGE:-cogs-insecure-sandbox:dev}
profile=insecure-container
operation=${1:-}
state_root="$repo/.cogs-dev"
state_name=${state#"$state_root/"}
state_id=$(printf '%s' "$state" | openssl dgst -sha256 2>/dev/null | awk '{print substr($NF,1,12)}')
container="cogs-insecure-$state_id"
volume="cogs-insecure-workspace-$state_id"
lock="${state}.lock"
sentinel="$state/.cogs-insecure-owner"
http_proxy=${COGS_HTTP_PROXY:-http://proxy.invalid:3128}
https_proxy=${COGS_HTTPS_PROXY:-$http_proxy}
result_emitted=false

emit() {
  result_emitted=true
  printf '{"version":"cogs.dev-driver/v1alpha1","profile":"%s","authority":"functional-only","command":"%s","result":"%s"}\n' "$profile" "$operation" "$1"
}

fail() {
  printf '%s\n' "$1" >&2
  return 1
}

on_error() {
  local status=$?
  trap - ERR INT TERM HUP
  if [[ "$result_emitted" != true && -n "$operation" ]]; then emit fail; fi
  exit "$status"
}

on_signal() {
  trap - ERR INT TERM HUP
  if [[ "$result_emitted" != true && -n "$operation" ]]; then emit fail; fi
  exit 130
}

trap on_error ERR
trap on_signal INT TERM HUP

if [[ "$state" != "$state_root/"* || -z "$state_name" || "$state_name" == */* \
    || ! "$state_name" =~ ^[A-Za-z0-9._-]+$ || -L "$state_root" || -L "$state" ]]; then
  printf 'insecure-container state directory must be one non-symlink child of %s\n' "$state_root" >&2
  exit 1
fi

require() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}

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

mode_octal() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
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

acquire_lock() {
  local parent
  parent=$(dirname "$lock")
  mkdir -p "$parent"
  if ! mkdir "$lock" 2>/dev/null; then
    fail 'another insecure-container lifecycle command holds the state lock'
  fi
  printf '%s\n' "$$" > "$lock/pid"
  trap 'rm -rf -- "$lock"' EXIT
}

validate_metadata() {
  local recorded
  if [[ -e "$state" ]]; then
    [[ -d "$state" && ! -L "$state" && -s "$sentinel" ]] \
      || fail 'insecure-container state lacks its ownership sentinel'
    recorded=$(<"$sentinel")
    [[ "$recorded" == "$state_id" ]] || fail 'insecure-container state ownership sentinel does not match'
  fi
  if [[ -e "$state/container" ]]; then
    recorded=$(<"$state/container")
    [[ "$recorded" == "$container" ]] || fail 'insecure-container metadata has an unexpected container name'
  fi
  if [[ -e "$state/volume" ]]; then
    recorded=$(<"$state/volume")
    [[ "$recorded" == "$volume" ]] || fail 'insecure-container metadata has an unexpected volume name'
  fi
}

verify_private_dir() {
  local path=$1 mode owner
  [[ -d "$path" && ! -L "$path" && "$(realpath "$path")" == "$path" ]] || fail 'insecure-container docker state is invalid'
  mode=$(mode_octal "$path")
  owner=$(stat -c '%u:%g' "$path" 2>/dev/null || stat -f '%u:%g' "$path")
  [[ "$owner:$mode:directory" == "$(id -u):$(id -g):700:directory" ]] || fail 'insecure-container docker state is invalid'
}

init_docker_tool_state() {
  docker_root="$state/docker-tool"
  docker_home="$docker_root/home"
  docker_config="$docker_root/config"
  buildx_config="$docker_root/buildx"
  docker_cmd="$docker_root/docker-command"
  verify_private_dir "$state"
  mkdir -p "$docker_root" "$docker_home" "$docker_config" "$buildx_config"
  chmod 0700 "$docker_root" "$docker_home" "$docker_config" "$buildx_config"
  verify_private_dir "$docker_root"
  cat > "$docker_cmd" <<EOF
#!/usr/bin/env bash
exec env HOME="$docker_home" DOCKER_CONFIG="$docker_config" BUILDX_CONFIG="$buildx_config" docker "\$@"
EOF
  chmod 0700 "$docker_cmd"
  verify_private_dir "$docker_home"
  verify_private_dir "$docker_config"
  verify_private_dir "$buildx_config"
  [[ -f "$docker_cmd" && ! -L "$docker_cmd" && "$(realpath "$docker_cmd")" == "$docker_cmd" ]] || fail 'insecure-container docker state is invalid'
}

verify_control_key_inventory() {
  local control="$state/control" entries first second
  verify_private_dir "$control"
  entries=$(find "$control" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort | tr '\n' ' ')
  [[ "$entries" == 'client_ed25519_key client_ed25519_key.pub ' ]] || fail 'insecure-container control inventory is invalid'
  for key_file in "$control/client_ed25519_key" "$control/client_ed25519_key.pub"; do
    [[ -f "$key_file" && ! -L "$key_file" && "$(realpath "$key_file")" == "$key_file" ]] \
      || fail 'insecure-container control inventory is invalid'
  done
  first=$(mode_octal "$control/client_ed25519_key")
  second=$(mode_octal "$control/client_ed25519_key.pub")
  [[ "$first" == 600 && "$second" == 600 ]] || fail 'insecure-container control inventory is invalid'
}

container_present() {
  local listing
  if ! listing=$(bounded 30s "$docker_cmd" container ls --all --quiet --filter "name=^/${container}$"); then
    fail 'could not query insecure-container resources'
    return 2
  fi
  [[ -n "$listing" ]]
}

volume_present() {
  local listing
  if ! listing=$(bounded 30s "$docker_cmd" volume ls --quiet --filter "name=$volume"); then
    fail 'could not query insecure-container workspace resources'
    return 2
  fi
  grep -Fxq "$volume" <<<"$listing"
}

validate_container_ownership() {
  local labels
  labels=$(bounded 30s "$docker_cmd" container inspect --format '{{index .Config.Labels "dev.cogs.profile"}} {{index .Config.Labels "dev.cogs.state"}}' "$container")
  [[ "$labels" == "$profile $state_id" ]] || fail 'refusing to operate on a container without matching ownership labels'
}

validate_volume_ownership() {
  local labels
  labels=$(bounded 30s "$docker_cmd" volume inspect --format '{{index .Labels "dev.cogs.profile"}} {{index .Labels "dev.cogs.state"}}' "$volume")
  [[ "$labels" == "$profile $state_id" ]] || fail 'refusing to operate on a volume without matching ownership labels'
}

assert_resources_absent() {
  local rc status=0
  if container_present; then
    printf 'insecure-container teardown left the container behind\n' >&2
    status=1
  else
    rc=$?
    (( rc == 1 )) || status=1
  fi
  if volume_present; then
    printf 'insecure-container teardown left the workspace volume behind\n' >&2
    status=1
  else
    rc=$?
    (( rc == 1 )) || status=1
  fi
  return "$status"
}

remove_resources() {
  local rc status=0
  if container_present; then
    if ! validate_container_ownership; then
      status=1
    elif ! bounded 45s "$docker_cmd" container rm --force "$container" >/dev/null; then
      printf 'failed to remove insecure-container container\n' >&2
      status=1
    fi
  else
    rc=$?
    (( rc == 1 )) || status=1
  fi

  if volume_present; then
    if ! validate_volume_ownership; then
      status=1
    elif ! bounded 45s "$docker_cmd" volume rm --force "$volume" >/dev/null; then
      printf 'failed to remove insecure-container workspace volume\n' >&2
      status=1
    fi
  else
    rc=$?
    (( rc == 1 )) || status=1
  fi

  if ! assert_resources_absent; then status=1; fi
  return "$status"
}

cleanup_failed_create() {
  local original_status=${1:-1}
  trap - ERR INT TERM HUP
  if remove_resources; then
    rm -rf -- "$state"
  else
    printf 'insecure-container cleanup failed; retained state for recovery\n' >&2
    original_status=1
  fi
  if [[ "$result_emitted" != true ]]; then emit fail; fi
  exit "$original_status"
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
  validate_metadata
  [[ ! -e "$state" ]] || fail 'insecure-container state already exists; reset or destroy it first'

  local input="$state/input" control="$state/control" ca_private
  mkdir -p "$control"
  chmod 0700 "$state" "$control"
  printf '%s\n' "$state_id" > "$sentinel"
  printf '%s\n' "$container" > "$state/container"
  printf '%s\n' "$volume" > "$state/volume"
  trap 'cleanup_failed_create "$?"' ERR
  trap 'cleanup_failed_create 130' INT TERM HUP
  init_docker_tool_state
  assert_resources_absent

  # Build before generating controller keys so private material never enters the build context.
  bounded 10m "$docker_cmd" build --pull=false --tag "$image" --file "$repo/dev/insecure-sandbox/Dockerfile" "$repo"
  assert_resources_absent

  mkdir -p "$input"
  chmod 0700 "$input"
  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-host -f "$input/ssh_host_ed25519_key"
  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-client -f "$control/client_ed25519_key"
  cp "$control/client_ed25519_key.pub" "$input/client_ed25519_key.pub"
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
    rm -f "$ca_private"
  fi

  bounded 30s "$docker_cmd" volume create \
    --label dev.cogs.profile="$profile" \
    --label dev.cogs.state="$state_id" \
    "$volume" >/dev/null
  bounded 45s "$docker_cmd" run --detach \
    --name "$container" \
    --hostname sandbox \
    --label dev.cogs.profile="$profile" \
    --label dev.cogs.authority=functional-only \
    --label dev.cogs.state="$state_id" \
    --read-only \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=32m,mode=0700 \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m \
    --tmpfs /shared:rw,nosuid,nodev,noexec,size=8m,mode=0700 \
    --tmpfs /user:rw,nosuid,nodev,noexec,size=8m,mode=0700 \
    --mount "type=bind,src=$input,dst=/run/cogs-input,readonly" \
    --mount "type=volume,src=$volume,dst=/workspace" \
    --add-host host.docker.internal:host-gateway \
    --publish 127.0.0.1::2222 \
    --env COGS_PROFILE="$profile" \
    --env HTTP_PROXY="$http_proxy" \
    --env HTTPS_PROXY="$https_proxy" \
    --env NO_PROXY="127.0.0.1,localhost" \
    --env SSL_CERT_FILE=/run/cogs-runtime/egress-ca.crt \
    "$image" >/dev/null

  local running deadline
  sleep 1
  running=$(bounded 30s "$docker_cmd" inspect --format '{{.State.Running}}' "$container")
  if [[ "$running" != true ]]; then
    bounded 15s "$docker_cmd" logs "$container" >&2 || true
    fail 'insecure-container stopped during startup'
  fi
  port=$(bounded 30s "$docker_cmd" port "$container" 2222/tcp | awk -F: 'NR == 1 {print $NF}')
  [[ "$port" =~ ^[0-9]+$ ]] || fail 'failed to discover SSH port'
  printf '[127.0.0.1]:%s %s\n' "$port" "$(awk 'NF >= 2 {print $1 " " $2; exit}' "$input/ssh_host_ed25519_key.pub")" > "$state/known_hosts"
  printf '%s\n' "$port" > "$state/port"

  ssh_options
  deadline=$((SECONDS + 30))
  until bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 true >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      bounded 15s "$docker_cmd" logs "$container" >&2 || true
      fail 'insecure-container SSH readiness timed out'
    fi
    running=$(bounded 30s "$docker_cmd" inspect --format '{{.State.Running}}' "$container")
    if [[ "$running" != true ]]; then
      bounded 15s "$docker_cmd" logs "$container" >&2 || true
      fail 'insecure-container stopped before SSH became ready'
    fi
    sleep 1
  done

  trap on_error ERR
  trap on_signal INT TERM HUP
}

verify_runtime_identity() {
  local running mount published
  validate_container_ownership
  validate_volume_ownership
  running=$(bounded 30s "$docker_cmd" inspect --format '{{.State.Running}}' "$container")
  [[ "$running" == true ]] || fail 'recorded insecure-container is not running'
  mount=$(bounded 30s "$docker_cmd" inspect --format '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Name}}{{end}}{{end}}' "$container")
  [[ "$mount" == "$volume" ]] || fail 'recorded workspace volume is not mounted in the container'
  published=$(bounded 30s "$docker_cmd" port "$container" 2222/tcp)
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
  validate_metadata
  init_docker_tool_state
  verify_control_key_inventory
  [[ -s "$state/container" && -s "$state/volume" && -s "$state/port" ]] || fail 'insecure-container state is absent or incomplete'
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
      -i "$state/control/client_ed25519_key" -p "$port" \
      root@127.0.0.1 true >/dev/null 2>"$mismatch_log"; then
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
}

destroy() {
  validate_metadata
  if [[ -e "$state" ]]; then init_docker_tool_state; fi
  remove_resources
  rm -rf -- "$state"
  [[ ! -e "$state" ]] || fail 'controller state teardown verification failed'
}

case "$operation" in
  create|verify|destroy)
    require docker
    select_timeout
    acquire_lock
    "$operation"
    emit pass
    ;;
  reset)
    require docker
    require ssh
    require ssh-keygen
    require sftp
    require openssl
    require cmp
    select_timeout
    acquire_lock
    destroy
    create
    verify
    emit pass
    ;;
  *)
    printf 'usage: %s create|verify|reset|destroy\n' "$0" >&2
    exit 2
    ;;
esac
