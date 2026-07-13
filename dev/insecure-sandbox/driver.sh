#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
state=${COGS_INSECURE_STATE_DIR:-"$repo/.cogs-dev/insecure-sandbox"}
image=${COGS_INSECURE_IMAGE:-cogs-insecure-sandbox:dev}
profile=insecure-container

require() {
  command -v "$1" >/dev/null 2>&1 || { printf 'required command is missing: %s\n' "$1" >&2; exit 1; }
}
for command in docker ssh ssh-keygen sftp openssl; do require "$command"; done

emit() {
  printf '{"version":"cogs.dev-driver/v1alpha1","profile":"%s","authority":"functional-only","command":"%s","result":"%s"}\n' "$profile" "$1" "$2"
}

identifier() {
  printf '%s' "$state" | openssl dgst -sha256 | awk '{print substr($NF,1,12)}'
}

read_metadata() {
  [[ -s "$state/container" && -s "$state/volume" && -s "$state/port" ]] || {
    printf 'insecure-container state is absent or incomplete\n' >&2
    exit 1
  }
  container=$(<"$state/container")
  volume=$(<"$state/volume")
  port=$(<"$state/port")
}

ssh_options() {
  SSH_OPTIONS=(
    -F /dev/null
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ConnectionAttempts=1
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
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$state/known_hosts"
    -o IdentitiesOnly=yes
    -o IdentityAgent=none
    -i "$state/control/client_ed25519_key"
    -P "$port"
  )
}

create() {
  if [[ -e "$state/container" ]]; then
    printf 'insecure-container already exists; reset or destroy it first\n' >&2
    exit 1
  fi
  local id container volume input control ca_private
  id=$(identifier)
  container="cogs-insecure-$id"
  volume="cogs-insecure-workspace-$id"
  input="$state/input"
  control="$state/control"
  mkdir -p "$input" "$control"
  chmod 0700 "$state" "$input" "$control"

  cleanup_failed_create() {
    docker rm --force "$container" >/dev/null 2>&1 || true
    docker volume rm --force "$volume" >/dev/null 2>&1 || true
    rm -rf "$state"
  }
  trap cleanup_failed_create ERR INT TERM

  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-host -f "$input/ssh_host_ed25519_key"
  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-client -f "$control/client_ed25519_key"
  cp "$control/client_ed25519_key.pub" "$input/client_ed25519_key.pub"

  if [[ -n "${COGS_PUBLIC_CA_FILE:-}" ]]; then
    [[ -s "$COGS_PUBLIC_CA_FILE" ]] || { printf 'configured public CA does not exist\n' >&2; return 1; }
    cp "$COGS_PUBLIC_CA_FILE" "$input/egress-ca.crt"
  else
    ca_private="$control/ephemeral-ca.key"
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
      -subj '/CN=Cogs Insecure Driver Public CA' \
      -keyout "$ca_private" -out "$input/egress-ca.crt" >/dev/null 2>&1
    rm -f "$ca_private"
  fi

  docker build --pull=false --tag "$image" --file "$repo/dev/insecure-sandbox/Dockerfile" "$repo"
  docker volume create --label dev.cogs.profile="$profile" "$volume" >/dev/null
  docker run --detach \
    --name "$container" \
    --hostname sandbox \
    --label dev.cogs.profile="$profile" \
    --label dev.cogs.authority=functional-only \
    --read-only \
    --tmpfs /run:rw,nosuid,nodev,noexec,size=32m \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m \
    --mount "type=bind,src=$input,dst=/run/cogs-input,readonly" \
    --mount "type=volume,src=$volume,dst=/workspace" \
    --publish 127.0.0.1::2222 \
    --env COGS_PROFILE="$profile" \
    --env HTTP_PROXY="${COGS_HTTP_PROXY:-http://proxy.invalid:3128}" \
    --env HTTPS_PROXY="${COGS_HTTPS_PROXY:-${COGS_HTTP_PROXY:-http://proxy.invalid:3128}}" \
    --env NO_PROXY="127.0.0.1,localhost" \
    --env SSL_CERT_FILE=/run/cogs-input/egress-ca.crt \
    "$image" >/dev/null

  port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "2222/tcp") 0).HostPort}}' "$container")
  [[ "$port" =~ ^[0-9]+$ ]] || { printf 'failed to discover SSH port\n' >&2; return 1; }
  printf '[127.0.0.1]:%s %s\n' "$port" "$(awk 'NF >= 2 {print $1 " " $2; exit}' "$input/ssh_host_ed25519_key.pub")" > "$state/known_hosts"
  printf '%s\n' "$container" > "$state/container"
  printf '%s\n' "$volume" > "$state/volume"
  printf '%s\n' "$port" > "$state/port"

  ssh_options
  local deadline=$((SECONDS + 30))
  until ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 true >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      docker logs "$container" >&2 || true
      printf 'insecure-container SSH readiness timed out\n' >&2
      return 1
    fi
    if ! docker inspect --format '{{.State.Running}}' "$container" 2>/dev/null | grep -qx true; then
      docker logs "$container" >&2 || true
      printf 'insecure-container stopped before SSH became ready\n' >&2
      return 1
    fi
    sleep 1
  done

  trap - ERR INT TERM
  emit create pass
}

verify() {
  read_metadata
  ssh_options
  local observed
  observed=$(ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
    'test "$(id -u)" = 0 && test "$COGS_PROFILE" = insecure-container && test -n "$HTTP_PROXY" && test -n "$HTTPS_PROXY" && test -r "$SSL_CERT_FILE" && printf verified')
  [[ "$observed" == verified ]] || { printf 'SSH contract verification failed\n' >&2; exit 1; }

  local transfer="$state/control/sftp-control.txt"
  printf 'sftp-positive-control\n' > "$transfer"
  sftp "${SFTP_OPTIONS[@]}" -b - root@127.0.0.1 >/dev/null <<EOF
put $transfer /workspace/sftp-control.txt
get /workspace/sftp-control.txt $state/control/sftp-roundtrip.txt
EOF
  cmp "$transfer" "$state/control/sftp-roundtrip.txt"

  local wrong="$state/control/wrong_host_key"
  ssh-keygen -q -t ed25519 -N '' -C wrong-host-positive-control -f "$wrong"
  printf '[127.0.0.1]:%s %s\n' "$port" "$(awk 'NF >= 2 {print $1 " " $2; exit}' "$wrong.pub")" > "$state/control/wrong_known_hosts"
  if ssh -o "UserKnownHostsFile=$state/control/wrong_known_hosts" "${SSH_OPTIONS[@]}" \
      root@127.0.0.1 true >/dev/null 2>&1; then
    printf 'host-key mismatch positive control unexpectedly succeeded\n' >&2
    exit 1
  fi
  rm -f "$wrong" "$wrong.pub" "$state/control/wrong_known_hosts"
  emit verify pass
}

destroy() {
  if [[ ! -d "$state" ]]; then
    emit destroy pass
    return
  fi
  read_metadata
  docker rm --force "$container" >/dev/null 2>&1 || true
  docker volume rm --force "$volume" >/dev/null 2>&1 || true
  if docker inspect "$container" >/dev/null 2>&1 || docker volume inspect "$volume" >/dev/null 2>&1; then
    printf 'insecure-container teardown verification failed\n' >&2
    exit 1
  fi
  rm -rf "$state"
  emit destroy pass
}

case "${1:-}" in
  create) create ;;
  verify) verify ;;
  reset) destroy; create; verify ;;
  destroy) destroy ;;
  *) printf 'usage: %s create|verify|reset|destroy\n' "$0" >&2; exit 2 ;;
esac
