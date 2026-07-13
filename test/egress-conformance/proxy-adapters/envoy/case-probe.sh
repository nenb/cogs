#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
driver="$repo/dev/insecure-sandbox/driver.sh"
state="$repo/.cogs-dev/insecure-sandbox"
log=$(mktemp)
cleanup_needed=true
cleanup() {
  if [[ "$cleanup_needed" == true ]]; then "$driver" destroy >/dev/null 2>&1 || true; fi
  rm -f -- "$log"
}
trap cleanup EXIT INT TERM HUP

for name in COGS_ENVOY_GUEST_PROXY COGS_ENVOY_TARGET COGS_ENVOY_PROXY_CA COGS_ENVOY_CAPABILITY COGS_ENVOY_EXPECT; do
  [[ -n "${!name:-}" ]] || { printf '{"passed":false,"diagnosticsRedacted":"probe input is absent"}\n'; exit 0; }
done
if [[ ! "$COGS_ENVOY_GUEST_PROXY" =~ ^http://host\.docker\.internal:[0-9]{1,5}$ \
    || ! "$COGS_ENVOY_TARGET" =~ ^https://localhost:[0-9]{1,5}/protected/header$ \
    || ! "$COGS_ENVOY_CAPABILITY" =~ ^[A-Za-z0-9._-]{16,256}$ \
    || ( "$COGS_ENVOY_EXPECT" != allow && "$COGS_ENVOY_EXPECT" != deny ) ]]; then
  printf '{"passed":false,"diagnosticsRedacted":"probe input is invalid"}\n'
  exit 0
fi

if ! COGS_HTTP_PROXY="$COGS_ENVOY_GUEST_PROXY" \
  COGS_HTTPS_PROXY="$COGS_ENVOY_GUEST_PROXY" \
  COGS_PUBLIC_CA_FILE="$COGS_ENVOY_PROXY_CA" \
  "$driver" create >"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"insecure-container guest creation failed"}\n'
  exit 0
fi
if ! "$driver" verify >>"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"insecure-container guest SSH/SFTP verification failed"}\n'
  exit 0
fi

port=$(<"$state/port")
ssh_options=(
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

result=$(ssh "${ssh_options[@]}" root@127.0.0.1 \
  bash -s -- "$COGS_ENVOY_EXPECT" "$COGS_ENVOY_TARGET" "$COGS_ENVOY_CAPABILITY" 2>>"$log" <<'REMOTE'
set -euo pipefail
expect=$1
target=$2
capability=$3
response=$(mktemp)
code_file=$(mktemp)
cleanup() { rm -f -- "$response" "$code_file"; }
trap cleanup EXIT
status=0
curl --silent --show-error \
  --output "$response" \
  --write-out '%{http_code}' \
  --max-time 15 \
  --connect-timeout 5 \
  --noproxy '' \
  --proxy "$HTTPS_PROXY" \
  --proxy-header "Proxy-Authorization: $capability" \
  --cacert "$SSL_CERT_FILE" \
  --header 'Authorization: Bearer cogs-non-secret-placeholder' \
  --http1.1 \
  "$target" >"$code_file" 2>/dev/null || status=$?
code=$(<"$code_file")
case "$expect" in
  allow)
    if (( status == 0 )) && [[ "$code" == 200 ]] && [[ $(<"$response") == ok ]]; then
      printf '{"passed":true,"diagnosticsRedacted":"guest allowed HTTPS CONNECT was intercepted and returned the protected fixture response"}\n'
    else
      printf '{"passed":false,"diagnosticsRedacted":"guest allowed HTTPS CONNECT failed with curl exit %s and HTTP status %s"}\n' "$status" "${code:-none}"
    fi
    ;;
  deny)
    if [[ "$code" != 200 ]] && ! grep -Fqx 'ok' "$response"; then
      printf '{"passed":true,"diagnosticsRedacted":"guest invalid proxy capability was denied before the protected fixture"}\n'
    else
      printf '{"passed":false,"diagnosticsRedacted":"guest invalid proxy capability unexpectedly reached the protected fixture"}\n'
    fi
    ;;
esac
REMOTE
) || {
  printf '{"passed":false,"diagnosticsRedacted":"guest probe transport failed"}\n'
  exit 0
}

if ! "$driver" destroy >>"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"insecure-container guest teardown failed"}\n'
  exit 0
fi
cleanup_needed=false
printf '%s\n' "$result"
