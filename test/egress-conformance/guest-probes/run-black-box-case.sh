#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
driver="$repo/dev/insecure-sandbox/driver.sh"
state="$repo/.cogs-dev/insecure-sandbox"
probe="$repo/test/egress-conformance/guest-probes/black-box-probe.py"
log=$(mktemp)
cleanup_needed=true
cleanup() {
  if [[ "$cleanup_needed" == true ]]; then "$driver" destroy >/dev/null 2>&1 || true; fi
  rm -f -- "$log"
}
trap cleanup EXIT INT TERM HUP

for name in COGS_SUITE_GUEST_PROXY COGS_SUITE_TARGET_PORT COGS_SUITE_PUBLIC_CA COGS_SUITE_CAPABILITY COGS_SUITE_SCENARIO COGS_SUITE_KIND COGS_SUITE_EXPECT; do
  [[ -n "${!name:-}" ]] || { printf '{"passed":false,"diagnosticsRedacted":"suite probe input is absent"}\n'; exit 0; }
done
if [[ ! "$COGS_SUITE_GUEST_PROXY" =~ ^http://host\.docker\.internal:[0-9]{1,5}$ \
    || ! "$COGS_SUITE_TARGET_PORT" =~ ^[0-9]{1,5}$ \
    || ! "$COGS_SUITE_CAPABILITY" =~ ^[A-Za-z0-9._-]{0,256}$ \
    || ! "$COGS_SUITE_SCENARIO" =~ ^[a-z0-9.-]{1,64}$ \
    || ! "$COGS_SUITE_KIND" =~ ^(https|redirect|raw-http1|raw-http2|fault|revocation|confidentiality)$ \
    || ( "$COGS_SUITE_EXPECT" != allow && "$COGS_SUITE_EXPECT" != deny && "$COGS_SUITE_EXPECT" != normalize ) ]]; then
  printf '{"passed":false,"diagnosticsRedacted":"suite probe input is invalid"}\n'
  exit 0
fi

if ! COGS_HTTP_PROXY="$COGS_SUITE_GUEST_PROXY" COGS_HTTPS_PROXY="$COGS_SUITE_GUEST_PROXY" \
  COGS_PUBLIC_CA_FILE="$COGS_SUITE_PUBLIC_CA" "$driver" create >"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"suite guest creation failed"}\n'
  exit 0
fi
if ! "$driver" verify >>"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"suite guest verification failed"}\n'
  exit 0
fi
port=$(<"$state/port")
common=(
  -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1
  -o ServerAliveInterval=5 -o ServerAliveCountMax=1 -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$state/known_hosts" -o IdentitiesOnly=yes -o IdentityAgent=none
  -o ForwardAgent=no -o ClearAllForwardings=yes -i "$state/control/client_ed25519_key"
)
if ! scp "${common[@]}" -P "$port" -- "$probe" root@127.0.0.1:/workspace/cogs-black-box-probe.py >>"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"suite probe transfer failed"}\n'
  exit 0
fi
proxy_port=${COGS_SUITE_GUEST_PROXY##*:}
result=$(ssh "${common[@]}" -p "$port" root@127.0.0.1 python3 /workspace/cogs-black-box-probe.py \
  "$COGS_SUITE_SCENARIO" "$COGS_SUITE_KIND" host.docker.internal "$proxy_port" "$COGS_SUITE_TARGET_PORT" \
  "$COGS_SUITE_CAPABILITY" "$COGS_SUITE_EXPECT" 2>>"$log") || {
  printf '{"passed":false,"diagnosticsRedacted":"suite guest probe transport failed"}\n'
  exit 0
}
if ! "$driver" destroy >>"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"suite guest teardown failed"}\n'
  exit 0
fi
cleanup_needed=false
printf '%s\n' "$result"
