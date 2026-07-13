#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
state=${COGS_KVM_STATE_DIR:-$repo/.cogs-dev/linux-kvm}
probe="$repo/test/egress-conformance/guest-probes/black-box-probe.py"
log=$(mktemp)
result_file=$(mktemp)
cleanup() { rm -f -- "$log" "$result_file"; }
trap cleanup EXIT INT TERM HUP

for name in COGS_SUITE_GUEST_PROXY COGS_SUITE_TARGET_PORT COGS_SUITE_PUBLIC_CA COGS_SUITE_CAPABILITY COGS_SUITE_SCENARIO COGS_SUITE_KIND COGS_SUITE_EXPECT; do
  [[ -n "${!name:-}" ]] || { printf '{"passed":false,"diagnosticsRedacted":"KVM suite input is absent"}\n'; exit 0; }
done
if [[ "$COGS_SUITE_GUEST_PROXY" != http://192.0.2.1:18080 \
    || ! "$COGS_SUITE_TARGET_PORT" =~ ^[0-9]{1,5}$ \
    || ! "$COGS_SUITE_CAPABILITY" =~ ^[A-Za-z0-9._-]{0,256}$ \
    || ! "$COGS_SUITE_SCENARIO" =~ ^[a-z0-9.-]{1,64}$ \
    || ! "$COGS_SUITE_KIND" =~ ^(https|redirect|raw-http1|raw-http2|fault|revocation|confidentiality|bypass)$ \
    || ( "$COGS_SUITE_EXPECT" != allow && "$COGS_SUITE_EXPECT" != deny && "$COGS_SUITE_EXPECT" != safe ) ]]; then
  printf '{"passed":false,"diagnosticsRedacted":"KVM suite input is invalid"}\n'
  exit 0
fi
[[ -f "$state/.cogs-linux-kvm-v1" && -f "$state/control/client_ed25519_key" && -f "$state/known_hosts" ]] || {
  printf '{"passed":false,"diagnosticsRedacted":"KVM guest state is unavailable"}\n'; exit 0;
}
common=(
  -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1
  -o ServerAliveInterval=5 -o ServerAliveCountMax=1 -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$state/known_hosts" -o IdentitiesOnly=yes -o IdentityAgent=none
  -o ForwardAgent=no -o ClearAllForwardings=yes -i "$state/control/client_ed25519_key"
)
if ! scp "${common[@]}" -- "$probe" "$COGS_SUITE_PUBLIC_CA" root@192.0.2.2:/workspace/ >>"$log" 2>&1; then
  printf '{"passed":false,"diagnosticsRedacted":"KVM suite public material transfer failed"}\n'; exit 0
fi
ca_name=$(basename "$COGS_SUITE_PUBLIC_CA")
ssh "${common[@]}" root@192.0.2.2 \
  'iptables -F 2>/dev/null || true; ip6tables -F 2>/dev/null || true; nft flush ruleset 2>/dev/null || true' >>"$log" 2>&1
remote=(ssh "${common[@]}" root@192.0.2.2 env SSL_CERT_FILE="/workspace/$ca_name"
  python3 /workspace/black-box-probe.py "$COGS_SUITE_SCENARIO" "$COGS_SUITE_KIND" 192.0.2.1 18080
  "$COGS_SUITE_TARGET_PORT" "$COGS_SUITE_CAPABILITY" "$COGS_SUITE_EXPECT")
if [[ "$COGS_SUITE_SCENARIO" == long-lived-drain ]]; then
  if [[ ! "${COGS_SUITE_DRAIN_CONTAINER:-}" =~ ^cogs-[A-Za-z0-9_.-]{1,120}$ ]]; then
    printf '{"passed":false,"diagnosticsRedacted":"KVM drain control is invalid"}\n'; exit 0
  fi
  "${remote[@]}" >"$result_file" 2>>"$log" &
  remote_pid=$!
  sleep 1
  docker kill --signal=TERM "$COGS_SUITE_DRAIN_CONTAINER" >>"$log" 2>&1 || true
  wait "$remote_pid" || true
else
  "${remote[@]}" >"$result_file" 2>>"$log" || {
    printf '{"passed":false,"diagnosticsRedacted":"KVM suite probe transport failed"}\n'; exit 0;
  }
fi
result=$(<"$result_file")
[[ -n "$result" ]] || { printf '{"passed":false,"diagnosticsRedacted":"KVM suite probe returned no result"}\n'; exit 0; }
printf '%s\n' "$result"
