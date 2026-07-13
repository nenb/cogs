#!/usr/bin/env bash
set -euo pipefail
umask 077

for name in COGS_ENVOY_PROXY COGS_ENVOY_TARGET COGS_ENVOY_PROXY_CA COGS_ENVOY_CAPABILITY COGS_ENVOY_EXPECT; do
  [[ -n "${!name:-}" ]] || { printf '{"passed":false,"diagnosticsRedacted":"probe input is absent"}\n'; exit 0; }
done

response=$(mktemp)
diagnostics=$(mktemp)
cleanup() { rm -f -- "$response" "$diagnostics"; }
trap cleanup EXIT

status=0
curl --silent --show-error \
  --output "$response" \
  --write-out '%{http_code}' \
  --max-time 15 \
  --connect-timeout 5 \
  --noproxy '' \
  --proxy "$COGS_ENVOY_PROXY" \
  --proxy-header "Proxy-Authorization: $COGS_ENVOY_CAPABILITY" \
  --cacert "$COGS_ENVOY_PROXY_CA" \
  --header 'Authorization: Bearer cogs-non-secret-placeholder' \
  --http1.1 \
  "$COGS_ENVOY_TARGET" >"$diagnostics.code" 2>"$diagnostics" || status=$?
code=$(<"$diagnostics.code")
rm -f "$diagnostics.code"

case "$COGS_ENVOY_EXPECT" in
  allow)
    if (( status == 0 )) && [[ "$code" == 200 ]] && [[ $(<"$response") == ok ]]; then
      printf '{"passed":true,"diagnosticsRedacted":"allowed HTTPS CONNECT was intercepted and returned the protected fixture response"}\n'
    else
      printf '{"passed":false,"diagnosticsRedacted":"allowed HTTPS CONNECT did not complete successfully"}\n'
    fi
    ;;
  deny)
    if [[ "$code" != 200 ]] && ! grep -Fqx 'ok' "$response"; then
      printf '{"passed":true,"diagnosticsRedacted":"invalid proxy capability was denied before the protected fixture"}\n'
    else
      printf '{"passed":false,"diagnosticsRedacted":"invalid proxy capability unexpectedly reached the protected fixture"}\n'
    fi
    ;;
  *)
    printf '{"passed":false,"diagnosticsRedacted":"probe expectation is invalid"}\n'
    ;;
esac
