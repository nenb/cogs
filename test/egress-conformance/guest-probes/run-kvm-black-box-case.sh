#!/usr/bin/env bash
set -euo pipefail
# Retired legacy ingress: no sentinel discovery, raw transport, temporary files,
# cleanup or environment override. Migration requires a separately reviewed gate.
printf 'FAIL: ADR0335 legacy KVM conformance execution is not admitted\n' >&2
exit 1
