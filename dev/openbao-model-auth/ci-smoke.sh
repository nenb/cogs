#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

OPENBAO_IMAGE="quay.io/openbao/openbao:2.6.0@sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653"
REPORT_DIR="${1:-docs/security-evidence/generated/openbao-model-auth}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
TIMEOUT="timeout"
if ! command -v "${TIMEOUT}" >/dev/null 2>&1; then
  TIMEOUT="gtimeout"
fi
if ! command -v "${TIMEOUT}" >/dev/null 2>&1; then
  echo "OpenBao smoke requires timeout or gtimeout" >&2
  exit 1
fi

cd "${REPO_ROOT}"
if [[ "${COGS_SOURCE_REVISION:-}" == "" ]]; then
  COGS_SOURCE_REVISION="$(git rev-parse HEAD)"
fi
if ! [[ "${COGS_SOURCE_REVISION}" =~ ^[a-f0-9]{40}$ ]]; then
  echo "COGS_SOURCE_REVISION must be 40 lowercase hex" >&2
  exit 1
fi

SESSION_ID="$(printf '%s' "${COGS_SOURCE_REVISION}-$$-$(date +%s)" | shasum -a 256 | cut -c1-16)"
CONTAINER="cogs-openbao-model-auth-${SESSION_ID}"
LABEL_KEY="cogs.openbao-model-auth.session"
LABEL="${LABEL_KEY}=${SESSION_ID}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cogs-openbao-model-auth.XXXXXX")"
PORT=""

cleanup_inventory() {
  local ids
  ids="$({ "${TIMEOUT}" 10s docker ps -a --filter "label=${LABEL}" --format '{{.ID}}'; } 2>/dev/null || true)"
  if [ -n "${ids}" ]; then
    while IFS= read -r id; do
      [ -n "${id}" ] && "${TIMEOUT}" 20s docker rm -f "${id}" >/dev/null 2>&1 || true
    done <<<"${ids}"
  fi
  rm -rf -- "${TMP_DIR}"
}
verify_zero_inventory() {
  local containers
  local volumes
  if ! containers="$({ "${TIMEOUT}" 10s docker ps -a --filter "label=${LABEL}" --format '{{.ID}}'; } 2>/dev/null)"; then
    echo "OpenBao smoke cleanup failed: container inventory command failed" >&2
    return 1
  fi
  if [ -n "${containers}" ]; then
    echo "OpenBao smoke cleanup failed: labeled container remains" >&2
    return 1
  fi
  if ! volumes="$({ "${TIMEOUT}" 10s docker volume ls --filter "label=${LABEL}" --format '{{.Name}}'; } 2>/dev/null)"; then
    echo "OpenBao smoke cleanup failed: volume inventory command failed" >&2
    return 1
  fi
  if [ -n "${volumes}" ]; then
    echo "OpenBao smoke cleanup failed: labeled volume remains" >&2
    return 1
  fi
  if [ -e "${TMP_DIR}" ]; then
    echo "OpenBao smoke cleanup failed: temp state remains" >&2
    return 1
  fi
}
cleanup_exit() {
  local status=$?
  set +e
  cleanup_inventory
  verify_zero_inventory || status=1
  exit "${status}"
}
signal_exit() {
  trap - EXIT HUP INT TERM
  set +e
  cleanup_inventory
  verify_zero_inventory >/dev/null 2>&1 || true
  exit 130
}
trap cleanup_exit EXIT
trap signal_exit HUP INT TERM

mkdir -p -- "${REPORT_DIR}"
chmod 700 "${TMP_DIR}"
"${TIMEOUT}" 120s docker pull "${OPENBAO_IMAGE}" >/dev/null

"${TIMEOUT}" 45s docker run --detach --rm \
  --name "${CONTAINER}" \
  --label "${LABEL}" \
  --user 100:1000 \
  --publish "127.0.0.1::8200" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "${REPO_ROOT}/dev/openbao-model-auth/config.hcl:/openbao/cogs-config.hcl:ro" \
  "${OPENBAO_IMAGE}" server -config=/openbao/cogs-config.hcl >/dev/null

if [ "$({ "${TIMEOUT}" 10s docker inspect --format '{{.State.Running}}' "${CONTAINER}"; } 2>/dev/null)" != "true" ]; then
  echo "OpenBao smoke container is not running" >&2
  exit 1
fi
PORT="$({ "${TIMEOUT}" 10s docker inspect --format '{{(index (index .NetworkSettings.Ports "8200/tcp") 0).HostPort}}' "${CONTAINER}"; } 2>/dev/null)"
if ! [[ "${PORT}" =~ ^[0-9]+$ ]]; then
  echo "OpenBao smoke could not determine loopback port" >&2
  exit 1
fi
BINDING="$({ "${TIMEOUT}" 10s docker inspect --format '{{(index (index .NetworkSettings.Ports "8200/tcp") 0).HostIp}}' "${CONTAINER}"; } 2>/dev/null)"
if [ "${BINDING}" != "127.0.0.1" ]; then
  echo "OpenBao smoke port is not loopback-bound" >&2
  exit 1
fi
OPENBAO_RUNTIME_VERSION="$({ "${TIMEOUT}" 10s docker exec "${CONTAINER}" bao version; } 2>/dev/null)"
if ! [[ "${OPENBAO_RUNTIME_VERSION}" =~ ^OpenBao[[:space:]]+v2\.6\.0([[:space:],]|$) ]]; then
  echo "OpenBao smoke runtime version mismatch" >&2
  exit 1
fi

ready=0
for _ in $(seq 1 60); do
  if COGS_OPENBAO_ADDR="http://127.0.0.1:${PORT}" "${TIMEOUT}" 3s node -e 'fetch(`${process.env.COGS_OPENBAO_ADDR}/v1/sys/health`, { redirect: "error" }).then(()=>process.exit(0),()=>process.exit(1))' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "${ready}" != 1 ]; then
  echo "OpenBao smoke readiness timed out" >&2
  exit 1
fi

COGS_OPENBAO_ADDR="http://127.0.0.1:${PORT}" \
COGS_OPENBAO_REPORT_DIR="${REPORT_DIR}" \
COGS_OPENBAO_RUNTIME_VERSION="${OPENBAO_RUNTIME_VERSION}" \
COGS_SOURCE_REVISION="${COGS_SOURCE_REVISION}" \
"${TIMEOUT}" 60s npx --no-install tsx dev/openbao-model-auth/smoke.ts
