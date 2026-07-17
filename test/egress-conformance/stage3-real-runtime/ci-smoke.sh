#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

ENVOY_IMAGE="envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb"
ENVOY_DIGEST="sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb"
OPENBAO_IMAGE="quay.io/openbao/openbao:2.6.0@sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../.." && pwd)"
REPORT_DIR="${1:-${REPO_ROOT}/docs/security-evidence/generated/stage3-real-runtime}"
PROFILE="${COGS_STAGE3_REAL_RUNTIME_PROFILE:-insecure-container}"
if [ "${PROFILE}" != "insecure-container" ] && [ "${PROFILE}" != "linux-kvm" ]; then
  echo "invalid Stage 3 real-runtime profile" >&2
  exit 1
fi
SESSION_ID="$(printf '%s' "${COGS_SOURCE_REVISION:-local}-$$-$(date +%s%N)" | sha256sum | cut -c1-16)"
LABEL="cogs.stage3-real-runtime.session=${SESSION_ID}"
OPENBAO_CONTAINER="cogs-stage3-openbao-${SESSION_ID}"
TMP_ROOT="$(mktemp -d "${RUNNER_TEMP:-/tmp}/cogs-stage3-real-runtime.XXXXXX")"
ENVOY_CONTAINER=""
OPENBAO_PORT=""
TRUST_PATH="/usr/local/share/ca-certificates/cogs-stage3-real-runtime.crt"
TRUST_CLEANUP_ARMED=0
DIR_CREATED=0
TMPFS_MOUNTED=0
cleanup_failed=0
cleanup_messages=()

if command -v timeout >/dev/null 2>&1; then
  TIMEOUT=timeout
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT=gtimeout
else
  echo "stage3 real runtime smoke requires timeout or gtimeout" >&2
  exit 1
fi

bounded() {
  local duration=$1
  shift
  "${TIMEOUT}" --signal=TERM --kill-after=10s "${duration}" "$@"
}

record_cleanup_failure() {
  cleanup_failed=1
  cleanup_messages+=("$1")
  echo "$1" >&2
}

write_failure_report() {
  local diagnostic=${1:-"Stage 3 real-runtime smoke failed before validated evidence was published."}
  rm -rf -- "${REPORT_DIR}"/stage3-real-runtime-* 2>/dev/null || true
  mkdir -p -- "${REPORT_DIR}"
  python3 - "${REPORT_DIR}" "${COGS_SOURCE_REVISION:-}" "${PROFILE}" "${diagnostic}" <<'PY'
import datetime,json,os,platform,sys,time
out,revision,profile,diagnostic=sys.argv[1:]
if not revision:
 import subprocess; revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
now=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
authority='authoritative-local' if profile=='linux-kvm' else 'functional-only'
network='real' if profile=='linux-kvm' else 'not-applicable'
report={
 'version':'cogs.security-report/v1alpha1','report_id':f'stage3-real-runtime-{profile}-failure-{revision[:12]}',
 'source_revision':revision,'profile':profile,'authority':authority,'started_at':now,'completed_at':now,'duration_ms':0,
 'environment':{'os':platform.system().lower(),'architecture':platform.machine(),'runner':os.environ.get('RUNNER_NAME','local'),'runner_image':os.environ.get('ImageOS','local'),'runtime_versions':{'node':os.environ.get('NODE_VERSION','unknown')},'metadata':{'kvm_present':profile=='linux-kvm','kvm_enabled':False,'guest_root':False,'distinct_boot_ids':False} if profile=='linux-kvm' else {}},
 'components':[{'name':'cogs','version':'0.0.0'}],
 'dependencies':{name:{'mode':('real' if name in ('authorization','audit','revocation','identity') else network),'implementation':'failure before full Stage 3 evidence publication'} for name in ['authorization','audit','revocation','identity','network_enforcement']},
 'tests':[{'id':'stage3.real-runtime.failure','group':'credential-handling','result':'fail','release_eligible':False,'duration_ms':0,'dependency_modes':{'authorization':'real','audit':'real','identity':'real','revocation':'real','telemetry':'stubbed','network_enforcement':network},'diagnostics_redacted':diagnostic[:2048]}],
 'known_limitations':['Failure report only; no successful Stage 3 evidence claim.']}
dest=os.path.join(out,report['report_id']); os.makedirs(dest,exist_ok=True)
with open(os.path.join(dest,'report.json'),'w',encoding='utf-8') as f: json.dump(report,f,indent=2); f.write('\n')
PY
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  set +e
  if [ -n "${ENVOY_CONTAINER}" ]; then
    bounded 20s docker rm -f "${ENVOY_CONTAINER}" >/dev/null 2>&1 || record_cleanup_failure "Envoy extraction container cleanup failed"
  fi
  bounded 30s docker rm -f "${OPENBAO_CONTAINER}" >/dev/null 2>&1 || true
  local remaining_containers
  if ! remaining_containers="$(bounded 20s docker ps -a --filter "label=${LABEL}" --format '{{.ID}}' 2>/dev/null)"; then
    record_cleanup_failure "labeled container inventory command failed"
  elif [ -n "${remaining_containers}" ]; then
    record_cleanup_failure "labeled OpenBao/runtime container remained after cleanup"
  fi
  local remaining_volumes
  if ! remaining_volumes="$(bounded 20s docker volume ls --filter "label=${LABEL}" --format '{{.Name}}' 2>/dev/null)"; then
    record_cleanup_failure "labeled volume inventory command failed"
  elif [ -n "${remaining_volumes}" ]; then
    record_cleanup_failure "labeled OpenBao/runtime volume remained after cleanup"
  fi
  if [ "${TRUST_CLEANUP_ARMED}" = 1 ]; then
    bounded 30s sudo rm -f -- "${TRUST_PATH}" >/dev/null 2>&1 || record_cleanup_failure "failed to remove disposable CI trust anchor"
    bounded 60s sudo update-ca-certificates >/dev/null 2>&1 || record_cleanup_failure "failed to restore system CA bundle after disposable trust removal"
  fi
  if [ "${TMPFS_MOUNTED}" = 1 ]; then
    if [ -n "$(find /run/cogs/egress -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)" ]; then
      record_cleanup_failure "trusted tmpfs was not empty before unmount"
      bounded 20s sudo find /run/cogs/egress -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + >/dev/null 2>&1 || true
    fi
    bounded 20s sudo umount /run/cogs/egress >/dev/null 2>&1 || record_cleanup_failure "failed to unmount trusted tmpfs"
  fi
  if [ "${DIR_CREATED}" = 1 ]; then
    bounded 20s sudo rmdir /run/cogs/egress >/dev/null 2>&1 || record_cleanup_failure "failed to remove trusted tmpfs directory"
  fi
  rm -rf -- "${TMP_ROOT}" || record_cleanup_failure "failed to remove temporary runtime directory"
  if [ "${cleanup_failed}" -ne 0 ]; then
    printf 'stage3 real runtime cleanup ambiguity: %s\n' "${cleanup_messages[*]}" >&2
    write_failure_report "Stage 3 real-runtime cleanup failed closed."
    exit 1
  fi
  if [ "${status}" -ne 0 ]; then write_failure_report; fi
  exit "${status}"
}

interrupted() {
  echo "stage3 real runtime smoke interrupted" >&2
  exit 130
}
trap cleanup EXIT
trap interrupted INT TERM HUP

cd "${REPO_ROOT}"
if [ "${COGS_SOURCE_REVISION:-}" = "" ]; then
  COGS_SOURCE_REVISION="$(git rev-parse HEAD)"
fi
if ! [[ "${COGS_SOURCE_REVISION}" =~ ^[a-f0-9]{40}$ ]]; then
  echo "COGS_SOURCE_REVISION must be 40 lowercase hex" >&2
  exit 1
fi

ENVOY_ROOT="${TMP_ROOT}/envoy-root"
ENVOY_BIN_DIR="${TMP_ROOT}/envoy-bin"
mkdir -p -- "${ENVOY_ROOT}" "${ENVOY_BIN_DIR}" "${REPORT_DIR}"

bounded 3m docker pull "${ENVOY_IMAGE}" >/dev/null
bounded 30s docker image inspect --format '{{json .RepoDigests}}' "${ENVOY_IMAGE}" | grep -F "${ENVOY_DIGEST}" >/dev/null
ENVOY_CONTAINER="$(bounded 30s docker create --label "${LABEL}" "${ENVOY_IMAGE}")"
bounded 2m docker cp "${ENVOY_CONTAINER}:/usr/local/bin/envoy" "${ENVOY_BIN_DIR}/envoy"
chmod 0500 "${ENVOY_BIN_DIR}/envoy"
bounded 30s docker rm -f "${ENVOY_CONTAINER}" >/dev/null
ENVOY_CONTAINER=""
ENVOY_VERSION_OUTPUT="$(bounded 30s "${ENVOY_BIN_DIR}/envoy" --version)"
printf '%s\n' "${ENVOY_VERSION_OUTPUT}" | grep -F "1.38.3" >/dev/null

if [ -e "${TRUST_PATH}" ]; then
  echo "disposable CI trust anchor path already exists" >&2
  exit 1
fi
if [ -e /run/cogs/egress ]; then
  echo "/run/cogs/egress already exists before setup" >&2
  exit 1
fi
sudo mkdir -p /run/cogs/egress
DIR_CREATED=1
if mountpoint -q /run/cogs/egress; then
  echo "/run/cogs/egress is already mounted" >&2
  exit 1
fi
if [ -n "$(find /run/cogs/egress -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null || true)" ]; then
  echo "/run/cogs/egress is not empty before mount" >&2
  exit 1
fi
sudo mount -t tmpfs -o "size=32m,mode=0700,uid=$(id -u),gid=$(id -g),nosuid,nodev,noexec" tmpfs /run/cogs/egress
TMPFS_MOUNTED=1
[ "$(stat -f -c '%T' /run/cogs/egress)" = "tmpfs" ]
[ "$(stat -c '%u %a' /run/cogs/egress)" = "$(id -u) 700" ]

bounded 3m docker pull "${OPENBAO_IMAGE}" >/dev/null
bounded 45s docker run --detach --rm \
  --name "${OPENBAO_CONTAINER}" \
  --label "${LABEL}" \
  --user 100:1000 \
  --publish "127.0.0.1::8200" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --volume "${REPO_ROOT}/dev/openbao-model-auth/config.hcl:/openbao/cogs-config.hcl:ro" \
  "${OPENBAO_IMAGE}" server -config=/openbao/cogs-config.hcl >/dev/null
[ "$(bounded 10s docker inspect --format '{{.State.Running}}' "${OPENBAO_CONTAINER}")" = "true" ]
OPENBAO_PORT="$(bounded 10s docker inspect --format '{{(index (index .NetworkSettings.Ports "8200/tcp") 0).HostPort}}' "${OPENBAO_CONTAINER}")"
[[ "${OPENBAO_PORT}" =~ ^[0-9]+$ ]]
[ "$(bounded 10s docker inspect --format '{{(index (index .NetworkSettings.Ports "8200/tcp") 0).HostIp}}' "${OPENBAO_CONTAINER}")" = "127.0.0.1" ]
OPENBAO_RUNTIME_VERSION="$(bounded 10s docker exec "${OPENBAO_CONTAINER}" bao version)"
[[ "${OPENBAO_RUNTIME_VERSION}" =~ ^OpenBao[[:space:]]+v2\.6\.0([[:space:],]|$) ]]
ready=0
for _ in $(seq 1 60); do
  if COGS_OPENBAO_ADDR="http://127.0.0.1:${OPENBAO_PORT}" bounded 3s node -e 'fetch(`${process.env.COGS_OPENBAO_ADDR}/v1/sys/health`, { redirect: "error" }).then(()=>process.exit(0),()=>process.exit(1))' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ "${ready}" = 1 ]

TRUST_CLEANUP_ARMED=1
COGS_ENVOY_EXECUTABLE="${ENVOY_BIN_DIR}/envoy" \
COGS_ENVOY_IMAGE="${ENVOY_IMAGE}" \
COGS_ENVOY_IMAGE_DIGEST="${ENVOY_DIGEST}" \
COGS_OPENBAO_ADDR="http://127.0.0.1:${OPENBAO_PORT}" \
COGS_OPENBAO_IMAGE="${OPENBAO_IMAGE}" \
COGS_OPENBAO_RUNTIME_VERSION="${OPENBAO_RUNTIME_VERSION}" \
COGS_TRUST_CERT_PATH="${TRUST_PATH}" \
COGS_STAGE3_REAL_RUNTIME_TMP="${TMP_ROOT}" \
COGS_SOURCE_REVISION="${COGS_SOURCE_REVISION}" \
COGS_STAGE3_REAL_RUNTIME_PROFILE="${PROFILE}" \
bounded 3m npx --no-install tsx test/egress-conformance/stage3-real-runtime/harness.ts "${REPORT_DIR}"
