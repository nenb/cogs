#!/usr/bin/env bash
set -uo pipefail
umask 077

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
report=${1:-"$repo/docs/security-evidence/generated/insecure-container-smoke.json"}
driver="$repo/dev/insecure-sandbox/driver.sh"
state=${COGS_INSECURE_STATE_DIR:-"$repo/.cogs-dev/insecure-sandbox"}
started=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
started_ms=$(date +%s%3N)
status=0
verify_passed=false
cleanup_pending=true
diagnostics=()
tmp_report=''
image_id=''

if command -v timeout >/dev/null 2>&1; then
  timeout_command=timeout
elif command -v gtimeout >/dev/null 2>&1; then
  timeout_command=gtimeout
else
  printf 'insecure-container smoke requires timeout (or gtimeout)\n' >&2
  exit 1
fi

bounded() {
  local duration=$1
  shift
  "$timeout_command" --signal=TERM --kill-after=10s "$duration" "$@"
}

append_failure() {
  status=1
  diagnostics+=("$1")
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM HUP
  if [[ "$cleanup_pending" == true ]]; then
    if ! bounded 2m "$driver" destroy >/dev/null; then
      printf 'insecure-container emergency teardown failed\n' >&2
      exit_status=1
    fi
  fi
  [[ -z "$tmp_report" ]] || rm -f -- "$tmp_report"
  exit "$exit_status"
}

interrupted() {
  append_failure 'insecure-container smoke was interrupted'
  exit 130
}

trap cleanup EXIT
trap interrupted INT TERM HUP
rm -f -- "$report"

if ! bounded 12m "$driver" create; then
  append_failure 'insecure-container create failed or exceeded its deadline'
else
  container=$(<"$state/container")
  if ! image_id=$(bounded 30s docker container inspect --format '{{.Image}}' "$container" 2>/dev/null) \
      || [[ ! "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    append_failure 'tested container image provenance was unavailable'
  fi
  if ! bounded 2m "$driver" verify; then
    append_failure 'insecure-container SSH/SFTP verification failed or exceeded its deadline'
  else
    verify_passed=true
  fi
fi

if ! bounded 2m "$driver" destroy; then
  append_failure 'insecure-container teardown failed or exceeded its deadline'
else
  cleanup_pending=false
fi

completed=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
completed_ms=$(date +%s%3N)
if ! docker_version=$(bounded 30s docker version --format '{{.Server.Version}}' 2>/dev/null) || [[ -z "$docker_version" ]]; then
  docker_version=unavailable
  append_failure 'Docker runtime provenance was unavailable'
fi
source_revision=${COGS_SOURCE_REVISION:-$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)}
if [[ ! "$source_revision" =~ ^[a-f0-9]{40}$ ]]; then
  printf 'insecure-container source revision is absent or invalid\n' >&2
  exit 1
fi
if (( ${#diagnostics[@]} == 0 )); then
  diagnostics=('SSH/SFTP, injected host-key pin, controller-key denial, root, workspace, CA, and proxy-input wiring controls passed.')
fi
diagnostic=$(IFS='; '; printf '%s' "${diagnostics[*]}")

report_dir=$(dirname "$report")
if ! mkdir -p "$report_dir"; then
  printf 'could not create insecure-container evidence directory\n' >&2
  exit 1
fi
tmp_report=$(mktemp "$report_dir/.insecure-container-smoke.XXXXXX") || exit 1

if ! STATUS=$status \
  VERIFY_PASSED=$verify_passed \
  DIAGNOSTIC=$diagnostic \
  STARTED=$started \
  COMPLETED=$completed \
  DURATION_MS=$((completed_ms - started_ms)) \
  IMAGE_ID=$image_id \
  DOCKER_VERSION=$docker_version \
  REPORT_ID="insecure-container-${GITHUB_RUN_ID:-local}" \
  SOURCE_REVISION="$source_revision" \
  python3 - "$tmp_report" <<'PY'
import json
import os
import platform
import sys

status = int(os.environ["STATUS"])
component = {"name": "insecure-sandbox", "version": "stage1"}
image = os.environ["IMAGE_ID"]
if image.startswith("sha256:") and len(image) == 71:
    component["image_digest"] = image
is_actions = os.environ.get("GITHUB_ACTIONS") == "true"
runner = (
    f"GitHub Actions {os.environ.get('RUNNER_NAME', 'unknown')}"
    if is_actions
    else "local Docker host"
)
report = {
    "version": "cogs.security-report/v1alpha1",
    "report_id": os.environ["REPORT_ID"],
    "source_revision": os.environ["SOURCE_REVISION"],
    "profile": "insecure-container",
    "authority": "functional-only",
    "started_at": os.environ["STARTED"],
    "completed_at": os.environ["COMPLETED"],
    "duration_ms": int(os.environ["DURATION_MS"]),
    "environment": {
        "os": platform.system().lower(),
        "architecture": platform.machine(),
        "runner": runner,
        "runner_image": os.environ.get("ImageOS", "local"),
        "runtime_versions": {"docker": os.environ["DOCKER_VERSION"]},
        "metadata": {
            "guest_root": os.environ["VERIFY_PASSED"] == "true",
            "isolation_claim": False,
            "proxy_behavior_tested": False,
        },
    },
    "components": [component],
    "dependencies": {
        name: {"mode": "not-applicable", "implementation": "Stage 1 driver smoke only"}
        for name in ["authorization", "audit", "revocation", "identity", "network_enforcement"]
    },
    "tests": [{
        "id": "driver.ssh-sftp-contract",
        "group": "driver-smoke",
        "result": "pass" if status == 0 else "fail",
        "release_eligible": False,
        "duration_ms": int(os.environ["DURATION_MS"]),
        "dependency_modes": {},
        "diagnostics_redacted": os.environ["DIAGNOSTIC"],
    }],
    "known_limitations": [
        "Plain containers provide no VM isolation or authoritative guest-root default-deny claim.",
        "Proxy and CA values are input-wiring checks only; proxy behavior awaits the first Stage 1 candidate adapter.",
    ],
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
then
  printf 'insecure-container evidence generation failed\n' >&2
  exit 1
fi

if ! mv -f -- "$tmp_report" "$report"; then
  printf 'insecure-container evidence publication failed\n' >&2
  exit 1
fi
tmp_report=''
exit "$status"
