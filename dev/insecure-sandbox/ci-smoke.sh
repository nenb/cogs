#!/usr/bin/env bash
set -uo pipefail
umask 077

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
report=${1:-"$repo/docs/security-evidence/generated/insecure-container-smoke.json"}
driver="$repo/dev/insecure-sandbox/driver.sh"
state=${COGS_INSECURE_STATE_DIR:-"$repo/.cogs-dev/insecure-sandbox"}
source_revision=${COGS_SOURCE_REVISION:-$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)}
abort() {
  printf '%s\n' "$1" >&2
  exit 1
}
[[ "$source_revision" =~ ^[a-f0-9]{40}$ ]] || abort 'insecure-container source revision is absent or invalid'
command -v openssl >/dev/null 2>&1 || abort 'insecure-container smoke requires openssl'
generation=$(openssl rand -hex 16)
[[ "$generation" =~ ^[a-f0-9]{32}$ ]] || abort 'could not issue an insecure-container generation'
export COGS_INSECURE_GENERATION=$generation COGS_INSECURE_ORIGINAL_REVISION=$source_revision
started=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
started_ms=$(date +%s%3N)
status=0
# Keep -e disabled: this smoke accumulates guarded step failures into one redacted evidence report.
verify_passed=false
cleanup_pending=false
diagnostics=()
tmp_report=''
receipt_file=''
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

run_driver() {
  local duration=$1 command=$2 rc expected canonical bytes lines
  receipt_file=$(mktemp "${TMPDIR:-/tmp}/cogs-insecure-receipt.XXXXXX") || return 1
  bounded "$duration" "$driver" "$command" >"$receipt_file"
  rc=$?
  expected=pass
  (( rc == 0 )) || expected=fail
  canonical=$(printf '{"version":"cogs.dev-driver/v1alpha1","profile":"insecure-container","authority":"functional-only","command":"%s","result":"%s","generation":"%s"}' \
    "$command" "$expected" "$generation")
  bytes=$(wc -c < "$receipt_file")
  lines=$(wc -l < "$receipt_file")
  if (( bytes != ${#canonical} + 1 || lines != 1 )) || [[ "$(<"$receipt_file")" != "$canonical" ]]; then
    printf 'insecure-container rejected malformed, extra, duplicate, stale, or non-LF receipt for %s\n' "$command" >&2
    rc=1
  fi
  rm -f -- "$receipt_file"
  receipt_file=''
  return "$rc"
}

append_failure() {
  status=1
  diagnostics+=("$1")
}

cleanup() {
  local exit_status=$?
  trap - EXIT INT TERM HUP
  if [[ "$cleanup_pending" == true ]]; then
    cleanup_pending=false
    if ! run_driver 2m destroy; then
      printf 'insecure-container emergency teardown failed; cleanup authority was consumed\n' >&2
      exit_status=1
    fi
  fi
  [[ -z "$receipt_file" ]] || rm -f -- "$receipt_file"
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

if ! run_driver 12m create; then
  append_failure 'insecure-container create failed, exceeded its deadline, or returned an invalid receipt'
else
  cleanup_pending=true
  container=$(<"$state/container")
  if ! image_id=$(bounded 30s docker container inspect --format '{{.Image}}' "$container" 2>/dev/null) \
      || [[ ! "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]; then
    append_failure 'tested container image provenance was unavailable'
  fi
  if ! run_driver 2m verify; then
    append_failure 'insecure-container SSH/SFTP verification failed or exceeded its deadline'
  fi
  if ! run_driver 12m reset; then
    append_failure 'insecure-container reset failed or exceeded its deadline'
  elif ! run_driver 2m verify; then
    append_failure 'post-reset SSH/SFTP verification failed or exceeded its deadline'
  else
    verify_passed=true
    reset_container=$(<"$state/container")
    if [[ "$reset_container" != "$container" ]]; then
      append_failure 'reset replaced the exact acquired container'
    elif ! reset_image_id=$(bounded 30s docker container inspect --format '{{.Image}}' "$reset_container" 2>/dev/null) \
        || [[ "$reset_image_id" != "$image_id" ]]; then
      append_failure 'reset used an unexpected container image'
    fi
  fi
fi

if [[ "$cleanup_pending" == true ]]; then
  # Consume the one-shot cleanup authority before invocation: lost/malformed output must not trigger a retry.
  cleanup_pending=false
  if ! run_driver 2m destroy; then
    append_failure 'insecure-container teardown failed, exceeded its deadline, or returned an invalid receipt'
  fi
fi

completed=$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)
completed_ms=$(date +%s%3N)
if ! docker_version=$(bounded 30s docker version --format '{{.Server.Version}}' 2>/dev/null) || [[ -z "$docker_version" ]]; then
  docker_version=unavailable
  append_failure 'Docker runtime provenance was unavailable'
fi
if (( ${#diagnostics[@]} == 0 )); then
  diagnostics=('Create, SSH/SFTP, reset, post-reset, injected host-key pin, controller-key denial, root, workspace, CA, and proxy-input wiring controls passed.')
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
  python3 -I - "$tmp_report" <<'PY'
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
