#!/usr/bin/env bash
set -eEuo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
directory=${COGS_AWS_FEASIBILITY_DIRECTORY:-$root/deploy/aws-feasibility}
state="$directory/.state"
validator=${COGS_STAGE2_MEASUREMENT_VALIDATOR:-npx --no-install tsx $root/scripts/validate-aws-stage2-measurement-report.ts}
renderer=${COGS_STAGE2_MEASUREMENT_RENDERER:-npx --no-install tsx $root/scripts/render-aws-stage2-measurement-report.ts}
validate_seconds() {
  local name=$1 value=$2 min=$3 max=$4
  [[ "$value" =~ ^[0-9]+$ ]] || { printf '%s must be an integer number of seconds\n' "$name" >&2; exit 2; }
  (( value >= min && value <= max )) || { printf '%s must be between %s and %s seconds\n' "$name" "$min" "$max" >&2; exit 2; }
}
validation_timeout_seconds=${COGS_STAGE2_ORCHESTRATOR_VALIDATION_TIMEOUT_SECONDS:-840}
poll_interval_seconds=${COGS_STAGE2_SSM_POLL_INTERVAL_SECONDS:-5}
poll_attempts=${COGS_STAGE2_SSM_POLL_ATTEMPTS:-160}
validate_seconds COGS_STAGE2_ORCHESTRATOR_VALIDATION_TIMEOUT_SECONDS "$validation_timeout_seconds" 1 900
validate_seconds COGS_STAGE2_SSM_POLL_INTERVAL_SECONDS "$poll_interval_seconds" 1 30
[[ "$poll_attempts" =~ ^[0-9]+$ ]] || { printf 'COGS_STAGE2_SSM_POLL_ATTEMPTS must be an integer\n' >&2; exit 2; }
(( poll_attempts >= 1 && poll_attempts <= 900 )) || { printf 'COGS_STAGE2_SSM_POLL_ATTEMPTS out of range\n' >&2; exit 2; }
poll_timeout_seconds=$((poll_interval_seconds * poll_attempts))
(( poll_timeout_seconds < validation_timeout_seconds )) || { printf 'poll timeout must be less than orchestrator timeout\n' >&2; exit 2; }
: "${AWS_PROFILE:=nebula}"
export AWS_PROFILE AWS_REGION=us-east-1

cleanup_started_at=""
cleanup_completed_at=""
status=0
timestamp() { python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
PY
}
remove_measurement_artifacts() {
  rm -f "$state/stage2-measurement-evidence.json" "$state/stage2-measurement-report.md" "$state/remote-measurement-result.json"
}
finalize_evidence() {
  local evidence="$state/stage2-measurement-evidence.json"
  local inventory="$state/final-zero-resource-inventory.json"
  [[ -f "$evidence" && -f "$inventory" && -n "$cleanup_started_at" && -n "$cleanup_completed_at" ]] || return 0
  python3 - "$evidence" "$inventory" "$cleanup_completed_at" <<'PY'
import json, sys
from datetime import datetime
path, inventory_path, cleanup_completed_at = sys.argv[1:]
def parse(value): return datetime.fromisoformat(value.replace('Z', '+00:00'))
with open(path, encoding='utf-8') as handle:
    evidence = json.load(handle)
with open(inventory_path, encoding='utf-8') as handle:
    inventory = json.load(handle)
if inventory.get('total') != 0:
    raise SystemExit('final inventory is not zero')
timing_path = path.rsplit('/', 1)[0] + '/campaign-timing.json'
with open(timing_path, encoding='utf-8') as handle:
    timing = json.load(handle)
started = parse(timing['apply_started_at'])
completed = parse(cleanup_completed_at)
observed_ms = max(1, int((completed - started).total_seconds() * 1000))
hourly = 0.08902 + 0.005 + 0.003
estimated_cost = round((observed_ms / 3_600_000) * hourly, 4)
evidence['campaign']['observed_duration_ms'] = observed_ms
evidence['campaign']['cleanup_observed'] = True
evidence['campaign']['final_zero_inventory_total'] = 0
evidence['campaign']['estimated_cost_usd'] = estimated_cost
evidence['campaign']['cost_basis'] = 'observed apply-start through destroy-complete duration multiplied by c8i-flex.large Linux on-demand 0.08902 USD/hour, ephemeral IPv4 0.005 USD/hour, and a small gp3 allowance; excludes unrelated account costs; not SSH-ready timing'
with open(path, 'w', encoding='utf-8') as output:
    json.dump(evidence, output, sort_keys=True, separators=(',', ':'))
    output.write('\n')
PY
  # shellcheck disable=SC2086
  $validator "$evidence" || return $?
  # shellcheck disable=SC2086
  $renderer "$evidence" "$state/stage2-measurement-report.md" || return $?
}
cleanup() {
  body_status=$?
  cleanup_status=$body_status
  trap - EXIT
  cleanup_started_at=$(timestamp)
  set +e
  "$directory/destroy.sh"
  destroy_status=$?
  set -e
  (( destroy_status == 0 )) || cleanup_status=$destroy_status
  cleanup_completed_at=$(timestamp)
  set +e
  "$directory/inventory.sh" >"$state/final-zero-resource-inventory.json"
  inventory_status=$?
  set -e
  (( inventory_status == 0 )) || cleanup_status=$inventory_status
  set +e
  python3 - "$state/final-zero-resource-inventory.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as handle:
    inventory = json.load(handle)
if inventory.get('total') != 0:
    raise SystemExit('final inventory is not zero')
PY
  zero_inventory_status=$?
  set -e
  (( zero_inventory_status == 0 )) || cleanup_status=$zero_inventory_status
  if (( body_status == 0 && destroy_status == 0 && inventory_status == 0 && zero_inventory_status == 0 )); then
    set +e
    finalize_evidence
    finalize_status=$?
    set -e
    if (( finalize_status != 0 )); then
      cleanup_status=$finalize_status
      remove_measurement_artifacts
    fi
  else
    remove_measurement_artifacts
  fi
  exit "$cleanup_status"
}

[[ ${COGS_AWS_MEASUREMENT_CAMPAIGN_APPROVED:-} == "run-one-stage2-measurement-campaign" ]] || {
  printf 'manual gate closed: set COGS_AWS_MEASUREMENT_CAMPAIGN_APPROVED=run-one-stage2-measurement-campaign only after reviewing plan and cost bounds\n' >&2
  exit 1
}
[[ $(git -C "$root" status --porcelain) == "" ]] || { printf 'refusing to run a campaign from a dirty tree\n' >&2; exit 1; }
remove_measurement_artifacts
"$directory/plan.sh"
interrupt() {
  signal_status=$1
  trap - INT TERM
  exit "$signal_status"
}
trap cleanup EXIT
trap 'interrupt 130' INT
trap 'interrupt 143' TERM
COGS_AWS_APPLY_APPROVED=apply-one-cpu-instance "$directory/apply.sh"
timeout --kill-after=5s "${validation_timeout_seconds}s" "$directory/run-measurement-validation.sh"
