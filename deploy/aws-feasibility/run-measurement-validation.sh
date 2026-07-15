#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
directory="$root/deploy/aws-feasibility"
state="$directory/.state"
tofu=$($root/scripts/install-opentofu.sh)
validate_seconds() {
  local name=$1 value=$2 min=$3 max=$4
  [[ "$value" =~ ^[0-9]+$ ]] || { printf '%s must be an integer number of seconds\n' "$name" >&2; exit 2; }
  (( value >= min && value <= max )) || { printf '%s must be between %s and %s seconds\n' "$name" "$min" "$max" >&2; exit 2; }
}
remote_timeout_seconds=${COGS_STAGE2_REMOTE_TIMEOUT_SECONDS:-720}
ssm_timeout_seconds=${COGS_STAGE2_SSM_TIMEOUT_SECONDS:-780}
poll_interval_seconds=${COGS_STAGE2_SSM_POLL_INTERVAL_SECONDS:-5}
poll_attempts=${COGS_STAGE2_SSM_POLL_ATTEMPTS:-160}
validate_seconds COGS_STAGE2_REMOTE_TIMEOUT_SECONDS "$remote_timeout_seconds" 60 840
validate_seconds COGS_STAGE2_SSM_TIMEOUT_SECONDS "$ssm_timeout_seconds" 60 870
validate_seconds COGS_STAGE2_SSM_POLL_INTERVAL_SECONDS "$poll_interval_seconds" 1 30
[[ "$poll_attempts" =~ ^[0-9]+$ ]] || { printf 'COGS_STAGE2_SSM_POLL_ATTEMPTS must be an integer\n' >&2; exit 2; }
(( poll_attempts >= 1 && poll_attempts <= 900 )) || { printf 'COGS_STAGE2_SSM_POLL_ATTEMPTS out of range\n' >&2; exit 2; }
poll_timeout_seconds=$((poll_interval_seconds * poll_attempts))
(( remote_timeout_seconds < ssm_timeout_seconds && ssm_timeout_seconds < poll_timeout_seconds && poll_timeout_seconds <= 820 )) || {
  printf 'timeout hierarchy must satisfy remote < SSM < poll <= 820 seconds\n' >&2
  exit 2
}
: "${AWS_PROFILE:=nebula}"
export AWS_PROFILE AWS_REGION=us-east-1
[[ -f "$state/terraform.tfstate" ]] || { printf 'campaign state is missing\n' >&2; exit 1; }
[[ -f "$state/campaign-timing.json" ]] || { printf 'campaign timing is missing; rerun apply with the checked harness\n' >&2; exit 1; }
[[ $(git -C "$root" status --porcelain) == "" ]] || { printf 'refusing to send measurement script from a dirty tree\n' >&2; exit 1; }
planned_revision=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["variables"]["source_revision"]["value"])' "$state/campaign.plan.json")
[[ "$planned_revision" == "$(git -C "$root" rev-parse HEAD)" ]] || { printf 'saved plan source revision is not the checked-out revision\n' >&2; exit 1; }
"$tofu" -chdir="$directory" show -json >"$state/current-state.json"
python3 - "$state/current-state.json" "$planned_revision" <<'PY'
import json, sys
state_path, planned_revision = sys.argv[1:]
state = json.load(open(state_path, encoding='utf-8'))
campaign = state.get('values', {}).get('outputs', {}).get('campaign', {}).get('value', {})
if campaign.get('source_revision') != planned_revision:
    raise SystemExit('applied state source revision does not match saved plan and HEAD')
PY
instance_id=$("$tofu" -chdir="$directory" output -json campaign | python3 -c 'import json,sys; print(json.load(sys.stdin)["instance_id"])')
[[ "$instance_id" =~ ^i-[0-9a-f]+$ ]] || { printf 'invalid state-bound instance ID\n' >&2; exit 1; }
rm -f "$state/stage2-measurement-evidence.json" "$state/stage2-measurement-report.md" "$state/remote-measurement-result.json"
script="$directory/remote/measure-runtime.sh"
payload=$(base64 <"$script" | tr -d '\n')
parameters=$(python3 - "$payload" "$remote_timeout_seconds" <<'PY'
import json, shlex, sys
payload = sys.argv[1]
remote_timeout = sys.argv[2]
if not remote_timeout.isdecimal():
    raise SystemExit('remote timeout must be numeric')
command = ' '.join([
    'printf', '%s', shlex.quote(payload), '|', 'base64', '-d', '>/var/tmp/cogs-measure-runtime.sh', '&&',
    'chmod', '0700', '/var/tmp/cogs-measure-runtime.sh', '&&',
    'timeout', '--kill-after=5s', f'{remote_timeout}s', '/var/tmp/cogs-measure-runtime.sh',
])
print(json.dumps({'commands': [command]}))
PY
)
command_id=$(aws ssm send-command \
  --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript \
  --comment "Cogs Stage 2 bounded measurement validation" \
  --timeout-seconds "$ssm_timeout_seconds" \
  --parameters "$parameters" \
  --query 'Command.CommandId' --output text)
[[ "$command_id" =~ ^[0-9a-f-]+$ ]] || { printf 'invalid SSM command ID\n' >&2; exit 1; }
printf '%s\n' "$command_id" >"$state/measurement-command-id.txt"
status=Pending
for _ in $(seq 1 "$poll_attempts"); do
  status=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" --query Status --output text 2>/dev/null || true)
  case "$status" in
    Success|Failed|Cancelled|TimedOut|Cancelling) break ;;
  esac
  sleep "$poll_interval_seconds"
done
if [[ "$status" != Success ]]; then
  aws ssm cancel-command --command-id "$command_id" >/dev/null 2>&1 || true
  diagnostics=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" --query '{Status:Status,StatusDetails:StatusDetails,ResponseCode:ResponseCode,Stderr:StandardErrorContent}' --output json 2>/dev/null || printf '{}')
  printf '%s\n' "$diagnostics" | head -c 8192 >"$state/measurement-failure.json"
  printf '%s\n' "$diagnostics" | head -c 4096 >&2
  printf '\nAWS Stage 2 measurement validation failed; destroy the campaign before debugging.\n' >&2
  exit 1
fi
stdout=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" --query StandardOutputContent --output text)
measurement_json=$(printf '%s\n' "$stdout" | tail -n 1)
printf '%s\n' "$measurement_json" >"$state/remote-measurement-result.json"

instance_json=$(aws ec2 describe-instances --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].{State:State.Name,Type:InstanceType,ImageId:ImageId,Architecture:Architecture,MetadataTokens:MetadataOptions.HttpTokens,PublicIpPresent:PublicIpAddress!=`null`}' --output json)
type_json=$(aws ec2 describe-instance-types --instance-types c8i-flex.large --query 'InstanceTypes[0].{Type:InstanceType,VCPU:VCpuInfo.DefaultVCpus,MemoryMiB:MemoryInfo.SizeInMiB,BareMetal:BareMetal,GpuPresent:GpuInfo!=`null`}' --output json)
completed_at=$(python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
PY
)
python3 - "$state/remote-measurement-result.json" "$state/current-state.json" "$state/campaign-timing.json" "$state/stage2-measurement-evidence.json" "$root/schemas/aws-stage2-measurement-evidence-v1alpha1.json" "$instance_json" "$type_json" "$completed_at" "$planned_revision" <<'PY'
import json, sys
from datetime import datetime, timezone
measurement_path, state_path, timing_path, output_path, schema_path, instance_raw, type_raw, completed_at, planned_revision = sys.argv[1:]
measurement = json.load(open(measurement_path, encoding='utf-8'))
state = json.load(open(state_path, encoding='utf-8'))
timing = json.load(open(timing_path, encoding='utf-8'))
schema = json.load(open(schema_path, encoding='utf-8'))
measurement_schema = schema.get('properties', {}).get('measurement', {})
schema_properties = measurement_schema.get('properties', {})
schema_required = set(measurement_schema.get('required', []))
allowed_measurement = set(schema_properties)
if not allowed_measurement or schema_required != allowed_measurement or measurement_schema.get('additionalProperties') is not False:
    raise SystemExit('measurement schema is not an exact remote-result key contract')
measurement_keys = set(measurement)
missing = sorted(allowed_measurement - measurement_keys)
extra = sorted(measurement_keys - allowed_measurement)
if missing or extra or measurement.get('result') != 'pass':
    diagnostics = []
    if missing:
        diagnostics.append('missing=' + ','.join(missing))
    if extra:
        diagnostics.append('extra=' + ','.join(extra))
    if measurement.get('result') != 'pass':
        diagnostics.append('result=' + repr(measurement.get('result')))
    raise SystemExit('remote measurement result is malformed: ' + '; '.join(diagnostics))
if measurement['host_kernel'] == measurement['guest_kernel']:
    raise SystemExit('host and guest kernels are not distinct')
for key in ('guest_root', 'cpu_vmx', 'kvm_device', 'qmp_kvm_present', 'qmp_kvm_enabled'):
    if measurement[key] is not True:
        raise SystemExit(f'remote invariant failed: {key}')
values = state.get('values', {})
campaign = values.get('outputs', {}).get('campaign', {}).get('value', {})
if campaign.get('source_revision') != planned_revision:
    raise SystemExit('applied state source revision does not match planned/head revision')
resources = values.get('root_module', {}).get('resources', [])
launches = [item for item in resources if item.get('address') == 'aws_launch_template.host']
if len(launches) != 1:
    raise SystemExit('state does not contain one launch template')
cpu = launches[0]['values'].get('cpu_options', [])
if len(cpu) != 1 or cpu[0].get('nested_virtualization') != 'enabled':
    raise SystemExit('applied launch template does not retain nested virtualization')
instance = json.loads(instance_raw)
instance_type = json.loads(type_raw)
if instance.get('State') != 'running' or instance.get('Type') != 'c8i-flex.large' or instance.get('MetadataTokens') != 'required':
    raise SystemExit('running instance metadata violates the campaign plan')
if instance_type.get('BareMetal') is not False or instance_type.get('GpuPresent') is not False or instance_type.get('VCPU') != 2:
    raise SystemExit('instance type is not the approved two-vCPU non-GPU virtual type')
def parse(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))
started = parse(timing['apply_started_at'])
running = parse(timing['instance_running_at'])
ssm = parse(timing['ssm_online_at'])
completed = parse(completed_at)
observed_ms = max(1, int((completed - started).total_seconds() * 1000))
apply_to_running_ms = max(1, int((running - started).total_seconds() * 1000))
apply_to_ssm_online_ms = max(1, int((ssm - started).total_seconds() * 1000))
hours = observed_ms / 3_600_000
# c8i-flex.large Linux on-demand plus ephemeral public IPv4 and a small gp3 root-volume allowance.
hourly = 0.08902 + 0.005 + 0.003
estimated_cost = round(hours * hourly, 4)
measurement_sample_count = len(measurement['kata_cold_boot']['samples'])
limitations = [
  'single EC2 host campaign; EC2 launch p50/p95 requires multiple launches and is not measured by this harness',
  'SSM readiness has one sample per campaign; SSH-ready is not measured because Stage 2 access is SSM-only',
  'Git and package-build measurements are host baselines only; representative sandbox Git/build/package workload acceptance remains unmet by this evidence',
  'density estimate is a conservative bound, not a scheduler or isolation claim',
]
evidence = {
  'version': 'cogs.aws-stage2-measurement-evidence/v1alpha1',
  'authority': 'aws-feasibility',
  'result': 'pass',
  'source_revision': campaign['source_revision'],
  'region': campaign['region'],
  'expires_at': campaign['expiry'],
  'launch': {
    'instance_type': instance['Type'], 'image_id': instance['ImageId'], 'architecture': instance['Architecture'],
    'imds_v2': instance['MetadataTokens'] == 'required', 'nested_virtualization': cpu[0]['nested_virtualization'],
    'vcpu': instance_type['VCPU'], 'memory_mib': instance_type['MemoryMiB'],
    'bare_metal': instance_type['BareMetal'], 'gpu': instance_type['GpuPresent'],
  },
  'campaign': {
    'sample_count': measurement_sample_count,
    'observed_duration_ms': observed_ms,
    'apply_to_running_ms': apply_to_running_ms,
    'apply_to_ssm_online_ms': apply_to_ssm_online_ms,
    'cleanup_observed': False,
    'final_zero_inventory_total': -1,
    'estimated_cost_usd': estimated_cost,
    'cost_basis': 'bounded estimate from apply-start to measurement-complete, not SSH-ready, multiplied by c8i-flex.large Linux on-demand 0.08902 USD/hour, ephemeral IPv4 0.005 USD/hour, and a small gp3 allowance; excludes unrelated account costs and destroy minutes until run-measurement-campaign records cleanup',
  },
  'measurement': measurement,
  'limitations': limitations,
}
with open(output_path, 'w', encoding='utf-8') as output:
    json.dump(evidence, output, sort_keys=True, separators=(',', ':'))
    output.write('\n')
print(json.dumps(evidence, sort_keys=True, separators=(',', ':')))
PY
npx --no-install tsx "$root/scripts/validate-aws-stage2-measurement-report.ts" --provisional "$state/stage2-measurement-evidence.json"
