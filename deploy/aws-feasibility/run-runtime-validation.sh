#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
directory="$root/deploy/aws-feasibility"
state="$directory/.state"
tofu=$($root/scripts/install-opentofu.sh)
: "${AWS_PROFILE:=nebula}"
export AWS_PROFILE AWS_REGION=us-east-1
[[ -f "$state/terraform.tfstate" ]] || { printf 'campaign state is missing\n' >&2; exit 1; }
instance_id=$("$tofu" -chdir="$directory" output -json campaign | python3 -c 'import json,sys; print(json.load(sys.stdin)["instance_id"])')
[[ "$instance_id" =~ ^i-[0-9a-f]+$ ]] || { printf 'invalid state-bound instance ID\n' >&2; exit 1; }
script="$directory/remote/validate-runtime.sh"
payload=$(base64 <"$script" | tr -d '\n')
parameters=$(python3 - "$payload" <<'PY'
import json, sys
payload = sys.argv[1]
command = f"printf '%s' '{payload}' | base64 -d >/var/tmp/cogs-validate-runtime.sh && chmod 0700 /var/tmp/cogs-validate-runtime.sh && timeout 2700 /var/tmp/cogs-validate-runtime.sh"
print(json.dumps({'commands': [command]}))
PY
)
command_id=$(aws ssm send-command \
  --instance-ids "$instance_id" \
  --document-name AWS-RunShellScript \
  --comment "Cogs Stage 2 bounded KVM and Kata validation" \
  --timeout-seconds 2800 \
  --parameters "$parameters" \
  --query 'Command.CommandId' --output text)
[[ "$command_id" =~ ^[0-9a-f-]+$ ]] || { printf 'invalid SSM command ID\n' >&2; exit 1; }
printf '%s\n' "$command_id" >"$state/runtime-command-id.txt"
status=Pending
for _ in $(seq 1 280); do
  status=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" --query Status --output text 2>/dev/null || true)
  case "$status" in
    Success|Failed|Cancelled|TimedOut|Cancelling) break ;;
  esac
  sleep 10
done
if [[ "$status" != Success ]]; then
  aws ssm cancel-command --command-id "$command_id" >/dev/null 2>&1 || true
  diagnostics=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" --query '{Status:Status,StatusDetails:StatusDetails,ResponseCode:ResponseCode,Stderr:StandardErrorContent}' --output json 2>/dev/null || printf '{}')
  printf '%s\n' "$diagnostics" >"$state/runtime-failure.json"
  printf '%s\n' "$diagnostics" | head -c 4096 >&2
  printf '\nAWS runtime validation failed; destroy the campaign before debugging.\n' >&2
  exit 1
fi
stdout=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance_id" --query StandardOutputContent --output text)
runtime_json=$(printf '%s\n' "$stdout" | tail -n 1)
printf '%s\n' "$runtime_json" >"$state/remote-runtime-result.json"

"$tofu" -chdir="$directory" show -json >"$state/current-state.json"
instance_json=$(aws ec2 describe-instances --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].{State:State.Name,Type:InstanceType,ImageId:ImageId,Architecture:Architecture,Hypervisor:Hypervisor,RootDeviceType:RootDeviceType,MetadataTokens:MetadataOptions.HttpTokens,PublicIpPresent:PublicIpAddress!=`null`,LaunchTemplateId:LaunchTemplate.LaunchTemplateId,LaunchTemplateVersion:LaunchTemplate.Version}' --output json)
type_json=$(aws ec2 describe-instance-types --instance-types c8i-flex.large --query 'InstanceTypes[0].{Type:InstanceType,VCPU:VCpuInfo.DefaultVCpus,MemoryMiB:MemoryInfo.SizeInMiB,BareMetal:BareMetal,GpuPresent:GpuInfo!=`null`}' --output json)
python3 - "$state/remote-runtime-result.json" "$state/current-state.json" "$state/runtime-evidence.json" "$instance_json" "$type_json" <<'PY'
import json, sys
runtime_path, state_path, output_path, instance_raw, type_raw = sys.argv[1:]
runtime = json.load(open(runtime_path, encoding='utf-8'))
expected = {
  'version', 'result', 'host_kernel', 'guest_kernel', 'guest_root', 'cpu_vmx', 'kvm_device',
  'qmp_kvm_present', 'qmp_kvm_enabled', 'containerd_version', 'qemu_version', 'kata_runtime_version',
  'kata_archive_sha256', 'package_setup_ms', 'kata_boot_ms'
}
if set(runtime) != expected or runtime['result'] != 'pass':
    raise SystemExit('remote runtime result is malformed')
for key in ('guest_root', 'cpu_vmx', 'kvm_device', 'qmp_kvm_present', 'qmp_kvm_enabled'):
    if runtime[key] is not True:
        raise SystemExit(f'remote invariant failed: {key}')
if runtime['host_kernel'] == runtime['guest_kernel']:
    raise SystemExit('host and guest kernels are not distinct')
state = json.load(open(state_path, encoding='utf-8'))
values = state.get('values', {})
campaign = values.get('outputs', {}).get('campaign', {}).get('value', {})
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
evidence = {
  'version': 'cogs.aws-feasibility-evidence/v1alpha1',
  'authority': 'aws-feasibility',
  'result': 'pass',
  'source_revision': campaign['source_revision'],
  'region': campaign['region'],
  'expires_at': campaign['expiry'],
  'launch': {
    'instance_type': instance['Type'], 'image_id': instance['ImageId'], 'architecture': instance['Architecture'],
    'hypervisor': instance['Hypervisor'], 'root_device_type': instance['RootDeviceType'],
    'imds_v2': instance['MetadataTokens'] == 'required', 'ephemeral_public_ip': instance['PublicIpPresent'],
    'nested_virtualization': cpu[0]['nested_virtualization'], 'vcpu': instance_type['VCPU'],
    'memory_mib': instance_type['MemoryMiB'], 'bare_metal': instance_type['BareMetal'], 'gpu': instance_type['GpuPresent'],
  },
  'runtime': runtime,
}
with open(output_path, 'w', encoding='utf-8') as output:
    json.dump(evidence, output, sort_keys=True, separators=(',', ':'))
    output.write('\n')
print(json.dumps(evidence, sort_keys=True, separators=(',', ':')))
PY
npx --no-install tsx "$root/scripts/validate-aws-feasibility-report.ts" "$state/runtime-evidence.json"
