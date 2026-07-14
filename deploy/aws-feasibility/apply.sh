#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
directory="$root/deploy/aws-feasibility"
tofu=$($root/scripts/install-opentofu.sh)
: "${AWS_PROFILE:=nebula}"
export AWS_PROFILE AWS_REGION=us-east-1
[[ ${COGS_AWS_APPLY_APPROVED:-} == "apply-one-cpu-instance" ]] || {
  printf 'manual gate closed: set COGS_AWS_APPLY_APPROVED=apply-one-cpu-instance only after reviewing the saved plan\n' >&2
  exit 1
}
[[ $(git -C "$root" status --porcelain) == "" ]] || { printf 'refusing to apply from a dirty tree\n' >&2; exit 1; }
plan="$directory/.state/campaign.tfplan"
[[ -f "$plan" && -f "$plan.sha256" ]] || { printf 'checked saved plan is missing\n' >&2; exit 1; }
[[ $(shasum -a 256 "$plan" | awk '{print $1}') == "$(cat "$plan.sha256")" ]] || {
  printf 'saved plan digest changed\n' >&2
  exit 1
}
python3 "$directory/check-plan.py" "$directory/.state/campaign.plan.json"
planned_revision=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["variables"]["source_revision"]["value"])' "$directory/.state/campaign.plan.json")
[[ "$planned_revision" == "$(git -C "$root" rev-parse HEAD)" ]] || { printf 'saved plan source revision is not the checked-out revision\n' >&2; exit 1; }

cleanup_on_error() {
  status=$?
  if (( status != 0 )); then
    printf 'apply/readiness failed; destroying partial campaign resources\n' >&2
    "$tofu" -chdir="$directory" destroy -auto-approve -input=false -lock-timeout=30s -var-file=.state/campaign.auto.tfvars.json || true
  fi
  exit "$status"
}
trap cleanup_on_error EXIT INT TERM
"$tofu" -chdir="$directory" apply -input=false -lock-timeout=30s .state/campaign.tfplan
instance_id=$("$tofu" -chdir="$directory" output -json campaign | python3 -c 'import json,sys; print(json.load(sys.stdin)["instance_id"])')
aws ec2 wait instance-running --instance-ids "$instance_id"
for _ in $(seq 1 60); do
  status=$(aws ssm describe-instance-information --filters "Key=InstanceIds,Values=$instance_id" --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)
  [[ "$status" == "Online" ]] && break
  sleep 10
done
[[ ${status:-} == "Online" ]] || { printf 'instance did not become SSM-online within ten minutes\n' >&2; exit 1; }
aws ec2 describe-instances --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].{State:State.Name,Type:InstanceType,PublicIpPresent:PublicIpAddress!=`null`,IamProfilePresent:IamInstanceProfile!=`null`,MetadataTokens:MetadataOptions.HttpTokens}' --output json >"$directory/.state/instance-readiness.json"
trap - EXIT INT TERM
printf 'One disposable instance is running and SSM-online: %s\n' "$instance_id"
printf 'Independent AWS termination and guest-local termination fallbacks are armed.\n'
