#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $# != 2 || ! $1 =~ ^[1-7]$ || ! $2 =~ ^[1-7]$ || $1 -gt $2 ]]; then
  echo "usage: $0 START_ORDINAL END_ORDINAL" >&2
  exit 64
fi
start_ordinal=$1
end_ordinal=$2
for name in RUNNER_TEMP GITHUB_RUN_ID GITHUB_SHA H G Q AMI_ID AMI_COMMITMENT \
  STATIC_CONTROL_SHA256 ROOTFS_DESCRIPTOR_SHA256 BUDGET_EMAIL; do
  [[ -n ${!name:-} ]] || { echo "missing $name" >&2; exit 64; }
done

work="$RUNNER_TEMP/aws-seven-cycle-tofu"
trace_root="$RUNNER_TEMP/seven-cycle-trace"
install -d -m 0700 "$work" "$trace_root" "$HOME/.aws"
cp deploy/aws-feasibility/{main.tf,outputs.tf,variables.tf,versions.tf,.terraform.lock.hcl} "$work/"
printf '[profile nebula]\nregion = us-east-1\noutput = json\n' >"$HOME/.aws/config"
printf '[nebula]\naws_access_key_id = %s\naws_secret_access_key = %s\naws_session_token = %s\n' \
  "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_SESSION_TOKEN" >"$HOME/.aws/credentials"
export AWS_PROFILE=nebula AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=
batch=$(printf '%s' "throwaway-seven-$GITHUB_RUN_ID-$GITHUB_SHA" | sha256sum | cut -d' ' -f1)
export TF_VAR_aws_profile=nebula TF_VAR_aws_region=us-east-1
export TF_VAR_availability_zone=us-east-1a TF_VAR_instance_type=c8i-flex.large
export TF_VAR_ami_id="$AMI_ID" TF_VAR_ami_commitment="$AMI_COMMITMENT"
export TF_VAR_batch_commitment="$batch"
export TF_VAR_source_revision="$H" TF_VAR_control_revision="$G"
export TF_VAR_rootfs_descriptor_sha256="$ROOTFS_DESCRIPTOR_SHA256"
export TF_VAR_budget_alert_email="$BUDGET_EMAIL"
AWS_PROFILE=nebula bash deploy/aws-feasibility/inventory.sh \
  >"$trace_root/preflight-zero-inventory.json"
[[ $(jq -r .total "$trace_root/preflight-zero-inventory.json") == 0 ]]
tofu=$(COGS_TOFU_BIN="$RUNNER_TEMP/tofu" scripts/install-opentofu.sh)
"$tofu" -chdir="$work" init -input=false

cleanup() {
  rc=$?
  trap - EXIT HUP INT TERM
  set +e
  "$tofu" -chdir="$work" destroy -auto-approve -input=false
  destroy_rc=$?
  AWS_PROFILE=nebula bash deploy/aws-feasibility/inventory.sh \
    >"$trace_root/trap-final-inventory.json"
  inventory_rc=$?
  rm -f "$HOME/.aws/credentials" "$HOME/.aws/config"
  if [[ $destroy_rc -ne 0 || $inventory_rc -ne 0 ]]; then exit 97; fi
  exit "$rc"
}
trap cleanup EXIT HUP INT TERM

tracer64=$(base64 -w0 deploy/aws-feasibility/remote/completion_aws_full_cycle_trace.py)
for ordinal in $(seq "$start_ordinal" "$end_ordinal"); do
  if [[ $ordinal -eq 1 ]]; then mode=full; else mode=readiness; fi
  cycle="$trace_root/cycle-$ordinal"
  install -d -m 0700 "$cycle"
  export TF_VAR_cycle_ordinal="$ordinal"
  TF_VAR_expires_at="$(date -u -d '+3 hours' +%Y-%m-%dT%H:%M:%SZ)"
  export TF_VAR_expires_at
  "$tofu" -chdir="$work" apply -auto-approve -input=false
  "$tofu" -chdir="$work" output -json campaign >"$cycle/campaign.json"
  instance=$(jq -er .instance_id "$cycle/campaign.json")
  aws ec2 wait instance-running --instance-ids "$instance"
  status=Offline
  for _ in $(seq 1 120); do
    status=$(aws ssm describe-instance-information \
      --filters "Key=InstanceIds,Values=$instance" \
      --query 'InstanceInformationList[0].PingStatus' --output text)
    [[ $status == Online ]] && break
    sleep 5
  done
  [[ $status == Online ]]

  python3 - "$batch" "$H" "$G" "$STATIC_CONTROL_SHA256" \
    "$ROOTFS_DESCRIPTOR_SHA256" "$AMI_COMMITMENT" "$ordinal" "$mode" \
    >"$cycle/grant.json" <<'PY'
import dataclasses,json,pathlib,sys
sys.path.insert(0,str(pathlib.Path('deploy/aws-feasibility').resolve()))
import completion_campaign_production as p
batch,h,g,control,rootfs,ami,ordinal,mode=sys.argv[1:]
fields={'batch_commitment':batch,'ordinal':int(ordinal),'mode':mode,
  'implementation_revision':h,'control_revision':g,
  'static_control_sha256':control,'rootfs_descriptor_sha256':rootfs,
  'ami_commitment':ami,'plan_sha256':'e55812f8acef92083da92c875288c1b3761ce61267c03fd066866cc7e2a42f0d'}
grant=p.CycleLaunchGrant(**fields,grant_commitment=p._commit(
  b'cogs.stage2-cycle-launch-grant/v1',fields))
print(json.dumps({'version':'cogs.stage2-cycle-launch-grant/v1',
  **dataclasses.asdict(grant)},sort_keys=True,separators=(',',':')))
PY
  grant64=$(base64 -w0 "$cycle/grant.json")
  python3 - "$H" "$Q" "$grant64" "$tracer64" "$mode" \
    >"$cycle/ssm-parameters.json" <<'PY'
import json,sys
h,q,grant,tracer,mode=sys.argv[1:]
shell=(
  "set -eu; umask 077; test ! -e /var/lib/cogs; "
  "for x in git python3 tar zstd; do command -v \"$x\" >/dev/null; done; "
  "w=/root/cogs-stage2-bootstrap; test ! -e \"$w\"; mkdir -m 700 \"$w\"; "
  "g='env -i HOME=/nonexistent PATH=/usr/bin:/bin GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 /usr/bin/git -c credential.helper= -c core.hooksPath=/dev/null'; "
  "umask 022; $g init -q \"$w/H\"; $g -C \"$w/H\" remote add origin https://github.com/nenb/cogs.git; "
  f"$g -C \"$w/H\" fetch -q --no-tags --depth=1 origin {h}; $g -C \"$w/H\" checkout -q --detach FETCH_HEAD; "
  "umask 077; $g init -q \"$w/Q\"; $g -C \"$w/Q\" remote add origin https://github.com/nenb/cogs.git; "
  f"$g -C \"$w/Q\" fetch -q --no-tags --depth=1 origin {q}; $g -C \"$w/Q\" checkout -q --detach FETCH_HEAD; "
  "install -d -m 755 /run/netns; chmod 755 /opt; "
  "python3 -I -B \"$w/H/scripts/prepare-stage2-fixed-source.py\" >/dev/null; "
  "python3 -I -B \"$w/H/scripts/stage2-stage-prebuilt-control.py\" stage-qualification >/dev/null; "
  "rm -rf -- \"$w\"; "
  "/usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/usr/bin:/bin TZ=UTC /usr/bin/python3 -I -B /var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/remote/completion_kata_immutable_preparation.py >/dev/null; "
  f"printf '%s' '{tracer}' | base64 -d >/root/cogs-stage2-trace.py; chmod 500 /root/cogs-stage2-trace.py; "
  f"printf '%s\\n' '{mode}' >/root/cogs-stage2-cycle-mode; chmod 400 /root/cogs-stage2-cycle-mode; "
  "python3 -I -B /var/lib/cogs/stage2-completion-v1/source/scripts/provision-stage2-nft-owner.py; "
  "d=/var/lib/cogs/stage2-completion-v1/cycle-authority-v1; install -d -m 700 \"$d\"; "
  f"printf '%s' '{grant}' | base64 -d >\"$d/grant.json\"; chmod 400 \"$d/grant.json\"; "
  "/usr/bin/env -i HOME=/nonexistent LANG=C LC_ALL=C PATH=/opt/kata/bin:/usr/sbin:/usr/bin:/sbin:/bin TZ=UTC /usr/bin/python3 -I -B /root/cogs-stage2-trace.py")
print(json.dumps({'commands':[shell],'executionTimeout':['5400']},separators=(',',':')))
PY
  command=$(aws ssm send-command --instance-ids "$instance" \
    --document-name AWS-RunShellScript --timeout-seconds 5400 \
    --parameters "file://$cycle/ssm-parameters.json" \
    --query Command.CommandId --output text)
  trace="$cycle/aws-cycle-trace.json"
  while :; do
    if aws ssm get-command-invocation --command-id "$command" --instance-id "$instance" \
      --output json >"$trace.tmp" 2>/dev/null; then
      status=$(jq -r .Status "$trace.tmp")
      case "$status" in
        Success|Cancelled|Failed|TimedOut|Cancelling) mv "$trace.tmp" "$trace"; break ;;
      esac
    fi
    sleep 5
  done
  jq --argjson ordinal "$ordinal" --arg mode "$mode" \
    '{ordinal:$ordinal,mode:$mode,Status,ResponseCode,ExecutionStartDateTime,
      ExecutionEndDateTime,TraceEvents:(.StandardErrorContent | split("\n") |
      map(select(length > 0) | try (fromjson | .event) catch "non-json"))}' "$trace"
  cycle_rc=0
  [[ -s $trace ]] || cycle_rc=2
  [[ $(jq -r .Status "$trace") == Success ]] || cycle_rc=2
  [[ $(jq -r .ResponseCode "$trace") == 0 ]] || cycle_rc=2

  set +e
  "$tofu" -chdir="$work" destroy -auto-approve -input=false
  destroy_rc=$?
  AWS_PROFILE=nebula bash deploy/aws-feasibility/inventory.sh \
    >"$cycle/final-inventory.json"
  inventory_rc=$?
  set -e
  if [[ $destroy_rc -ne 0 || $inventory_rc -ne 0 ]]; then exit 97; fi
  [[ $(jq -r .total "$cycle/final-inventory.json") == 0 ]]
  if [[ $cycle_rc -ne 0 ]]; then exit "$cycle_rc"; fi
done

jq -n --arg run_id "$GITHUB_RUN_ID" --arg head_sha "$GITHUB_SHA" \
  --argjson start "$start_ordinal" --argjson end "$end_ordinal" \
  '{version:"cogs.stage2-throwaway-cycle-range/v1",run_id:$run_id,
    head_sha:$head_sha,start_ordinal:$start,end_ordinal:$end,
    status:"passed",authoritative:false}' >"$trace_root/range-summary.json"
