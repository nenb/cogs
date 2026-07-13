#!/usr/bin/env bash
set -euo pipefail
umask 077
report=${1:-docs/security-evidence/generated/kvm-driver-smoke.json}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
driver="$repo/dev/linux-kvm/driver.sh"
started=$(python3 -c 'import time; print(time.time_ns()//1000000)')
passed=false
cleanup() {
  "$driver" destroy >/dev/null 2>&1 || true
  if [[ "$passed" != true && ! -f "$report" ]]; then write_report fail 'Linux/KVM isolated driver setup or teardown failed.' || true; fi
}
write_report() {
  local result=$1 diagnostic=$2
  mkdir -p "$(dirname "$report")"
  python3 - "$report" "$started" "$result" "$diagnostic" <<'PY'
import datetime,json,os,platform,subprocess,sys,time
path,started,result,diagnostic=sys.argv[1:]
start=int(started); end=time.time_ns()//1_000_000
fmt=lambda ms: datetime.datetime.fromtimestamp(ms/1000,datetime.timezone.utc).isoformat().replace('+00:00','Z')
revision=os.environ.get('COGS_SOURCE_REVISION') or subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
deps=['authorization','audit','revocation','identity','network_enforcement']
report={
 'version':'cogs.security-report/v1alpha1','report_id':f"kvm-driver-{os.environ.get('GITHUB_RUN_ID','local')}",
 'source_revision':revision,'profile':'linux-kvm','authority':'authoritative-local','started_at':fmt(start),
 'completed_at':fmt(end),'duration_ms':end-start,
 'environment':{'os':platform.system().lower(),'architecture':platform.machine(),'runner':os.environ.get('RUNNER_NAME','local-linux'),
  'runner_image':os.environ.get('ImageOS','unknown'),'runtime_versions':{'qemu':subprocess.check_output(['qemu-system-x86_64','--version'],text=True).splitlines()[0]},
  'metadata':{'kvm_present':os.path.exists('/dev/kvm'),'kvm_enabled':result=='pass','guest_root':result=='pass',
   'distinct_boot_ids':result=='pass','host_enforced_network':result=='pass','guest_firewall_trusted':False,
   'guest_image_sha512':'78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667'}},
 'components':[{'name':'qemu','version':subprocess.check_output(['qemu-system-x86_64','--version'],text=True).splitlines()[0]}],
 'dependencies':{name:{'mode':'real' if name=='network_enforcement' else 'not-applicable','implementation':'host TAP input/forward policy' if name=='network_enforcement' else 'driver qualification only'} for name in deps},
 'tests':[{'id':'runner.kvm-isolated-driver','group':'runner-qualification','result':result,'release_eligible':False,
  'dependency_modes':{name:'real' if name=='network_enforcement' else 'not-applicable' for name in deps},'diagnostics_redacted':diagnostic}],
 'known_limitations':['Driver smoke qualifies KVM, guest root, reset, and host network control; full proxy dependency results remain separate and stub-aware.']}
with open(path,'w') as f: json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
PY
}
trap cleanup EXIT INT TERM HUP

"$driver" destroy >/dev/null
"$driver" create >/dev/null
"$driver" verify >/dev/null
host_boot=$(cat /proc/sys/kernel/random/boot_id)
guest_boot=$($driver ssh cat /proc/sys/kernel/random/boot_id)
[[ -n "$guest_boot" && "$guest_boot" != "$host_boot" ]]
$driver ssh 'iptables -F 2>/dev/null || true; ip6tables -F 2>/dev/null || true; nft flush ruleset 2>/dev/null || true'
! $driver ssh 'timeout 2 bash -c "</dev/tcp/192.0.2.1/22"' >/dev/null 2>&1
! $driver ssh 'timeout 2 bash -c "</dev/tcp/1.1.1.1/443"' >/dev/null 2>&1
! $driver ssh 'ip route show default | grep -q .'

socat TCP-LISTEN:18080,bind=0.0.0.0,reuseaddr,fork EXEC:/bin/true &
socat_pid=$!
trap 'kill "$socat_pid" 2>/dev/null || true; cleanup' EXIT INT TERM HUP
for _ in $(seq 1 20); do
  $driver ssh 'timeout 1 bash -c "</dev/tcp/192.0.2.1/18080"' >/dev/null 2>&1 && break
  sleep 0.1
done
$driver ssh 'timeout 2 bash -c "</dev/tcp/192.0.2.1/18080"'
kill "$socat_pid" 2>/dev/null || true
wait "$socat_pid" 2>/dev/null || true
trap cleanup EXIT INT TERM HUP

first_boot=$guest_boot
"$driver" reset >/dev/null
second_boot=$($driver ssh cat /proc/sys/kernel/random/boot_id)
[[ -n "$second_boot" && "$second_boot" != "$first_boot" && "$second_boot" != "$host_boot" ]]
$driver ssh grep -qx reset-persistent /workspace/reset-marker
"$driver" destroy >/dev/null
write_report pass 'Active KVM booted a distinct root guest; host TAP policy survived guest-firewall removal, denied non-proxy traffic, allowed only the proxy port, and reset preserved the workspace on a fresh boot.'
passed=true
printf 'PASS: authoritative Linux/KVM driver smoke wrote %s\n' "$report"
