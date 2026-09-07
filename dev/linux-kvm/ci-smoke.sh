#!/usr/bin/env bash
set -euo pipefail
umask 077
report=${1:-docs/security-evidence/generated/kvm-driver-smoke.json}
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
driver="$repo/dev/linux-kvm/driver.sh"
started=$(python3 -c 'import time; print(time.time_ns()//1000000)')
passed=false
acquired=false
helper_safe=true
export COGS_KVM_GENERATION
COGS_KVM_GENERATION=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
proxy_port=${COGS_KVM_PROXY_PORT:-18080}
[[ "$proxy_port" =~ ^[1-9][0-9]{0,4}$ && "$proxy_port" -ge 1 && "$proxy_port" -le 65535 ]] || exit 1
state=${COGS_KVM_STATE_DIR:-$repo/.cogs-dev/linux-kvm}
# Never adopt or pre-delete an ambient generation. This smoke requires fresh custody.
[[ ! -e "$state" && ! -L "$state" ]] || { echo 'FAIL: smoke requires absent state' >&2; exit 1; }
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  if [[ "$passed" != true ]]; then
    if [[ "$helper_safe" != true ]]; then
      echo 'FAIL: proxy helper retirement uncertain; retaining driver dependencies' >&2
    elif [[ "$acquired" == true ]] && ! "$driver" destroy >/dev/null; then
      echo 'FAIL: driver cleanup uncertain; retained recovery state' >&2
    fi
    write_report fail 'Linux/KVM isolated driver setup or teardown failed.'
    status=1
  fi
  exit "$status"
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
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# Only a successful exact ready receipt confers cleanup authority. Lost receipt
# or failed create retains driver custody; pathname existence grants nothing.
receipt=$("$driver" create)
python3 - "$receipt" "$COGS_KVM_GENERATION" <<'PY'
import json,sys
value=json.loads(sys.argv[1])
if value.get('status')!='ready' or value.get('profile')!='linux-kvm' or value.get('generation')!=sys.argv[2]:
    raise SystemExit('FAIL: create generation receipt mismatch')
PY
acquired=true
"$driver" verify >/dev/null
host_boot=$(cat /proc/sys/kernel/random/boot_id)
guest_boot=$("$driver" ssh cat /proc/sys/kernel/random/boot_id)
[[ -n "$guest_boot" && "$guest_boot" != "$host_boot" ]]
"$driver" ssh 'iptables -F 2>/dev/null || true; ip6tables -F 2>/dev/null || true; nft flush ruleset 2>/dev/null || true'
! "$driver" ssh 'timeout 2 bash -c "</dev/tcp/192.0.2.1/22"' >/dev/null 2>&1
! "$driver" ssh 'timeout 2 bash -c "</dev/tcp/1.1.1.1/443"' >/dev/null 2>&1
! "$driver" ssh 'ip route show default | grep -q .'

proxy_probe() {
  python3 - "$driver" "$proxy_port" <<'PY'
import os,select,signal,subprocess,sys,time
# No fork/EXEC: socat is one direct, non-daemonizing child, not a process tree.
# Do not poll/wait (reap) it before opening the pidfd; its PID cannot be reused.
def interrupted(signum,frame): raise RuntimeError('proxy probe interrupted')
for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,interrupted)
fd=None; child=None; helper_code=None
handled={signal.SIGINT,signal.SIGTERM,signal.SIGHUP}
previous=signal.pthread_sigmask(signal.SIG_BLOCK,handled)
try:
    child=subprocess.Popen(['socat',f'TCP-LISTEN:{sys.argv[2]},bind=0.0.0.0,reuseaddr','OPEN:/dev/null'],
                           preexec_fn=lambda:signal.pthread_sigmask(signal.SIG_SETMASK,previous))
    fd=os.pidfd_open(child.pid,0)
    poll=select.poll(); poll.register(fd,select.POLLIN)
    signal.pthread_sigmask(signal.SIG_SETMASK,previous)
    for _ in range(20):
        if poll.poll(0): raise RuntimeError('proxy helper exited before probe')
        result=subprocess.run([sys.argv[1],'ssh',f'timeout 2 bash -c "</dev/tcp/192.0.2.1/{sys.argv[2]}"'],
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if result.returncode==0: break
        time.sleep(.1)
    else: raise RuntimeError('proxy probe failed')
finally:
    # Defer handled signals during retirement; there is exactly one cleanup owner.
    for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP): signal.signal(sig,signal.SIG_IGN)
    if child is not None:
        if fd is None:
            # Unreaped direct child still reserves its PID, even on pidfd failure.
            child.kill(); helper_code=child.wait(timeout=5)
        else:
            try:
                poll=select.poll(); poll.register(fd,select.POLLIN)
                for sig,ms in ((signal.SIGTERM,2000),(signal.SIGKILL,5000)):
                    if poll.poll(0): break
                    signal.pidfd_send_signal(fd,sig,None,0)
                    if poll.poll(ms): break
                else: raise RuntimeError('proxy helper retirement uncertain')
                helper_code=child.wait(timeout=1)
            finally: os.close(fd)
    print('retired',flush=True)
    if helper_code not in (None,0,-signal.SIGTERM,-signal.SIGKILL):
        raise RuntimeError('proxy helper failed')
PY
}
helper_safe=false
probe_status=0
probe_receipt=$(proxy_probe) || probe_status=$?
[[ "$probe_receipt" == retired ]] || exit 1
helper_safe=true
[[ "$probe_status" == 0 ]] || exit 1

first_boot=$guest_boot
"$driver" reset >/dev/null
second_boot=$("$driver" ssh cat /proc/sys/kernel/random/boot_id)
[[ -n "$second_boot" && "$second_boot" != "$first_boot" && "$second_boot" != "$host_boot" ]]
"$driver" ssh grep -qx reset-persistent /workspace/reset-marker
"$driver" destroy >/dev/null
acquired=false
write_report pass 'Active KVM booted a distinct root guest; host TAP policy survived guest-firewall removal, denied non-proxy traffic, allowed only the proxy port, and reset preserved the workspace on a fresh boot.'
passed=true
printf 'PASS: authoritative Linux/KVM driver smoke wrote %s\n' "$report"
