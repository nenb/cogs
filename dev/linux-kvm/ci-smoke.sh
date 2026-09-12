#!/usr/bin/env bash
set -euo pipefail
umask 077
report=${1:-docs/security-evidence/generated/kvm-driver-smoke.json}
script=${BASH_SOURCE[0]}
repo=${script%/dev/linux-kvm/ci-smoke.sh}
[[ "$repo" != "$script" ]] || repo=$PWD
repo=$(builtin cd "$repo" && builtin pwd -P)
# shellcheck source=dev/linux-kvm/git-tools.sh
source "$repo/dev/linux-kvm/git-tools.sh"
cogs_kvm_execution_gate
driver="$repo/dev/linux-kvm/driver.sh"
started=$(/usr/bin/python3 -I -B -c 'import time; print(time.time_ns()//1000000)')
passed=false
acquired=false
helper_safe=true
boot_records=
export COGS_KVM_GENERATION COGS_SOURCE_REVISION
# The gate has already bound this generation to the workflow run/attempt/source;
# a random smoke nonce would silently create an unreceipted execution path.
[[ "${COGS_KVM_GENERATION:-}" =~ ^[a-f0-9]{32}$ && "${COGS_SOURCE_REVISION:-}" =~ ^[a-f0-9]{40}$ ]] || exit 1
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
    elif [[ "$acquired" == true ]]; then
      local cleanup_receipt cleanup_status=0
      cleanup_receipt=$(mktemp)
      acquired=false # consume before invocation, including failure/lost response
      "$driver" destroy >"$cleanup_receipt" || cleanup_status=$?
      if [[ $cleanup_status -eq 0 ]]; then
        exact_receipt "$cleanup_receipt" destroy || cleanup_status=$?
      fi
      rm -f "$cleanup_receipt"
      [[ $cleanup_status -eq 0 ]] || echo 'FAIL: driver cleanup uncertain; retained recovery state' >&2
    fi
    write_report fail 'Linux/KVM isolated driver setup or teardown failed.' || status=1
    status=1
  fi
  if [[ -n "$boot_records" ]]; then
    rm -f -- "$boot_records/first" "$boot_records/second"
    rmdir -- "$boot_records"
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
   'distinct_boot_ids':result=='pass','host_enforced_network':False,'guest_firewall_trusted':False,
   'guest_image_sha512':'78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667'}},
 'components':[{'name':'qemu','version':subprocess.check_output(['qemu-system-x86_64','--version'],text=True).splitlines()[0]}],
 'dependencies':{name:{'mode':'real' if name=='network_enforcement' else 'not-applicable','implementation':'host TAP input/forward policy' if name=='network_enforcement' else 'driver qualification only'} for name in deps},
 'tests':[{'id':'runner.kvm-isolated-driver','group':'runner-qualification','result':result,'release_eligible':False,
  'dependency_modes':{name:'real' if name=='network_enforcement' else 'not-applicable' for name in deps},'diagnostics_redacted':diagnostic}],
 'known_limitations':['Driver smoke observes KVM, guest root, generation-bound proxy reachability, and reset. Non-proxy failures lack live same-destination controls and grant no host-network enforcement evidence.']}
with open(path,'w') as f: json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
PY
}
exact_receipt() {
  python3 -I - "$1" "$COGS_KVM_GENERATION" "$2" "$proxy_port" <<'PY'
import json,pathlib,re,sys
path,generation,command,port=sys.argv[1:]
raw=pathlib.Path(path).read_bytes()
if len(raw)>8192 or not raw.endswith(b'\n') or raw.count(b'\n')!=1:
    raise SystemExit('FAIL: driver receipt framing mismatch')
def pairs(items):
    value={}
    for key,item in items:
        if key in value: raise ValueError('duplicate receipt key')
        value[key]=item
    return value
try: value=json.loads(raw,object_pairs_hook=pairs)
except (UnicodeError,ValueError) as error: raise SystemExit(f'FAIL: malformed driver receipt: {error}')
if raw!=(json.dumps(value,separators=(',',':'))+'\n').encode():
    raise SystemExit('FAIL: noncanonical driver receipt')
if command=='destroy':
    expected={'profile':'linux-kvm','status':'destroyed','generation':generation,'command':'destroy'}
else:
    keys={'status','profile','guest_root','kvm_enabled','distinct_boot_ids','guest_kernel',
          'guest_image_sha512','host_ip','guest_ip','proxy_port','generation','command'}
    if set(value)!=keys or any(value.get(name) is not True for name in ('guest_root','kvm_enabled','distinct_boot_ids')) \
       or value.get('status')!='ready' or value.get('profile')!='linux-kvm' \
       or value.get('generation')!=generation or value.get('command')!=command \
       or type(value.get('guest_kernel')) is not str or not re.fullmatch(r'[0-9A-Za-z._+-]{1,64}',value['guest_kernel']) \
       or value.get('guest_image_sha512')!='78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667' \
       or value.get('host_ip')!='192.0.2.1' or value.get('guest_ip')!='192.0.2.2' \
       or type(value.get('proxy_port')) is not int or value['proxy_port']!=int(port):
        raise SystemExit(f'FAIL: {command} generation receipt mismatch')
    expected=value
if value!=expected: raise SystemExit(f'FAIL: {command} generation receipt mismatch')
PY
}
run_ready() {
  local command=$1 file status=0
  file=$(mktemp)
  "$driver" "$command" >"$file" || status=$?
  if [[ $status -eq 0 ]]; then exact_receipt "$file" "$command" || status=$?; fi
  rm -f "$file"
  return "$status"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

# Only a successful exact ready receipt confers cleanup authority. Lost receipt
# or failed create retains driver custody; pathname existence grants nothing.
run_ready create
acquired=true
run_ready verify
boot_records=$(mktemp -d)
"$driver" probe boot-id >"$boot_records/first"
"$driver" probe clear-firewall
# These are bounded defense-in-depth diagnostics only. No listener/route control
# makes either failure causal firewall evidence, so the report grants no such credit.
# A helper/SSH timeout is failure, never a successful negative diagnostic.
"$driver" probe deny-host-ssh
"$driver" probe deny-public-https
"$driver" probe no-default-route

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
    time.sleep(.1)
    if poll.poll(0): raise RuntimeError('proxy helper exited before probe')
    result=subprocess.run([sys.argv[1],'probe','proxy-connect'], timeout=45,
                          stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if result.returncode!=0: raise RuntimeError('proxy probe failed; no remote retry')
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

run_ready reset
"$driver" probe boot-id >"$boot_records/second"
python3 -I - "$boot_records" <<'PY'
import json,pathlib,re,sys
records=[]
for name in ('first','second'):
    with open(pathlib.Path(sys.argv[1])/name,'rb') as stream: raw=stream.read(129)
    value=json.loads(raw)
    if len(raw)>128 or type(value) is not dict or set(value)!={'boot-id'} \
       or raw!=(json.dumps(value,separators=(',',':'))+'\n').encode() \
       or type(value['boot-id']) is not str or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',value['boot-id']):
        raise SystemExit('FAIL: invalid boot receipt')
    records.append(value['boot-id'].encode()+b'\n')
with open('/proc/sys/kernel/random/boot_id','rb') as stream: host=stream.read(38)
if not re.fullmatch(rb'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\n',host) or len(set([host,*records]))!=3:
    raise SystemExit('FAIL: boot identities not distinct')
PY
"$driver" probe reset-read
destroy_receipt=$(mktemp)
destroy_status=0
acquired=false # consume before invocation; EXIT must never retry this destroy
"$driver" destroy >"$destroy_receipt" || destroy_status=$?
if [[ $destroy_status -eq 0 ]]; then
  exact_receipt "$destroy_receipt" destroy || destroy_status=$?
fi
rm -f "$destroy_receipt"
if [[ $destroy_status -ne 0 ]]; then
  echo 'FAIL: driver destroy uncertain; retained recovery state' >&2
  exit 1
fi
rm -f -- "$boot_records/first" "$boot_records/second"
rmdir -- "$boot_records"
boot_records=
write_report pass 'Active KVM booted a distinct root guest, used the generation-bound proxy probe, and reset preserved the workspace on a fresh boot. Non-proxy connection failures are diagnostic only and grant no firewall-enforcement evidence.'
passed=true
printf 'PASS: authoritative Linux/KVM driver smoke wrote %s\n' "$report"
