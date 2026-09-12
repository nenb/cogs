#!/usr/bin/env bash
set -euo pipefail
umask 077

# Pure policy renderer is also consumed by disposable causal mutation fixtures.
# No network or filesystem effects on this path.
network_policy() {
  local interface=$1 input=$2 forward=$3 port=$4
  cat <<EOF
*filter
:$input - [0:0]
:$forward - [0:0]
-A $input -i $interface -s 192.0.2.2 -d 192.0.2.1 -p tcp --dport $port -m comment --comment relay-allow -j ACCEPT
-A $input -d 192.0.2.1 -p tcp --dport $port -m comment --comment relay-exclusion -j DROP
-A $input -i $interface -s 192.0.2.2 -d 192.0.2.1 -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT
-A $input -m comment --comment input-deny -j DROP
-A $forward -m comment --comment forward-deny -j DROP
-I INPUT 1 -i $interface -j $input
-I INPUT 1 -d 192.0.2.1 -p tcp --dport $port -j $input
-I FORWARD 1 -i $interface -j $forward
COMMIT
EOF
}
operation=${1:-}
if [[ "$operation" == print-network-policy ]]; then
  network_policy cgfixture CGFIXI CGFIXF 18080
  exit 0
fi
script=${BASH_SOURCE[0]}
repo=${script%/dev/linux-kvm/driver.sh}
[[ "$repo" != "$script" ]] || repo=$PWD
repo=$(builtin cd "$repo" && builtin pwd -P)
# shellcheck source=dev/linux-kvm/git-tools.sh
source "$repo/dev/linux-kvm/git-tools.sh"
# The renderer above is the sole ungated path. Every other operation binds the
# root-written workflow receipt before locks, state paths or subprocesses.
cogs_kvm_execution_gate
state=${COGS_KVM_STATE_DIR:-$repo/.cogs-dev/linux-kvm}
cache=${COGS_KVM_CACHE_DIR:-$repo/.cogs-dev/cache}
image_name=debian-13-generic-amd64-20260712-2537.qcow2
image_url="https://cloud.debian.org/images/cloud/trixie/20260712-2537/$image_name"
image_sha512=78f658893d7aecb56288b86afebb72dcdb1a636e8e9db8bda64851a308697794678ceb5cd3b7c86afd5fb892afbc6baf9d2dbaceb7855347fde8660e8d68e667
host_ip=192.0.2.1
guest_ip=192.0.2.2
proxy_port=${COGS_KVM_PROXY_PORT:-18080}
lock="$repo/.cogs-dev/linux-kvm.lock"
mkdir -p "$repo/.cogs-dev"
python3 -I - "$repo/.cogs-dev" "$lock" <<'PY'
import os,stat,sys
root,lock=sys.argv[1:]; uid=os.getuid(); parent=os.lstat(root)
if not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=uid or parent.st_mode & 0o077:
    raise SystemExit('FAIL: unsafe driver lock root')
fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
try:
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
        raise SystemExit('FAIL: unsafe driver lock')
    os.fsync(fd)
finally: os.close(fd)
PY
exec 9<>"$lock"
flock -w 30 9 || { echo 'FAIL: linux-kvm driver lock timed out' >&2; exit 1; }
python3 -I - "$lock" <<'PY'
import os,stat,sys
held=os.fstat(9); named=os.lstat(sys.argv[1])
if (held.st_dev,held.st_ino)!=(named.st_dev,named.st_ino) or not stat.S_ISREG(named.st_mode) or named.st_nlink!=1 or named.st_uid!=os.getuid() or stat.S_IMODE(named.st_mode)!=0o600:
    raise SystemExit('FAIL: replaced driver lock')
PY

validate_paths() {
  python3 - "$repo/.cogs-dev" "$state" "$cache" <<'PY'
import os,sys
root,state,cache=map(os.path.abspath,sys.argv[1:])
root_real=os.path.realpath(root)
for value in (state,cache):
    if os.path.dirname(value) != root or os.path.realpath(os.path.dirname(value)) != root_real:
        raise SystemExit("state/cache must be one direct child of .cogs-dev")
    if os.path.lexists(value) and os.path.islink(value):
        raise SystemExit("state/cache must not be symlinks")
PY
}
validate_paths

# This owner is the sole authority for driver-local files. Its durable intent
# precedes each state effect; exact inode inventory is refreshed only while the
# repository lock is held. Mismatch is sticky and never authorizes adoption.
generation_owner() {
  python3 -I - "$repo/.cogs-dev" "$state" "$1" "$generation" "${2:-}" "$source_revision" linux-kvm "$state" <<'PY'
import json,os,pathlib,re,stat,sys
parent=pathlib.Path(sys.argv[1]); state=pathlib.Path(sys.argv[2])
action,generation,key,revision,profile,locator=sys.argv[3:9]
uid=os.getuid(); authority='.generation.owner'; sentinel='.cogs-linux-kvm-v1'
root_info=parent.lstat()
if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=uid or root_info.st_mode & 0o077:
    raise SystemExit('FAIL: unsafe driver lock root')
class Rejected(RuntimeError): pass
def canonical(value): return (json.dumps(value,separators=(',',':'))+'\n').encode()
def write_fd(fd,data):
    view=memoryview(data)
    while view:
        count=os.write(fd,view)
        if count<=0: raise RuntimeError('short custody write')
        view=view[count:]
    os.fsync(fd)
def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
def strict_file(path,mode=0o600):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=mode or info.st_nlink!=1:
        raise RuntimeError(f'unsafe custody file: {path.name}')
    return info
def read_file(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
            raise RuntimeError(f'unsafe custody file: {path.name}')
        parts=[]; remaining=limit+1
        while remaining:
            chunk=os.read(fd,remaining)
            if not chunk: break
            parts.append(chunk); remaining-=len(chunk)
        value=b''.join(parts)
        if len(value)>limit: raise RuntimeError('oversized custody file')
        return value
    finally: os.close(fd)
def read_json(path):
    def pairs(items):
        value={}
        for name,item in items:
            if name in value: raise RuntimeError('duplicate custody key')
            value[name]=item
        return value
    raw=read_file(path,262144)
    if not raw.endswith(b'\n') or raw.count(b'\n')!=1: raise RuntimeError('invalid custody encoding')
    return json.loads(raw,object_pairs_hook=pairs)
def open_state():
    fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    info=os.fstat(fd)
    if info.st_uid!=uid or stat.S_IMODE(info.st_mode)!=0o700: os.close(fd); raise RuntimeError('unsafe state directory')
    return fd,info
def scan():
    values=[]
    for base,dirs,files in os.walk(state,topdown=True,followlinks=False):
        dirs.sort(); files.sort()
        for name in dirs+files:
            path=pathlib.Path(base)/name; rel=str(path.relative_to(state))
            if rel in (authority,sentinel): continue
            info=path.lstat()
            kind='d' if stat.S_ISDIR(info.st_mode) else 'f' if stat.S_ISREG(info.st_mode) else 's' if stat.S_ISSOCK(info.st_mode) else None
            if kind is None or (kind!='d' and info.st_nlink!=1) or info.st_uid!=uid:
                raise RuntimeError('unsafe state inventory')
            values.append({'path':rel,'kind':kind,'dev':info.st_dev,'ino':info.st_ino,
                           'mode':stat.S_IMODE(info.st_mode),'nlink':info.st_nlink})
    return values
def save(value):
    temporary=state/(authority+'.pending')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try: write_fd(fd,canonical(value))
    finally: os.close(fd)
    os.replace(temporary,state/authority); fsync_dir(state)
def validate():
    fd,info=open_state()
    try:
        token=read_file(state/sentinel,33)
        if token!=generation.encode()+b'\n' or not re.fullmatch('[a-f0-9]{32}',generation):
            raise RuntimeError('driver generation mismatch')
        value=read_json(state/authority)
        if set(value)!={'version','generation','profile','sourceRevision','locator','directory','pending','guest','failed','uncertain','keys','inventory'} \
           or value['version']!='cogs.linux-kvm-owner/v1' or value['generation']!=generation \
           or value['profile']!=profile or value['sourceRevision']!=revision or value['locator']!=locator \
           or value['directory']!=[info.st_dev,info.st_ino] or type(value['keys']) is not list \
           or type(value['inventory']) is not list or type(value['failed']) is not bool \
           or type(value['uncertain']) is not bool or (value['pending'] is not None and type(value['pending']) is not str) \
           or (value['guest'] is not None and type(value['guest']) is not str):
            raise RuntimeError('invalid generation authority')
        return value
    finally: os.close(fd)
def same_inventory(expected): return scan()==expected
def finish(value,key,success):
    # Only these names can be acquired or replaced by each published intent.
    final={
      'cache':{},
      'keys':{'control':('d',0o700),'control/client_ed25519_key':('f',0o600),
              'control/client_ed25519_key.pub':('f',0o600),'control/host_ed25519_key':('f',0o600),
              'control/host_ed25519_key.pub':('f',0o600),'known_hosts':('f',0o600)},
      'disks':{'root-overlay.qcow2':('f',0o600),'workspace.img':('f',0o600),'git-tools.img':('f',0o400)},
      'seed':{'user-data':('f',0o400),'meta-data':('f',0o400),'network-config':('f',0o400),'seed.img':('f',0o400)},
      'runtime':{'qemu.owner':('f',0o600),'network.owner':('f',0o600),'network.policy':('f',0o600),
                 'qmp.sock':('s',0o700),'qemu.stdout':('f',0o600),'qemu.stderr':('f',0o600),'qemu.pid':('f',0o600)},
      'reset':{'qemu.owner':('f',0o600),'network.owner':('f',0o600),'root-overlay.qcow2':('f',0o600),
               'seed.img':('f',0o400),'user-data':('f',0o400),'meta-data':('f',0o400),
               'network-config':('f',0o400),'qmp.sock':('s',0o700)},
      'retirement':{'qemu.owner':('f',0o600),'network.owner':('f',0o600),'qmp.sock':None},
    }
    if key not in final: raise RuntimeError('unknown acquisition inventory')
    before={item['path']:item for item in value['inventory']}; observed=scan(); after={item['path']:item for item in observed}
    allowed=set(final[key])
    for path in set(before)|set(after):
        if path not in allowed and before.get(path)!=after.get(path):
            raise RuntimeError('unapproved state inventory change')
    for path,required in final[key].items():
        item=after.get(path)
        if required is None:
            if item is not None and item!=before.get(path): raise RuntimeError('invalid stage output')
        elif item is not None and item['kind']!=required[0]:
            raise RuntimeError('invalid stage output')
    if success:
        for path,required in final[key].items():
            item=after.get(path)
            if required is None:
                if item is not None: raise RuntimeError('retired output remained')
            elif item is None or (item['kind'],item['mode'])!=required:
                raise RuntimeError('required stage output missing')
    value['inventory']=observed
    value['pending']=None
    if key not in value['keys']: value['keys'].append(key)
def remove_exact(value):
    if value['pending']!='removal' or value['uncertain'] or not same_inventory(value['inventory']):
        raise RuntimeError('state inventory changed')
    entries=sorted(value['inventory'],key=lambda item:(item['path'].count('/'),item['kind']=='d'),reverse=True)
    for expected in entries:
        path=state/expected['path']; info=path.lstat()
        observed={'path':expected['path'],'kind':'d' if stat.S_ISDIR(info.st_mode) else 'f' if stat.S_ISREG(info.st_mode) else 's' if stat.S_ISSOCK(info.st_mode) else None,
                  'dev':info.st_dev,'ino':info.st_ino,'mode':stat.S_IMODE(info.st_mode),'nlink':info.st_nlink}
        if observed!=expected: raise RuntimeError('state identity changed during removal')
        path.rmdir() if expected['kind']=='d' else path.unlink()
    strict_file(state/authority)
    if read_file(state/sentinel,33)!=generation.encode()+b'\n': raise RuntimeError('sentinel changed during removal')
    (state/sentinel).unlink(); (state/authority).unlink(); fsync_dir(state)
    fd,info=open_state(); os.close(fd)
    if [info.st_dev,info.st_ino]!=value['directory']: raise RuntimeError('state directory changed during removal')
    state.rmdir(); fsync_dir(parent)
if not re.fullmatch('[a-f0-9]{32}',generation): raise SystemExit('FAIL: invalid generation')
if not re.fullmatch('[a-f0-9]{40}',revision) or profile!='linux-kvm' or locator!=str(state.absolute()):
    raise SystemExit('FAIL: invalid generation binding')
if action=='init':
    if state.exists() or state.is_symlink(): raise SystemExit('FAIL: linux-kvm state already exists')
    os.mkdir(state,0o700); fd,info=open_state(); os.close(fd)
    try:
        fd=os.open(state/sentinel,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try: write_fd(fd,generation.encode()+b'\n')
        finally: os.close(fd)
        value={'version':'cogs.linux-kvm-owner/v1','generation':generation,'profile':profile,
               'sourceRevision':revision,'locator':locator,'directory':[info.st_dev,info.st_ino],
               'pending':None,'guest':None,'failed':False,'uncertain':False,'keys':[],'inventory':[]}
        save(value); fsync_dir(parent) # immutable generation authority precedes subordinate effects
        value['pending']='bootstrap'; save(value)
        for name,item in (('qemu.owner',{'phase':'never'}),('network.owner',{'phase':'never','steps':[]})):
            fd=os.open(state/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try: write_fd(fd,canonical(item))
            finally: os.close(fd)
        observed=scan()
        if {(item['path'],item['kind'],item['mode']) for item in observed} != \
           {('qemu.owner','f',0o600),('network.owner','f',0o600)}:
            raise RuntimeError('unexpected bootstrap inventory')
        value['inventory']=observed; value['pending']=None; value['keys'].append('bootstrap'); save(value)
    except BaseException:
        # Creation without a complete authority is not cleanup authority.
        raise
    raise SystemExit(0)
value=None
try:
    value=validate()
    if value['uncertain']: raise RuntimeError('sticky driver custody uncertainty')
    if value['guest'] is not None and action not in ('guest-done','guest-fail'):
        # A killed helper/driver cannot turn lost remote completion into reuse.
        raise RuntimeError('unfinished guest command; recovery custody retained')
    if action=='guest-start':
        if value['failed'] or not key: raise Rejected('failed generation is cleanup-only')
        value['guest']=key; save(value)
    elif action in ('guest-done','guest-fail'):
        if value['guest']!=key: raise RuntimeError('guest command intent mismatch')
        value['guest']=None
        if action=='guest-fail': value['failed']=True
        save(value)
    elif action=='check':
        if value['failed'] and key!='destroy': raise Rejected('failed generation is cleanup-only')
        if value['pending'] is not None or not same_inventory(value['inventory']): raise RuntimeError('state inventory changed')
    elif action=='intent':
        if value['pending'] is not None or not same_inventory(value['inventory']): raise RuntimeError('state inventory changed')
        if value['failed'] and key not in ('retirement','removal'): raise Rejected('failed generation is cleanup-only')
        if not key or (key in value['keys'] and key not in ('reset','retirement')): raise Rejected('duplicate acquisition key')
        value['pending']=key; save(value)
    elif action in ('commit','fail'):
        if value['pending']!=key: raise RuntimeError('acquisition intent mismatch')
        finish(value,key,action=='commit')
        if action=='fail': value['failed']=True
        save(value)
    elif action=='remove': remove_exact(value)
    else: raise Rejected('invalid generation-owner action')
except Rejected:
    raise
except BaseException:
    # If the authority itself is still trusted, uncertainty survives retries.
    if value is not None:
        value['uncertain']=True
        try: save(value)
        except BaseException: pass
    raise
PY
}

# A caller nonce is mandatory and checked under the driver lock before effects.
generation=${COGS_KVM_GENERATION:-}
source_revision=${COGS_SOURCE_REVISION:-}
if [[ "$operation" != prepare-cache && "$operation" != print-network-policy ]]; then
  [[ "$generation" =~ ^[a-f0-9]{32}$ && "$source_revision" =~ ^[a-f0-9]{40}$ ]] \
    || { echo 'FAIL: invalid generation binding' >&2; exit 1; }
  if [[ "$operation" != create ]]; then
    generation_owner check "$operation" || { echo 'FAIL: no matching retained driver custody' >&2; exit 1; }
  fi
fi
select_network_names() {
  tap="cgk${generation:0:12}"
  input_chain="CGKI${generation:0:16}"
  drop_chain="CGKD${generation:0:16}"
}
select_network_names

bounded_guest() {
  local command=$1
  [[ $# -eq 1 ]] || return 1
  generation_owner guest-start "$command" || return 1
  if python3 -I "$repo/dev/linux-kvm/bounded-command.py" "$command" "$state" "$generation" "$proxy_port"; then
    generation_owner guest-done "$command" || return 1
  else
    local status=$?
    # Only the helper's settled failure permits VM cleanup. Local uncertainty,
    # a signal, or a lost helper response retains pending custody for recovery.
    if [[ $status -eq 1 ]]; then generation_owner guest-fail "$command" || true; fi
    return 1
  fi
}

# State is trusted, private, host-owned custody, not a guest-writable PID hint.
# No PID-number signal fallback: unsupported pidfds or lost identity stop cleanup.
qemu_owner() {
  python3 - "$state" "$1" <<'PY'
import json,os,pathlib,select,shutil,signal,sys,time
state=pathlib.Path(sys.argv[1]); action=sys.argv[2]; record=state/'qemu.owner'
def save(value):
    temporary=record.with_suffix('.pending')
    temporary.write_text(json.dumps(value)); temporary.replace(record)
def identity(pid):
    proc=pathlib.Path('/proc')/str(pid)
    fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
    exe=(proc/'exe').stat()
    return [pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            fields[19], os.readlink(proc/'exe'), exe.st_dev, exe.st_ino,
            (proc/'cmdline').read_bytes().hex()]
def owned(value):
    pid=value['pid']
    if type(pid) is not int or pid <= 1: raise RuntimeError('invalid QEMU PID')
    fd=os.pidfd_open(pid,0)
    try:
        if identity(pid) != value['identity']: raise RuntimeError('QEMU generation changed')
        return fd
    except BaseException:
        os.close(fd); raise

def run():
    value=json.loads(record.read_text())
    if value.get('failed'): raise RuntimeError('sticky QEMU custody uncertainty')
    if action == 'preflight':
        if not callable(getattr(signal,'pidfd_send_signal',None)): raise RuntimeError('pidfd signals unavailable')
        fd=os.pidfd_open(os.getpid(),0); os.close(fd)
        return
    if action == 'capture':
        if value != {'phase':'launching'}: raise RuntimeError('unexpected launch phase')
        pid=int((state/'qemu.pid').read_text())
        if pid <= 1: raise RuntimeError('invalid QEMU PID')
        expected=os.path.realpath(shutil.which('qemu-system-x86_64'))
        for _ in range(100):
            observed=identity(pid)
            if observed[2] == expected: break
            time.sleep(.02)
        argv=bytes.fromhex(observed[5]).split(b'\0')
        if observed[2] != expected or os.fsencode(f'unix:{state}/qmp.sock,server=on,wait=off') not in argv:
            raise RuntimeError('not the launched QEMU')
        value={'phase':'live','pid':pid,'identity':observed}
    elif value.get('phase') in ('never','retired') and action == 'stop':
        return
    elif value.get('phase') != 'live':
        raise RuntimeError('QEMU launch custody incomplete')
    fd=owned(value)
    try:
        poll=select.poll(); poll.register(fd,select.POLLIN)
        if action in ('check','capture'):
            if poll.poll(0): raise RuntimeError('QEMU exited')
            if action == 'capture': save(value)
            return
        if action != 'stop': raise RuntimeError('invalid QEMU owner action')
        for sig,timeout in ((signal.SIGTERM,10000),(signal.SIGKILL,5000)):
            if poll.poll(0): break
            # Revalidate immediately before each signal, but signal the held pidfd:
            # an exit/reuse after this check cannot target the replacement PID.
            if identity(value['pid']) != value['identity']: raise RuntimeError('QEMU identity changed')
            signal.pidfd_send_signal(fd,sig,None,0)
            if poll.poll(timeout): break
        else: raise RuntimeError('QEMU retirement deadline exceeded')
        save({'phase':'retired'})
    finally:
        os.close(fd)
try:
    run()
except BaseException:
    # Lost observation never becomes success on retry or on missing /proc state.
    value=json.loads(record.read_text()); value['failed']=True; save(value)
    raise
PY
}

# An inverse is authorized only by a successful recorded effect and unchanged
# snapshots. Pending/failed effects retain custody; absence alone is not proof.
network_owner() {
  sudo python3 -I - "$state" "$1" "$tap" "$input_chain" "$drop_chain" "$proxy_port" "$(id -u)" <<'PY'
import fcntl,json,os,pathlib,re,stat,subprocess,sys
state=pathlib.Path(sys.argv[1]); action,tap,chain,forward,port,owner_uid=sys.argv[2:]
record=state/'network.owner'
def domain_lock():
    # Provisioned externally by trusted root, never created/adopted by this driver.
    # Every administrator admitted to this isolated netns must use this same lock.
    global domain_identity
    ns=os.stat('/proc/self/ns/net'); initial=os.stat('/proc/1/ns/net')
    domain_identity=[ns.st_dev,ns.st_ino,pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()]
    if (ns.st_dev,ns.st_ino)==(initial.st_dev,initial.st_ino):
        raise RuntimeError('isolated network domain required (host PID namespace required)')
    parent=pathlib.Path('/run/cogs-kvm-network-domain')
    for path in (pathlib.Path('/run'),parent):
        info=path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise RuntimeError('untrusted network-domain parent')
    fd=os.open(parent/f'{ns.st_dev}-{ns.st_ino}',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode & 0o222:
            raise RuntimeError('untrusted network-domain lease')
        expected='cogs-exclusive-netns-v1 '+pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()+'\n'
        if os.read(fd,256).decode()!=expected: raise RuntimeError('network-domain admission missing')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        domain_identity.extend([info.st_dev,info.st_ino,info.st_ctime_ns])
        return fd
    except BaseException:
        os.close(fd); raise

def command(args,expected=None):
    # Revalidation belongs inside the effect adapter, after intent publication.
    # The domain lock, not this extra observation, excludes admitted writers.
    if expected is not None and snapshot()!=expected: raise RuntimeError('network changed at effect boundary')
    if args[:4]==['ip','link','delete','dev']:
        # RTM_DELLINK resolves the recorded ifindex, never a replaced TAP name.
        index=expected[1][0]['ifindex']
        program="""import socket,struct,sys
index=int(sys.argv[1])
with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as sock:
 sock.settimeout(20); sock.bind((0,0))
 payload=struct.pack('=BBHiII',socket.AF_UNSPEC,0,0,index,0,0)
 sock.sendto(struct.pack('=IHHII',32,17,5,1,0)+payload,(0,0))
 reply,sender=sock.recvfrom(65536)
 if sender[0]!=0 or len(reply)<20 or struct.unpack_from('=H',reply,4)[0]!=2 or struct.unpack_from('=I',reply,8)[0]!=1 or struct.unpack_from('=i',reply,16)[0]!=0:
  raise RuntimeError('ifindex deletion not acknowledged')
"""
        args=['python3','-I','-c',program,str(index)]
    # Run the fixed tools directly, not behind another sudo process. The actual
    # command inherits the flock: observer death cannot release a live effect's
    # domain exclusion. A timeout terminates/reaps this direct command, and the
    # pending journal remains sticky; every remaining descriptor holder excludes
    # new writers. This fixed-tool contract does not admit daemonizing writers.
    return subprocess.check_output(args,text=True,timeout=25,pass_fds=(domain_fd,))
def snapshot():
    rules=[re.sub(r'\[\d+:\d+\]','[0:0]', '\n'.join(
        line for line in command([tool,'-t','filter']).splitlines() if not line.startswith('#')))
        for tool in ('iptables-save','ip6tables-save')]
    if any(not ruleset.startswith('*filter\n') or not ruleset.endswith('\nCOMMIT')
           or any(':'+name+' ' not in ruleset for name in ('INPUT','FORWARD','OUTPUT')) for ruleset in rules):
        raise RuntimeError('incomplete filter-table observation')
    links=json.loads(command(['ip','-j','-d','link','show']))
    # Carrier, queue counts and TUN offload/header flags can change when QEMU
    # opens/closes the TAP. Bind ifindex/alias/kind/uid/gid, not those live fields.
    link=[{k:item.get(k) for k in ('ifindex','ifname','ifalias','link_type')}
          | {'up':'UP' in item['flags'], 'kind':item.get('linkinfo',{}).get('info_kind')}
          | {k:item.get('linkinfo',{}).get('info_data',{}).get(k) for k in ('owner','group')}
          for item in links if item['ifname']==tap]
    addresses=json.loads(command(['ip','-j','addr','show']))
    # Only configured IPv4 addresses; kernel IPv6 link-local/DAD is volatile.
    addr=[[a for a in item['addr_info'] if a['family']=='inet']
          for item in addresses if item['ifname']==tap]
    return [rules,link,addr]
def save(value):
    temporary=record.with_suffix('.pending')
    temporary.write_text(json.dumps(value))
    custody=state.stat(); os.chown(temporary,custody.st_uid,custody.st_gid)
    temporary.replace(record)
def effect(value,do,undo):
    before=snapshot()
    if before != value['current']: raise RuntimeError('network changed before effect')
    value['pending']=True; save(value) # acquisition intent precedes every effect
    command(do,before)
    after=snapshot()
    if after == before: raise RuntimeError('network effect not observed')
    value['steps'].append([undo,before,after]); value['current']=after
    value['pending']=False; save(value)
def run():
    value=json.loads(record.read_text())
    if value.get('failed') or value.get('pending'): raise RuntimeError('sticky network uncertainty')
    if action == 'remove':
        if value['phase'] == 'never': return
        if value.get('domain')!=domain_identity: raise RuntimeError('network domain changed')
        while value['steps']:
            undo,before,after=value['steps'][-1]
            if snapshot()!=after: raise RuntimeError('network ownership changed')
            value['pending']=True; save(value)
            command(undo,after)
            if snapshot()!=before: raise RuntimeError('network inverse not proven')
            value['steps'].pop(); value['current']=before; value['pending']=False; save(value)
        return
    if action != 'prepare' or value['phase'] != 'never': raise RuntimeError('network already acquired')
    if not port.isdecimal() or not 1 <= int(port) <= 65535: raise RuntimeError('invalid proxy port')
    before=snapshot()
    if before[1] or any(chain in rules or forward in rules or tap in rules for rules in before[0]):
        raise RuntimeError('network name collision')
    value={'phase':'owned','steps':[],'current':before,'domain':domain_identity}; save(value)
    effect(value,['ip','tuntap','add','dev',tap,'mode','tap','user',owner_uid],
           ['ip','link','delete','dev',tap])
    # Tag before any guest can open the link. A crash between creation/tagging
    # retains pending custody rather than guessing which interface to remove.
    import uuid
    effect(value,['ip','link','set','dev',tap,'alias','cogs-'+uuid.uuid4().hex],
           ['ip','link','set','dev',tap,'alias',''])
    effect(value,['ip','addr','add','192.0.2.1/30','dev',tap],
           ['ip','addr','del','192.0.2.1/30','dev',tap])
    # IPv6 is denied before bringing up the link (and thus before autoconfig).
    for builtin in ('INPUT','FORWARD'):
        rule=[builtin,'-i',tap,'-j','DROP']
        effect(value,['ip6tables','-w','5','-I',builtin,'1',*rule[1:]],
               ['ip6tables','-w','5','-D',*rule])
    # Exact rules, including their multiplicity and original port, are retained.
    policy=(state/'network.policy').read_text().splitlines()
    for line in policy:
        if line.startswith(':'):
            name=line.split()[0][1:]; do=['-N',name]; undo=['-X',name]
        elif line.startswith(('-A ','-I ')):
            do=line.split(); undo=['-D',*do[1:]]
            if do[0]=='-I': undo.pop(2) # insertion index is not part of rule identity
        else: continue
        effect(value,['iptables','-w','5',*do],['iptables','-w','5',*undo])
    effect(value,['ip','link','set','dev',tap,'up'],['ip','link','set','dev',tap,'down'])
try:
    domain_fd=domain_lock()
    try: run()
    finally: os.close(domain_fd)
except BaseException:
    value=json.loads(record.read_text()); value['failed']=True; save(value)
    raise
PY
}
remove_network() { network_owner remove; }
stop_vm() { qemu_owner stop; }
cleanup_partial() {
  stop_vm && remove_network
}
owner_stage_key=
owner_stage() {
  generation_owner intent "$1"
  owner_stage_key=$1
}
owner_stage_commit() {
  generation_owner commit "$owner_stage_key"
  owner_stage_key=
}
owner_stage_error() {
  local status=$?
  trap - ERR
  # Command substitutions propagate failure; only the locked top-level owner
  # may settle acquisitions, never an inherited subshell copy of its ledger.
  if (( BASH_SUBSHELL > 0 )); then exit "$status"; fi
  if [[ -n "$owner_stage_key" ]]; then generation_owner fail "$owner_stage_key" || true; fi
  if [[ "$operation" == create ]]; then
    rollback_create || echo 'FAIL: partial KVM custody retained for recovery' >&2
  fi
  exit "$status"
}
arm_owner_errors() {
  set -E
  trap owner_stage_error ERR
}
disarm_owner_errors() {
  trap - ERR
  owner_stage_key=
}
rollback_create() {
  generation_owner intent retirement || return 1
  if cleanup_partial; then
    generation_owner commit retirement || return 1
    generation_owner intent removal || return 1
    generation_owner remove
  else
    generation_owner fail retirement || true
    return 1
  fi
}

prepare_image() {
  mkdir -p "$cache"
  chmod 0700 "$cache"
  if [[ ! -f "$cache/$image_name" ]]; then
    tmp="$cache/$image_name.partial"
    [[ ! -e "$tmp" && ! -L "$tmp" ]] || { echo 'FAIL: foreign image partial retained' >&2; return 1; }
    (set -o noclobber; : > "$tmp")
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "$tmp" "$image_url"
    printf '%s  %s\n' "$image_sha512" "$tmp" | sha512sum --check --status
    mv "$tmp" "$cache/$image_name"
    chmod 0400 "$cache/$image_name"
  fi
  printf '%s  %s\n' "$image_sha512" "$cache/$image_name" | sha512sum --check --status
}

prepare_keys() {
  mkdir -p "$state/control"
  ssh-keygen -q -t ed25519 -N '' -C cogs-kvm-client -f "$state/control/client_ed25519_key"
  ssh-keygen -q -t ed25519 -N '' -C cogs-kvm-host -f "$state/control/host_ed25519_key"
  chmod 0600 "$state/control/"*_ed25519_key
  local host_key_type host_key_data ignored
  read -r host_key_type host_key_data ignored < "$state/control/host_ed25519_key.pub"
  [[ "$host_key_type" == ssh-ed25519 && "$host_key_data" =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || {
    echo 'FAIL: generated KVM host public key is invalid' >&2; return 1;
  }
  printf '%s %s %s\n' "$guest_ip" "$host_key_type" "$host_key_data" > "$state/known_hosts"
}

prepare_seed() {
  client_pub=$(<"$state/control/client_ed25519_key.pub")
  host_private=$(base64 -w0 < "$state/control/host_ed25519_key")
  host_public=$(base64 -w0 < "$state/control/host_ed25519_key.pub")
  cat > "$state/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
ssh_deletekeys: false
ssh_genkeytypes: []
users:
  - name: root
    lock_passwd: true
    shell: /bin/bash
    ssh_authorized_keys:
      - $client_pub
write_files:
  - path: /etc/ssh/cogs_host_ed25519_key
    owner: root:root
    permissions: '0600'
    encoding: b64
    content: $host_private
  - path: /etc/ssh/cogs_host_ed25519_key.pub
    owner: root:root
    permissions: '0644'
    encoding: b64
    content: $host_public
  - path: /etc/ssh/sshd_config.d/10-cogs.conf
    owner: root:root
    permissions: '0644'
    content: |
      HostKey /etc/ssh/cogs_host_ed25519_key
      PermitRootLogin prohibit-password
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      AllowAgentForwarding no
      AllowTcpForwarding no
      X11Forwarding no
      PermitTunnel no
mounts:
  - [LABEL=COGS_WORKSPACE, /workspace, auto, 'defaults,nosuid,nodev', '0', '2']
  - [LABEL=COGS_GITTOOLS, /opt/cogs-git, auto, 'ro,nosuid,nodev', '0', '2']
runcmd:
  - [bash, -lc, 'mountpoint -q /opt/cogs-git && findmnt -rn -o OPTIONS /opt/cogs-git | grep -Eq "(^|,)ro(,|$)" && findmnt -rn -o OPTIONS /opt/cogs-git | grep -Eq "(^|,)nosuid(,|$)" && findmnt -rn -o OPTIONS /opt/cogs-git | grep -Eq "(^|,)nodev(,|$)"']
  - [bash, -lc, 'test ! -e /usr/bin/git && test ! -L /usr/bin/git && ln -s /opt/cogs-git/bin/git /usr/bin/git']
  - [chown, -h, root:root, /usr/bin/git]
  - [bash, -lc, 'test -L /usr/bin/git && test "$(readlink /usr/bin/git)" = /opt/cogs-git/bin/git && test "$(stat -c "%u:%g:%F" /usr/bin/git)" = "0:0:symbolic link"']
  - [mkdir, -p, /shared/skills, /user/skills]
  - [chown, root:root, /shared/skills, /user/skills]
  - [chmod, '0700', /shared/skills, /user/skills]
  - [bash, -lc, 'for skill_root in /shared/skills /user/skills; do test -d "\$skill_root" && test ! -L "\$skill_root" && test "\$(realpath -e "\$skill_root")" = "\$skill_root" && test "\$(stat -c "%u:%g:%a:%F" "\$skill_root")" = "0:0:700:directory"; done']
  - [systemctl, restart, ssh]
EOF
  cat > "$state/meta-data" <<EOF
instance-id: cogs-kvm-$(sha256sum "$state/control/host_ed25519_key.pub" | cut -c1-16)
local-hostname: cogs-kvm-guest
EOF
  cat > "$state/network-config" <<EOF
version: 2
ethernets:
  id0:
    match:
      macaddress: '52:54:00:c0:65:01'
    set-name: eth0
    dhcp4: false
    dhcp6: false
    accept-ra: false
    addresses: [$guest_ip/30]
EOF
  cloud-localds --network-config="$state/network-config" "$state/seed.img" "$state/user-data" "$state/meta-data"
  chmod 0400 "$state/seed.img" "$state/user-data" "$state/meta-data" "$state/network-config"
}

prepare_disks() {
  qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image_name" "$state/root-overlay.qcow2" 12G
  qemu-img create -q -f raw "$state/workspace.img" 1G
  mkfs.ext4 -q -L COGS_WORKSPACE "$state/workspace.img"
  prepare_git_tools_disk "$state" "$cache"
  chmod 0600 "$state/root-overlay.qcow2" "$state/workspace.img"
  chmod 0400 "$state/git-tools.img"
}

prepare_network() {
  network_policy "$tap" "$input_chain" "$drop_chain" "$proxy_port" > "$state/network.policy"
  network_owner prepare
}

start_vm() {
  qemu_owner preflight
  prepare_network
  rm -f "$state/qmp.sock"
  printf '{"phase":"launching"}\n' > "$state/qemu.owner"
  nohup qemu-system-x86_64 \
    -name cogs-stage1-linux-kvm -machine q35 -accel kvm -cpu host -smp 2 -m 2048M \
    -drive if=virtio,format=qcow2,file="$state/root-overlay.qcow2" \
    -drive if=virtio,format=raw,readonly=on,file="$state/seed.img" \
    -drive if=virtio,format=raw,readonly=on,file="$state/git-tools.img" \
    -drive if=virtio,format=raw,file="$state/workspace.img" \
    -netdev tap,id=cogsnet,ifname="$tap",script=no,downscript=no \
    -device virtio-net-pci,netdev=cogsnet,mac=52:54:00:c0:65:01 \
    -display none -serial null -monitor none \
    -qmp unix:"$state/qmp.sock",server=on,wait=off -no-reboot \
    >"$state/qemu.stdout" 2>"$state/qemu.stderr" 9>&- &
  echo $! > "$state/qemu.pid"
  qemu_owner capture
  bounded_guest readiness || return 1
  qemu_owner check
}

query_kvm() {
  bounded_guest qmp
}

verify_git_tools() {
  local pid
  pid=$(<"$state/qemu.pid")
  tr '\0' ' ' < "/proc/$pid/cmdline" | grep -F -- "readonly=on,file=$state/git-tools.img" >/dev/null || {
    echo 'FAIL: Git tools disk is not attached read-only' >&2; return 1;
  }
  bounded_guest git-tools
}

verify_checks() {
  generation_owner check
  qemu_owner check
  query_kvm >/dev/null
  bounded_guest root
  bounded_guest workspace
  verify_git_tools
  bounded_guest no-default-route
  bounded_guest mac
  bounded_guest skills
  bounded_guest host-key
}
emit_ready() {
  bounded_guest "receipt-$1"
}
release_lock() {
  flock -u 9 || { echo 'FAIL: linux-kvm driver lock release failed' >&2; return 1; }
}

case "$operation" in
  prepare-cache)
    prepare_image >&2
    cogs_git_tools_prepare_cache "$cache" >&2
    release_lock
    printf '{"status":"prepared","profile":"linux-kvm"}\n'
    ;;
  create)
    generation_owner init
    select_network_names
    arm_owner_errors
    owner_stage cache
    prepare_image >&2
    owner_stage_commit
    owner_stage keys
    prepare_keys >&2
    owner_stage_commit
    owner_stage disks
    prepare_disks >&2
    owner_stage_commit
    owner_stage seed
    prepare_seed >&2
    owner_stage_commit
    owner_stage runtime
    start_vm >&2
    owner_stage_commit
    verify_checks >&2
    emit_ready create
    disarm_owner_errors
    release_lock
    ;;
  verify)
    verify_checks >&2
    emit_ready verify
    release_lock
    ;;
  reset)
    arm_owner_errors
    owner_stage reset
    qemu_owner check >&2
    bounded_guest reset-write >&2
    stop_vm >&2
    remove_network >&2
    printf '{"phase":"never","steps":[]}\n' > "$state/network.owner"
    rm -f "$state/root-overlay.qcow2" "$state/seed.img" "$state/user-data" "$state/meta-data" "$state/network-config"
    qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image_name" "$state/root-overlay.qcow2" 12G
    cogs_git_tools_verify_image_file "$state/git-tools.img" 2>/dev/null || prepare_git_tools_disk "$state" "$cache"
    cogs_git_tools_verify_image_file "$state/git-tools.img"
    prepare_seed
    start_vm
    bounded_guest reset-read
    owner_stage_commit
    verify_checks >&2
    emit_ready reset
    disarm_owner_errors
    release_lock
    ;;
  destroy)
    generation_owner intent retirement
    if cleanup_partial >&2; then generation_owner commit retirement; else generation_owner fail retirement || true; exit 1; fi
    generation_owner intent removal
    generation_owner remove
    release_lock
    python3 -I - "$generation" <<'PY'
import json,sys
print(json.dumps({'profile':'linux-kvm','status':'destroyed','generation':sys.argv[1],'command':'destroy'},separators=(',',':')))
PY
    ;;
  probe)
    [[ $# -eq 2 ]] || exit 2
    case "$2" in
      boot-id|clear-firewall|deny-host-ssh|deny-public-https|no-default-route|proxy-connect|reset-read)
        bounded_guest "$2" ;;
      *) echo 'FAIL: unallocated guest command' >&2; exit 2 ;;
    esac
    release_lock
    ;;
  *) echo 'usage: driver.sh {prepare-cache|create|verify|reset|destroy|probe fixed-id}' >&2; exit 2 ;;
esac
