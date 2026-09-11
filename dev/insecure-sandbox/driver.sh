#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Retirement requires root-held private custody. Reject before even resolving
# acquisition inputs or invoking tools; keep the independent final guard below.
if (( EUID != 0 )); then
  printf 'insecure-container requires root-held private custody\n' >&2
  exit 1
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
state=${COGS_INSECURE_STATE_DIR:-"$repo/.cogs-dev/insecure-sandbox"}
image=${COGS_INSECURE_IMAGE:-cogs-insecure-sandbox:dev}
profile=insecure-container
operation=${1:-}
generation=${COGS_INSECURE_GENERATION:-}
original_revision=${COGS_INSECURE_ORIGINAL_REVISION:-$(git -C "$repo" rev-parse HEAD 2>/dev/null || true)}
state_root="$repo/.cogs-dev"
state_name=${state#"$state_root/"}
state_id=$(printf '%s' "$state" | openssl dgst -sha256 2>/dev/null | awk '{print substr($NF,1,12)}')
container_name="cogs-insecure-$generation"
volume_name=''
lock="${state}.lock"
sentinel="$state/.cogs-insecure-owner"
authority="$state/authority"
intents="$state/intents"
inventory="$state/inventory"
locator="$state"
http_proxy=${COGS_HTTP_PROXY:-http://proxy.invalid:3128}
https_proxy=${COGS_HTTPS_PROXY:-$http_proxy}
lock_held=false
lock_owner=""
create_active=false
volume_acquired=false
container_acquired=false
container_id=''
container_pending=false
custody_bound=false
custody_identity=''
lock_identity=''

emit() {
  printf '{"version":"cogs.dev-driver/v1alpha1","profile":"%s","authority":"functional-only","command":"%s","result":"%s","generation":"%s"}\n' \
    "$profile" "$operation" "$1" "$generation"
}

fail() {
  printf '%s\n' "$1" >&2
  return 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is missing: $1"
}
durable_file() {
  COGS_DURABLE_CONTENT=$3 python3 -I - "$1" "$2" <<'PY'
import os, stat, sys
mode, path = sys.argv[1:]
data = os.environ["COGS_DURABLE_CONTENT"].encode()
parent, name = os.path.split(path)
dfd = os.open(parent, os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW)
flags = os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW
if mode == "new": flags |= os.O_CREAT | os.O_EXCL
else: flags |= os.O_APPEND
fd = os.open(name, flags, 0o600, dir_fd=dfd)
s = os.fstat(fd)
if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
    os.close(fd); raise SystemExit("unsafe durable journal")
with os.fdopen(fd, "wb") as f:
    f.write(data)
    f.flush()
    os.fsync(f.fileno())
os.fsync(dfd)
os.close(dfd)
pfd = os.open(os.path.dirname(parent), os.O_RDONLY | os.O_NONBLOCK | os.O_DIRECTORY | os.O_NOFOLLOW)
os.fsync(pfd); os.close(pfd)
PY
}
persist_new() { durable_file new "$1" "$2"; }
append_durable() { durable_file append "$1" "$2"; }
mode_octal() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

release_lock() {
  [[ "$lock_held" == true ]] || return 0
  docker_tool_custody remove || return 1
  lock_held=false
}
mark_cleanup_required() {
  [[ "$custody_bound" == true ]] || return 0
  validate_custody identity || return 1
  append_durable "$intents" $'cleanup-required\t'"$operation"$'\n' || true
}

finish_failure() {
  local status=$1
  trap - ERR INT TERM HUP
  if (( BASH_SUBSHELL > 0 )); then exit "$status"; fi
  mark_cleanup_required || status=1
  if [[ "$create_active" == true ]]; then rollback_partial || status=1; fi
  if ! release_lock; then
    printf 'insecure-container lock release failed; retained exact owner lock\n' >&2
    status=1
  fi
  emit fail
  exit "$status"
}

on_error() { finish_failure "$?"; }
on_signal() { finish_failure 130; }

if [[ ! "$operation" =~ ^(create|verify|reset|destroy)$ ]]; then
  printf 'usage: %s create|verify|reset|destroy\n' "$0" >&2
  exit 2
fi
if [[ ! "$generation" =~ ^[a-f0-9]{32}$ ]]; then
  printf 'COGS_INSECURE_GENERATION must be exactly 32 lowercase hexadecimal characters\n' >&2
  exit 1
fi
if [[ ! "$original_revision" =~ ^[a-f0-9]{40}$ ]]; then
  printf 'COGS_INSECURE_ORIGINAL_REVISION must identify a 40-character lowercase revision\n' >&2
  exit 1
fi
if [[ "$state" != "$state_root/"* || -z "$state_name" || "$state_name" == */* \
    || ! "$state_name" =~ ^[A-Za-z0-9._-]+$ || -L "$state_root" || -L "$state" ]]; then
  printf 'insecure-container state directory must be one non-symlink child of %s\n' "$state_root" >&2
  exit 1
fi

# A failed retirement may have moved the locator itself. Its quarantine is a
# durable veto even when the old state/lock name is absent; never recreate/adopt.
assert_retirement_absent() {
  if compgen -G "$state_root/.cogs-retire-$state_name-*" >/dev/null; then
    fail 'insecure-container retirement custody is uncertain; recovery required'
  fi
}
assert_retirement_absent

trap on_error ERR
trap on_signal INT TERM HUP

select_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout_command=timeout
  elif command -v gtimeout >/dev/null 2>&1; then
    timeout_command=gtimeout
  else
    fail 'required command is missing: timeout (or gtimeout)'
  fi
}

bounded() {
  local duration=$1
  shift
  "$timeout_command" --signal=TERM --kill-after=5s "$duration" "$@"
}

acquire_lock() {
  if [[ ! -e "$state_root" ]]; then mkdir "$state_root"; fi
  verify_private_dir "$state_root"
  if ! mkdir "$lock" 2>/dev/null; then
    fail 'another insecure-container lifecycle command holds the state lock'
  fi
  chmod 0700 "$lock"
  lock_owner="$generation:$$:$RANDOM"
  lock_identity=$(stat -c '%d:%i' "$lock" 2>/dev/null || stat -f '%d:%i' "$lock")
  persist_new "$lock/owner" "$lock_owner"$'\n'
  lock_held=true
}

verify_private_dir() {
  local path=$1 mode owner
  [[ -d "$path" && ! -L "$path" && "$(realpath "$path")" == "$path" ]] || fail 'insecure-container docker state is invalid'
  mode=$(mode_octal "$path")
  owner=$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path")
  [[ "$owner:$mode:directory" == "$(id -u):700:directory" ]] || fail 'insecure-container docker state is invalid'
}

init_docker_tool_state() {
  docker_root="$lock/docker-tool"
  docker_home="$docker_root/home"
  docker_config="$docker_root/config"
  buildx_config="$docker_root/buildx"
  verify_private_dir "$lock"
  mkdir "$docker_root" "$docker_home" "$docker_config" "$buildx_config"
  chmod 0700 "$docker_root" "$docker_home" "$docker_config" "$buildx_config"
  verify_private_dir "$docker_root"
  verify_private_dir "$docker_home"
  verify_private_dir "$docker_config"
  verify_private_dir "$buildx_config"
  docker_command=(env "HOME=$docker_home" "DOCKER_CONFIG=$docker_config" "BUILDX_CONFIG=$buildx_config" docker)
  docker_tool_custody capture
}

docker_tool_custody() {
  python3 -I - "$lock" "$lock_identity" "$lock_owner" "$1" <<'PY'
import hashlib,json,os,stat,sys
lock,identity,owner,action=sys.argv[1:]; manifest='docker-tool.inventory'; flags=os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW
def valid_dir(s): return stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700
def stamp(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def regular(fd,name):
    h=os.open(name,flags,dir_fd=fd); s=os.fstat(h)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or s.st_mode&0o7022 or s.st_size>67108864:
        os.close(h); raise SystemExit('unsafe docker tool member')
    digest=hashlib.sha256(); size=0
    while True:
        part=os.read(h,65536)
        if not part: break
        size+=len(part)
        if size>67108864: os.close(h); raise SystemExit('oversized docker tool metadata')
        digest.update(part)
    if size!=s.st_size or stamp(s)!=stamp(os.fstat(h)) or stamp(s)!=stamp(os.stat(name,dir_fd=fd,follow_symlinks=False)):
        os.close(h); raise SystemExit('docker tool file changed during capture')
    os.close(h); return ['f',s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_mtime_ns,size,digest.hexdigest()]
def walk(fd,path,out):
    s=os.fstat(fd); before=stamp(s)
    if s.st_uid!=os.getuid() or s.st_mode&0o7022 or path.count('/')>16 or len(out)>=512:
        raise SystemExit('foreign or excessive docker tool directory')
    out[path]=['d',s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_mtime_ns]
    for name in sorted(os.listdir(fd)):
        s=os.stat(name,dir_fd=fd,follow_symlinks=False); key=path+'/'+name
        if stat.S_ISDIR(s.st_mode):
            child=os.open(name,flags|os.O_DIRECTORY,dir_fd=fd); opened=os.fstat(child)
            if (opened.st_dev,opened.st_ino)!=(s.st_dev,s.st_ino): os.close(child); raise SystemExit('docker tool directory changed')
            walk(child,key,out); os.close(child)
        elif stat.S_ISREG(s.st_mode):
            value=regular(fd,name)
            if value[1:3]!=[s.st_dev,s.st_ino]: raise SystemExit('docker tool file changed')
            out[key]=value
        else: raise SystemExit('unsafe docker tool member')
        if len(out)>512 or sum(v[5] for v in out.values() if v[0]=='f')>67108864: raise SystemExit('excessive docker tool inventory')
    if before!=stamp(os.fstat(fd)): raise SystemExit('docker tool directory changed during capture')
def snapshot(tool):
    if set(os.listdir(tool))!={'home','config','buildx'}: raise SystemExit('foreign tool inventory')
    s=os.fstat(tool); out={'.':['d',s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_mtime_ns]}
    for name in ('home','config','buildx'):
        child=os.open(name,flags|os.O_DIRECTORY,dir_fd=tool); s=os.fstat(child)
        if not valid_dir(s): os.close(child); raise SystemExit('foreign docker tool root')
        walk(child,name,out); os.close(child)
    return out
def manifest_file(lfd,write=False):
    mode=(os.O_RDWR if write else os.O_RDONLY)|os.O_NONBLOCK|os.O_NOFOLLOW
    h=os.open(manifest,mode,dir_fd=lfd); s=os.fstat(h)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        os.close(h); raise SystemExit('unsafe docker tool inventory')
    return h
def dir_value(fd):
    s=os.fstat(fd); return ['d',s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_mtime_ns]
def absent(fd,name):
    if name in os.listdir(fd): raise SystemExit('replacement preserved; quarantine requires recovery')
def retire(fd,name,key,expected):
    value=expected.get(key)
    if not value: raise SystemExit('unknown docker tool member')
    slot=os.urandom(16).hex(); absent(qfd,slot)
    # Only the root-held private quarantine is a deletion namespace. No unlink/rmdir
    # ever resolves an old tool pathname. A raced rename is preserved, never restored
    # over a competitor, and post-rename identity/content verification precedes deletion.
    os.rename(name,slot,src_dir_fd=fd,dst_dir_fd=qfd); os.fsync(fd); os.fsync(qfd)
    if value[0]=='d':
        child=os.open(slot,flags|os.O_DIRECTORY,dir_fd=qfd)
        if dir_value(child)!=value: raise SystemExit('docker tool directory replaced; preserved in quarantine')
        for member in sorted(os.listdir(child)):
            retire(child,member,member if key=='.' else key+'/'+member,expected)
        os.close(child); os.rmdir(slot,dir_fd=qfd)
    else:
        if regular(qfd,slot)!=value: raise SystemExit('docker tool file replaced; preserved in quarantine')
        os.unlink(slot,dir_fd=qfd)
    os.fsync(qfd); absent(fd,name)
lfd=os.open(lock,flags|os.O_DIRECTORY); ls=os.fstat(lfd)
if f'{ls.st_dev}:{ls.st_ino}'!=identity or not valid_dir(ls): raise SystemExit('lock identity changed')
allowed={'owner','docker-tool'}|({manifest} if manifest in os.listdir(lfd) else set())
if set(os.listdir(lfd))!=allowed: raise SystemExit('foreign lock inventory')
held=os.open('owner',flags,dir_fd=lfd); hs=os.fstat(held)
if not stat.S_ISREG(hs.st_mode) or hs.st_nlink!=1 or hs.st_uid!=os.getuid() or stat.S_IMODE(hs.st_mode)!=0o600 or os.read(held,256)!=(owner+'\n').encode():
    os.close(held); raise SystemExit('lock owner changed')
os.close(held)
tool=os.open('docker-tool',flags|os.O_DIRECTORY,dir_fd=lfd)
if not valid_dir(os.fstat(tool)): raise SystemExit('foreign docker tool root')
current=snapshot(tool); expected=None
if manifest in allowed:
    h=manifest_file(lfd); data=b''
    while len(data)<=16777216:
        part=os.read(h,65536)
        if not part: break
        data+=part
    os.close(h)
    try: expected=json.loads(data)
    except Exception: raise SystemExit('malformed docker tool inventory')
    if data!=(json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode(): raise SystemExit('malformed docker tool inventory')
    if any(current[n][:4]!=expected.get(n,[])[:4] for n in ('.','home','config','buildx')): raise SystemExit('docker tool roots replaced')
if action=='capture':
    encoded=(json.dumps(current,sort_keys=True,separators=(',',':'))+'\n').encode()
    if manifest in allowed:
        h=manifest_file(lfd,True); os.lseek(h,0,os.SEEK_SET); os.ftruncate(h,0)
    else: h=os.open(manifest,os.O_WRONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CREAT|os.O_EXCL,0o600,dir_fd=lfd)
    s=os.fstat(h)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        os.close(h); raise SystemExit('unsafe docker tool inventory')
    view=memoryview(encoded)
    while view: view=view[os.write(h,view):]
    os.fsync(h); os.close(h); os.fsync(lfd)
elif action in ('check','remove'):
    if current!=expected: raise SystemExit('docker tool custody changed')
    if action=='check': os.close(tool); os.close(lfd); raise SystemExit(0)
    # Unprivileged same-UID writers cannot be excluded with chmod. Do not pretend
    # another validation makes pathname deletion atomic: preserve instead, no sudo.
    parent,name=os.path.split(lock); pfd=os.open(parent,flags|os.O_DIRECTORY)
    if os.geteuid()!=0 or ls.st_uid!=0 or os.fstat(pfd).st_uid!=0 or not valid_dir(os.fstat(pfd)):
        raise SystemExit('root-held private retirement parent required; custody preserved')
    named=os.stat(name,dir_fd=pfd,follow_symlinks=False)
    if (named.st_dev,named.st_ino)!=(ls.st_dev,ls.st_ino): raise SystemExit('lock replaced')
    records={n:regular(lfd,n) for n in (manifest,'owner')}
    quarantine='.cogs-retire-'+os.path.basename(lock)[:-5]+'-'+os.urandom(16).hex(); os.mkdir(quarantine,0o700,dir_fd=pfd)
    qfd=os.open(quarantine,flags|os.O_DIRECTORY,dir_fd=pfd); qs=os.fstat(qfd)
    if qs.st_uid!=0 or not valid_dir(qs): raise SystemExit('unsafe quarantine; preserve')
    os.fsync(pfd)
    retire(lfd,'docker-tool','.',expected); os.close(tool)
    for member in (manifest,'owner'): retire(lfd,member,member,records)
    if os.listdir(lfd): raise SystemExit('foreign lock inventory; preserve')
    retire(pfd,name,name,{name:dir_value(lfd)})
    # Parent and quarantine are root-only and never exposed to tool writers.
    if os.listdir(qfd): raise SystemExit('quarantine not empty; preserve')
    os.close(qfd); os.rmdir(quarantine,dir_fd=pfd); os.fsync(pfd); os.close(pfd)
else: raise SystemExit('invalid docker tool custody action')
os.close(lfd)
PY
}

bounded_docker() {
  local duration=$1 status=0
  shift
  docker_tool_custody check || return 1
  bounded "$duration" "${docker_command[@]}" "$@" || status=$?
  (( status == 0 )) || return "$status"
  docker_tool_custody capture
}

initialize_authority() {
  [[ ! -e "$state" ]] || fail 'insecure-container state already exists; refusing adoption'
  mkdir "$state"
  chmod 0700 "$state"
  local device inode body
  read -r device inode < <(stat -c '%d %i' "$state" 2>/dev/null || stat -f '%d %i' "$state")
  body=$(printf 'cogs.insecure-authority/v1\tgeneration=%s\tprofile=%s\trevision=%s\tlocator=%s\tdevice=%s\tinode=%s\tnonce=%s\n' \
    "$generation" "$profile" "$original_revision" "$locator" "$device" "$inode" "$generation")
  persist_new "$authority" "$body"$'\n'
  persist_new "$sentinel" "$generation"$'\n'
  persist_new "$intents" $'cogs.insecure-intents/v1\n'
  persist_new "$inventory" $'cogs.insecure-inventory/v1\n'
}

validate_custody() {
  local observed
  observed=$(COGS_EXPECTED_IDENTITY=$custody_identity COGS_EXPECTED_GENERATION=$generation COGS_EXPECTED_PROFILE=$profile \
  COGS_EXPECTED_REVISION=$original_revision COGS_EXPECTED_LOCATOR=$locator \
  python3 -I - "$state" "${1:-full}" <<'PY'
import os, stat, sys
root = sys.argv[1]
st = os.lstat(root)
if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.getuid():
    raise SystemExit("invalid authority directory")
def read(name, limit=65536):
    p = os.path.join(root, name)
    s = os.lstat(p)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600:
        raise SystemExit("invalid authority file")
    fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o600 or (opened.st_dev,opened.st_ino) != (s.st_dev,s.st_ino):
        os.close(fd); raise SystemExit('custody file changed')
    with os.fdopen(fd, 'rb') as stream: data = stream.read(limit + 1)
    if len(data) > limit or not data.endswith(b"\n") or b"\0" in data or b"\r" in data:
        raise SystemExit("invalid authority bytes")
    return data
E, gen = os.environ, os.environ["COGS_EXPECTED_GENERATION"]
if read(".cogs-insecure-owner", 33) != (gen + "\n").encode():
    raise SystemExit("foreign generation sentinel")
expected = (f"cogs.insecure-authority/v1\tgeneration={gen}\tprofile={E['COGS_EXPECTED_PROFILE']}\t" +
    f"revision={E['COGS_EXPECTED_REVISION']}\tlocator={E['COGS_EXPECTED_LOCATOR']}\tdevice={st.st_dev}\t" +
    f"inode={st.st_ino}\tnonce={gen}\n").encode()
if read("authority", 8192) != expected:
    raise SystemExit("immutable authority binding mismatch")
identity = f'{st.st_dev}:{st.st_ino}'
if E['COGS_EXPECTED_IDENTITY'] and E['COGS_EXPECTED_IDENTITY'] != identity:
    raise SystemExit('retained directory replaced')
if sys.argv[2] == 'identity':
    print(identity); raise SystemExit(0)
for name, header in (("intents", "cogs.insecure-intents/v1"), ("inventory", "cogs.insecure-inventory/v1")):
    lines = read(name).decode("ascii").splitlines()
    if not lines or lines[0] != header or any(not line for line in lines):
        raise SystemExit("malformed lifecycle journal")
    if name == "intents":
        pending = None
        for line in lines[1:]:
            fields = line.split("\t")
            if len(fields) != 3 or fields[0] not in ("pending", "complete"):
                raise SystemExit("cleanup-required or malformed lifecycle intent")
            if fields[0] == "pending" and pending is None:
                pending = fields[1:]
            elif fields[0] == "complete" and pending == fields[1:]:
                pending = None
            else:
                raise SystemExit("pending lifecycle command requires recovery")
        if pending is not None:
            raise SystemExit("pending lifecycle command requires recovery")
print(identity)
PY
) || return 1
  custody_identity=$observed
  custody_bound=true
}

record_intent() { append_durable "$intents" "$1"$'\t'"$2"$'\t'"$3"$'\n'; }
record_inventory() { append_durable "$inventory" "$1"$'\n'; }

read_owned_member() {
  python3 -I - "$state" "$custody_identity" "$1" "${2:-65536}" <<'PY'
import os,stat,sys
root,identity,name,limit=sys.argv[1:]; limit=int(limit)
rfd=os.open(root,os.O_RDONLY|os.O_NONBLOCK|os.O_DIRECTORY|os.O_NOFOLLOW); r=os.fstat(rfd)
if f'{r.st_dev}:{r.st_ino}'!=identity: raise SystemExit('authority directory changed')
fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=rfd); s=os.fstat(fd)
if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
    raise SystemExit('unsafe state member')
data=os.read(fd,limit+1)
if len(data)>limit or os.read(fd,1): raise SystemExit('oversized state member')
os.write(1,data); os.close(fd); os.close(rfd)
PY
}

validate_complete_inventory() {
  local inventory_text container_locator volume_locator
  inventory_text=$(read_owned_member inventory) || return 1
  inventory_lines=()
  while IFS= read -r line; do inventory_lines+=("$line"); done <<<"$inventory_text"
  [[ ${#inventory_lines[@]} -eq 3 && "${inventory_lines[0]}" == 'cogs.insecure-inventory/v1' ]] \
    || fail 'insecure-container exact inventory is incomplete or has extra entries'
  local -a volume_fields container_fields
  IFS=$'\t' read -r -a volume_fields <<<"${inventory_lines[1]}"
  IFS=$'\t' read -r -a container_fields <<<"${inventory_lines[2]}"
  [[ ${#volume_fields[@]} -eq 3 && "${volume_fields[0]}:${volume_fields[1]}" == 'volume:acquired' \
      && "${volume_fields[2]}" =~ ^[A-Za-z0-9_.-]{1,255}$ ]] || fail 'insecure-container volume inventory is invalid'
  volume_name=${volume_fields[2]}
  [[ ${#container_fields[@]} -eq 4 && "${container_fields[0]}" == container && "${container_fields[1]}" == acquired \
      && "${container_fields[2]}" =~ ^[a-f0-9]{64}$ && "${container_fields[3]}" == "$container_name" ]] \
    || fail 'insecure-container container inventory is invalid'
  container_id=${container_fields[2]}
  container_locator=$(read_owned_member container 256) || return 1
  volume_locator=$(read_owned_member volume 256) || return 1
  [[ "$container_locator" == "$container_id" ]] || fail 'insecure-container container locator does not match inventory'
  [[ "$volume_locator" == "$volume_name" ]] || fail 'insecure-container volume locator does not match inventory'
}

verify_tsx() {
  require realpath
  tsx_bin="$repo/node_modules/.bin/tsx"
  tsx_real=$(realpath "$tsx_bin")
  [[ "$tsx_real" == "$repo/node_modules/tsx/dist/cli.mjs" ]] || fail 'repo-local tsx executable is not canonical'
  [[ -f "$tsx_real" && -x "$tsx_real" ]] || fail 'repo-local tsx executable is missing or not executable'
  local mode
  mode=$(mode_octal "$tsx_real")
  [[ "$mode" =~ ^[0-7]+$ && $((8#$mode & 0022)) -eq 0 ]] || fail 'repo-local tsx executable is writable by group or other'
}

verify_control_key_inventory() {
  local control="$state/control" entries first second key_file
  verify_private_dir "$control"
  entries=$(find "$control" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ')
  [[ "$entries" == 'client_ed25519_key client_ed25519_key.pub ' ]] || fail 'insecure-container control inventory is invalid'
  for key_file in "$control/client_ed25519_key" "$control/client_ed25519_key.pub"; do
    [[ -f "$key_file" && ! -L "$key_file" && "$(realpath "$key_file")" == "$key_file" ]] \
      || fail 'insecure-container control inventory is invalid'
  done
  first=$(mode_octal "$control/client_ed25519_key")
  second=$(mode_octal "$control/client_ed25519_key.pub")
  [[ "$first" == 600 && "$second" == 600 ]] || fail 'insecure-container control inventory is invalid'
}

assert_container_name_available() {
  local listing
  listing=$(bounded_docker 30s container ls --all --quiet --no-trunc --filter "name=^/${container_name}$") \
    || fail 'could not query container-name competitors'
  [[ -z "$listing" ]] || fail 'refusing to adopt or delete a pre-existing container competitor'
}

# Preserve exact raw command receipts before Bash can strip trailing LF/NUL.
exact_line() {
  python3 -I -c 'import sys
b=sys.stdin.buffer.read(4097)
if len(b)>4096 or not b.endswith(b"\n") or b.count(b"\n")!=1 or any(c<32 or c>126 for c in b[:-1]):
 raise SystemExit("malformed Docker receipt")
sys.stdout.write(b[:-1].decode("ascii"))'
}
exact_empty() {
  python3 -I -c 'import sys
if sys.stdin.buffer.read(1): raise SystemExit("resource absence not proven")'
}

validate_container_ownership() {
  local observed
  observed=$(bounded_docker 30s container inspect --format \
    '{{.Id}} {{.Name}} {{index .Config.Labels "dev.cogs.profile"}} {{index .Config.Labels "dev.cogs.state"}} {{index .Config.Labels "dev.cogs.generation"}} {{index .Config.Labels "dev.cogs.revision"}}' "$container_id" | exact_line)
  [[ "$observed" == "$container_id /$container_name $profile $state_id $generation $original_revision" ]] \
    || fail 'refusing to operate on a container without exact ID, name, and authority labels'
}

validate_volume_ownership() {
  local observed
  observed=$(bounded_docker 30s volume inspect --format \
    '{{.Name}} {{index .Labels "dev.cogs.profile"}} {{index .Labels "dev.cogs.state"}} {{index .Labels "dev.cogs.generation"}} {{index .Labels "dev.cogs.revision"}}' "$volume_name" | exact_line)
  [[ "$observed" == "$volume_name $profile $state_id $generation $original_revision" ]] \
    || fail 'refusing to operate on a volume without exact authority labels'
}

retire_exact() {
  local kind=$1 target=$2 output listing
  [[ "$custody_bound" == true ]] && validate_custody identity || return 1
  if [[ "$kind" == container ]]; then
    validate_container_ownership || return 1
  else
    validate_volume_ownership || return 1
  fi
  record_inventory "$kind"$'\tretiring\t'"$target" || return 1
  record_intent pending "$kind-remove" "$target" || return 1
  if [[ "$kind" == container ]]; then
    output=$(bounded_docker 45s container rm --force "$target" | exact_line) || return 1
    [[ "$output" == "$target" ]] || return 1
    listing=$(bounded_docker 30s container ls --all --quiet --no-trunc --filter "id=$target" | exact_empty) || return 1
  else
    output=$(bounded_docker 45s volume rm --force "$target" | exact_line) || return 1
    [[ "$output" == "$target" ]] || return 1
    listing=$(bounded_docker 30s volume ls --quiet --filter "name=^${target}$" | exact_empty) || return 1
  fi
  [[ -z "$listing" ]] || return 1
  record_intent complete "$kind-remove" "$target" || return 1
  record_inventory "$kind"$'\tretired\t'"$target" || return 1
}

rollback_partial() {
  # A lost run response may have left a container using the volume. Never
  # retire dependencies on absence/name discovery, or after uncertain stop.
  [[ "$container_pending" == false ]] || return 1
  if [[ "$container_acquired" == true ]]; then retire_exact container "$container_id" || return 1; fi
  if [[ "$volume_acquired" == true ]]; then retire_exact volume "$volume_name" || return 1; fi
}

ssh_options() {
  SSH_OPTIONS=(
    -F /dev/null
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ConnectionAttempts=1
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=1
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$state/known_hosts"
    -o IdentitiesOnly=yes
    -o IdentityAgent=none
    -o ForwardAgent=no
    -o ClearAllForwardings=yes
    -i "$state/control/client_ed25519_key"
    -p "$port"
  )
  SFTP_OPTIONS=(
    -F /dev/null
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=1
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$state/known_hosts"
    -o IdentitiesOnly=yes
    -o IdentityAgent=none
    -o ClearAllForwardings=yes
    -i "$state/control/client_ed25519_key"
    -P "$port"
  )
}

create() {
  require ssh-keygen
  require openssl
  initialize_authority
  validate_custody
  create_active=true
  assert_container_name_available

  local input="$state/input" control="$state/control" ca_private output
  mkdir "$control" "$input"
  chmod 0700 "$control" "$input"

  record_intent pending image-build "$image"
  bounded_docker 10m build --pull=false --tag "$image" \
    --file "$repo/dev/insecure-sandbox/Dockerfile" "$repo" >&2
  record_intent complete image-build "$image"
  assert_container_name_available

  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-host -f "$input/ssh_host_ed25519_key"
  ssh-keygen -q -t ed25519 -N '' -C cogs-insecure-client -f "$control/client_ed25519_key"
  cp "$control/client_ed25519_key.pub" "$input/client_ed25519_key.pub"
  chmod 0600 "$control/client_ed25519_key.pub" "$input/client_ed25519_key.pub"
  verify_control_key_inventory

  if [[ ! "$http_proxy" =~ ^https?://[A-Za-z0-9.-]+:([0-9]{1,5})$ ]] \
      || (( 10#${BASH_REMATCH[1]:-0} < 1 || 10#${BASH_REMATCH[1]:-0} > 65535 )); then
    fail 'COGS_HTTP_PROXY must be a non-credentialed HTTP(S) host and port'
  fi
  if [[ ! "$https_proxy" =~ ^https?://[A-Za-z0-9.-]+:([0-9]{1,5})$ ]] \
      || (( 10#${BASH_REMATCH[1]:-0} < 1 || 10#${BASH_REMATCH[1]:-0} > 65535 )); then
    fail 'COGS_HTTPS_PROXY must be a non-credentialed HTTP(S) host and port'
  fi

  if [[ -n "${COGS_PUBLIC_CA_FILE:-}" ]]; then
    [[ -f "$COGS_PUBLIC_CA_FILE" && ! -L "$COGS_PUBLIC_CA_FILE" ]] || fail 'configured public CA must be a regular, non-symlink file'
    [[ $(wc -c < "$COGS_PUBLIC_CA_FILE") -le 1048576 ]] || fail 'configured public CA exceeds the one-megabyte limit'
    if grep -Eq -- '-----BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY-----' "$COGS_PUBLIC_CA_FILE"; then
      fail 'configured public CA contains private key material'
    fi
    openssl x509 -in "$COGS_PUBLIC_CA_FILE" -out "$input/egress-ca.crt"
  else
    ca_private="$control/ephemeral-ca.key"
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
      -subj '/CN=Cogs Insecure Driver Public CA' \
      -keyout "$ca_private" -out "$input/egress-ca.crt" >/dev/null 2>&1
    rm -- "$ca_private"
  fi

  record_intent pending volume-create "$generation"
  output=$(bounded_docker 30s volume create \
    --label dev.cogs.profile="$profile" --label dev.cogs.state="$state_id" \
    --label dev.cogs.generation="$generation" --label dev.cogs.revision="$original_revision" | exact_line)
  [[ "$output" =~ ^[A-Za-z0-9_.-]{1,255}$ ]] || fail 'volume create returned a malformed or lost acquisition response'
  volume_name=$output
  validate_volume_ownership
  record_intent complete volume-create "$generation"
  record_inventory $'volume\tacquired\t'"$volume_name"
  persist_new "$state/volume" "$volume_name"$'\n'
  volume_acquired=true

  container_pending=true
  record_intent pending container-run "$container_name"
  output=$(bounded_docker 45s run --detach \
    --name "$container_name" --hostname sandbox \
    --label dev.cogs.profile="$profile" --label dev.cogs.authority=functional-only \
    --label dev.cogs.state="$state_id" --label dev.cogs.generation="$generation" \
    --label dev.cogs.revision="$original_revision" \
    --read-only --tmpfs /run:rw,nosuid,nodev,noexec,size=32m,mode=0700 \
    --tmpfs /tmp:rw,nosuid,nodev,size=256m --tmpfs /shared:rw,nosuid,nodev,noexec,size=8m,mode=0700 \
    --tmpfs /user:rw,nosuid,nodev,noexec,size=8m,mode=0700 \
    --mount "type=bind,src=$input,dst=/run/cogs-input,readonly" \
    --mount "type=volume,src=$volume_name,dst=/workspace" \
    --add-host host.docker.internal:host-gateway --publish 127.0.0.1::2222 \
    --env COGS_PROFILE="$profile" --env HTTP_PROXY="$http_proxy" --env HTTPS_PROXY="$https_proxy" \
    --env NO_PROXY="127.0.0.1,localhost" --env SSL_CERT_FILE=/run/cogs-runtime/egress-ca.crt \
    "$image" | exact_line)
  [[ "$output" =~ ^[a-f0-9]{64}$ ]] || fail 'container run returned a malformed or lost acquisition response'
  container_id=$output
  validate_container_ownership
  record_intent complete container-run "$container_name"
  record_inventory $'container\tacquired\t'"$container_id"$'\t'"$container_name"
  persist_new "$state/container" "$container_id"$'\n'
  container_acquired=true
  container_pending=false

  local running deadline
  sleep 1
  running=$(bounded_docker 30s inspect --format '{{.State.Running}}' "$container_id")
  if [[ "$running" != true ]]; then
    bounded_docker 15s logs "$container_id" >&2 || true
    fail 'insecure-container stopped during startup'
  fi
  port=$(bounded_docker 30s port "$container_id" 2222/tcp | awk -F: 'NR == 1 {print $NF}')
  [[ "$port" =~ ^[0-9]+$ ]] || fail 'failed to discover SSH port'
  printf '[127.0.0.1]:%s %s\n' "$port" "$(awk 'NF >= 2 {print $1 " " $2; exit}' "$input/ssh_host_ed25519_key.pub")" > "$state/known_hosts"
  printf '%s\n' "$port" > "$state/port"

  ssh_options
  deadline=$((SECONDS + 30))
  until bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 true >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      bounded_docker 15s logs "$container_id" >&2 || true
      fail 'insecure-container SSH readiness timed out'
    fi
    running=$(bounded_docker 30s inspect --format '{{.State.Running}}' "$container_id")
    [[ "$running" == true ]] || fail 'insecure-container stopped before SSH became ready'
    sleep 1
  done
  file_custody capture
  create_active=false
}

verify_runtime_identity() {
  local running mount published
  validate_container_ownership
  validate_volume_ownership
  running=$(bounded_docker 30s inspect --format '{{.State.Running}}' "$container_id")
  [[ "$running" == true ]] || fail 'recorded insecure-container is not running'
  mount=$(bounded_docker 30s inspect --format '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Name}}{{end}}{{end}}' "$container_id")
  [[ "$mount" == "$volume_name" ]] || fail 'recorded workspace volume is not mounted in the container'
  published=$(bounded_docker 30s port "$container_id" 2222/tcp)
  [[ "$published" == "127.0.0.1:$port" ]] || fail 'recorded SSH endpoint is not the loopback-published container port'
}

verify_skill_roots() {
  bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 '
    for skill_parent in /shared /user; do
      test -d "$skill_parent" &&
      test ! -L "$skill_parent" &&
      test "$(realpath -e "$skill_parent")" = "$skill_parent" &&
      test "$(stat -c "%u:%g:%a:%F" "$skill_parent")" = "0:0:700:directory"
    done
    for skill_root in /shared/skills /user/skills; do
      test -d "$skill_root" &&
      test ! -L "$skill_root" &&
      test "$(realpath -e "$skill_root")" = "$skill_root" &&
      test "$(stat -c "%u:%g:%a:%F" "$skill_root")" = "0:0:700:directory"
    done
  ' >/dev/null || fail 'guest skill roots are not provisioned'
}

verify() {
  require ssh
  require ssh-keygen
  require sftp
  require cmp
  verify_tsx
  validate_custody
  validate_complete_inventory
  file_custody check
  verify_control_key_inventory
  port=$(read_owned_member port 32) || fail 'insecure-container state is absent or incomplete'
  [[ "$port" =~ ^[0-9]+$ ]] || fail 'insecure-container SSH port is invalid'
  verify_runtime_identity
  ssh_options
  verify_skill_roots

  local observed transfer="$state/control/sftp-control.txt" roundtrip="$state/control/sftp-roundtrip.txt" host_fingerprint
  host_fingerprint=$(ssh-keygen -q -lf "$state/input/ssh_host_ed25519_key.pub" -E sha256 | awk 'NR == 1 {print $2}')
  [[ "$host_fingerprint" =~ ^SHA256:[A-Za-z0-9+/]{43}$ ]] || fail 'insecure-container host fingerprint is invalid'
  bounded 20s "$tsx_bin" "$repo/dev/insecure-sandbox/ssh-adapter-smoke.ts" \
    "127.0.0.1:$port" "$state/control/client_ed25519_key" "$host_fingerprint" \
    >/dev/null || fail 'production SSH adapter smoke failed'

  observed=$(bounded 20s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
    'test "$(id -u)" = 0 && test "$COGS_PROFILE" = insecure-container && test -n "$HTTP_PROXY" && test -n "$HTTPS_PROXY" && test -r "$SSL_CERT_FILE" && printf verified')
  [[ "$observed" == verified ]] || fail 'SSH contract returned an unexpected result'

  printf 'sftp-positive-control\n' > "$transfer"
  (
    cd "$state/control"
    bounded 20s sftp "${SFTP_OPTIONS[@]}" -b - root@127.0.0.1 >/dev/null <<EOF
put sftp-control.txt /workspace/sftp-control-$state_id.txt
get /workspace/sftp-control-$state_id.txt sftp-roundtrip.txt
rm /workspace/sftp-control-$state_id.txt
EOF
  ) || fail 'SFTP contract verification failed'
  cmp "$transfer" "$roundtrip" || fail 'SFTP round-trip mismatch'
  rm -f "$transfer" "$roundtrip"

  local wrong_host="$state/control/wrong_host_key" mismatch_log="$state/control/host-mismatch.log"
  ssh-keygen -q -t ed25519 -N '' -C wrong-host-positive-control -f "$wrong_host"
  printf '[127.0.0.1]:%s %s\n' "$port" "$(awk 'NF >= 2 {print $1 " " $2; exit}' "$wrong_host.pub")" > "$state/control/wrong_known_hosts"
  if bounded 12s ssh \
      -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$state/control/wrong_known_hosts" \
      -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes \
      -i "$state/control/client_ed25519_key" -p "$port" root@127.0.0.1 true \
      >/dev/null 2>"$mismatch_log"; then
    fail 'host-key mismatch positive control unexpectedly succeeded'
  fi
  grep -Eq 'REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed' "$mismatch_log" \
    || fail 'host-key mismatch did not fail for host-key verification'
  rm -f "$wrong_host" "$wrong_host.pub" "$state/control/wrong_known_hosts" "$mismatch_log"
  bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 true >/dev/null

  local wrong_client="$state/control/wrong_client_key" auth_log="$state/control/client-auth.log"
  ssh-keygen -q -t ed25519 -N '' -C wrong-client-positive-control -f "$wrong_client"
  if bounded 12s ssh \
      -F /dev/null -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1 \
      -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$state/known_hosts" \
      -o IdentitiesOnly=yes -o IdentityAgent=none -o ForwardAgent=no -o ClearAllForwardings=yes \
      -i "$wrong_client" -p "$port" root@127.0.0.1 \
      'touch /workspace/unknown-client-side-effect' >/dev/null 2>"$auth_log"; then
    fail 'unknown controller key positive control unexpectedly authenticated'
  fi
  grep -Fq 'Permission denied (publickey)' "$auth_log" || fail 'unknown controller key did not fail as public-key authentication denial'
  rm -f "$wrong_client" "$wrong_client.pub" "$auth_log"
  observed=$(bounded 12s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
    'test ! -e /workspace/unknown-client-side-effect && printf healthy')
  [[ "$observed" == healthy ]] || fail 'SSH endpoint was not healthy after negative controls'
  file_custody check
}

reset() {
  validate_custody
  validate_complete_inventory
  file_custody check
  validate_container_ownership
  validate_volume_ownership
  local output
  record_intent pending container-restart "$container_id"
  output=$(bounded_docker 45s container restart "$container_id" | exact_line)
  [[ "$output" == "$container_id" ]] || fail 'container restart returned a malformed or lost response'
  validate_container_ownership
  record_intent complete container-restart "$container_id"
  verify
}

file_custody() {
  validate_custody identity || return 1
  python3 -I - "$state" "$1" "$custody_identity" <<'PY'
import hashlib,json,os,stat,sys
root,action,identity=sys.argv[1:]; record='files.owner'
top={'.cogs-insecure-owner','authority','intents','inventory','container','volume','port','known_hosts','input','control'}
children={'input':{'ssh_host_ed25519_key','ssh_host_ed25519_key.pub','client_ed25519_key.pub','egress-ca.crt'},
          'control':{'client_ed25519_key','client_ed25519_key.pub'}}
rfd=os.open(root,os.O_RDONLY|os.O_NONBLOCK|os.O_DIRECTORY|os.O_NOFOLLOW); info=os.fstat(rfd)
if f'{info.st_dev}:{info.st_ino}'!=identity: raise SystemExit('directory changed')
if set(os.listdir(rfd)) != top | (set() if action=='capture' else {record}): raise SystemExit('foreign state inventory')
pins=[]
def stamp(s): return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def file(fd,name,logical=None):
    handle=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=fd); s=os.fstat(handle)
    pins.append(os.dup(handle))
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        raise SystemExit('unsafe state member')
    with os.fdopen(handle,'rb') as stream:
        data=stream.read(1048577); after=os.fstat(stream.fileno())
    if len(data)>1048576 or stamp(s)!=stamp(after) or stamp(s)!=stamp(os.stat(name,dir_fd=fd,follow_symlinks=False)): raise SystemExit('state member changed')
    marker=[s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode)]
    return marker if (logical or name) in ('intents','inventory') else marker+[hashlib.sha256(data).hexdigest()]
values={}; held={}
for directory,names in children.items():
    fd=os.open(directory,os.O_RDONLY|os.O_NONBLOCK|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rfd); held[directory]=fd
    s=os.fstat(fd)
    if s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700 or set(os.listdir(fd))!=names:
        raise SystemExit('foreign key inventory')
    values[directory]=[s.st_dev,s.st_ino]
    for name in sorted(names): values[directory+'/'+name]=file(fd,name)
for name in sorted(top-children.keys()): values[name]=file(rfd,name)
if action=='capture':
    fd=os.open(record,os.O_WRONLY|os.O_NONBLOCK|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=rfd); s=os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        os.close(fd); raise SystemExit('unsafe file owner record')
    with os.fdopen(fd,'w') as out:
        json.dump(values,out,sort_keys=True,separators=(',',':')); out.write('\n'); out.flush(); os.fsync(out.fileno())
    os.fsync(rfd)
else:
    record_value=file(rfd,record)
    fd=os.open(record,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=rfd); s=os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o600:
        os.close(fd); raise SystemExit('unsafe file owner record')
    with os.fdopen(fd,'r') as stream: text=stream.read(65537)
    if [s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),hashlib.sha256(text.encode()).hexdigest()]!=record_value or len(text)>65536 or text!=json.dumps(values,sort_keys=True,separators=(',',':'))+'\n':
        raise SystemExit('retained file acquisition changed')
    if action=='remove':
        flags=os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_DIRECTORY
        parent,name=os.path.split(root); pfd=os.open(parent,flags); ps=os.fstat(pfd)
        if os.geteuid()!=0 or info.st_uid!=0 or ps.st_uid!=0 or stat.S_IMODE(ps.st_mode)!=0o700:
            raise SystemExit('root-held private retirement parent required; custody preserved')
        quarantine='.cogs-retire-'+name+'-'+os.urandom(16).hex(); os.mkdir(quarantine,0o700,dir_fd=pfd)
        qfd=os.open(quarantine,flags,dir_fd=pfd); qs=os.fstat(qfd)
        if qs.st_uid!=0 or stat.S_IMODE(qs.st_mode)!=0o700: raise SystemExit('unsafe quarantine; preserve')
        os.fsync(pfd)
        def retire(fd,name,expected,directory=False):
            slot=os.urandom(16).hex()
            os.rename(name,slot,src_dir_fd=fd,dst_dir_fd=qfd); os.fsync(fd); os.fsync(qfd)
            if directory:
                moved=os.open(slot,flags,dir_fd=qfd); s=os.fstat(moved)
                if [s.st_dev,s.st_ino]!=expected or os.listdir(moved): raise SystemExit('directory replaced; quarantine retained')
                os.close(moved); os.rmdir(slot,dir_fd=qfd)
            else:
                if file(qfd,slot,name)!=expected: raise SystemExit('file replaced; quarantine retained')
                os.unlink(slot,dir_fd=qfd)
            os.fsync(qfd)
            if name in os.listdir(fd): raise SystemExit('replacement preserved; quarantine requires recovery')
        for directory,names in children.items():
            for member in sorted(names): retire(held[directory],member,values[directory+'/'+member])
            retire(rfd,directory,values[directory],True)
        for member in sorted(top-children.keys()): retire(rfd,member,values[member])
        retire(rfd,record,record_value)
        retire(pfd,name,[info.st_dev,info.st_ino],True)
        os.close(qfd)
        try: os.rmdir(quarantine,dir_fd=pfd); os.fsync(pfd)
        except OSError:
            try: os.mkdir(quarantine,0o700,dir_fd=pfd)
            except FileExistsError: pass
            raise
        os.close(pfd)
    elif action!='check': raise SystemExit('invalid file owner operation')
for fd in [*held.values(),*pins]: os.close(fd)
os.close(rfd)
PY
}

destroy() {
  [[ -e "$state" ]] || fail 'insecure-container authority is absent; destroy cannot claim success'
  validate_custody
  validate_complete_inventory
  file_custody check
  retire_exact container "$container_id"
  retire_exact volume "$volume_name"
  local inventory_text
  inventory_text=$(read_owned_member inventory) || return 1
  inventory_lines=()
  while IFS= read -r line; do inventory_lines+=("$line"); done <<<"$inventory_text"
  [[ ${#inventory_lines[@]} -eq 7 \
      && "${inventory_lines[3]}" == "container"$'\t'"retiring"$'\t'"$container_id" \
      && "${inventory_lines[4]}" == "container"$'\t'"retired"$'\t'"$container_id" \
      && "${inventory_lines[5]}" == "volume"$'\t'"retiring"$'\t'"$volume_name" \
      && "${inventory_lines[6]}" == "volume"$'\t'"retired"$'\t'"$volume_name" ]] \
    || fail 'resource retirement inventory is not exact'
  file_custody remove
}

require python3
require openssl
require docker
select_timeout
acquire_lock
assert_retirement_absent
init_docker_tool_state
"$operation"
if ! release_lock; then
  fail 'insecure-container lock release failed; retained exact owner lock'
fi
emit pass
