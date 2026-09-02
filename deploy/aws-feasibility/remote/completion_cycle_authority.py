"""One-shot fixed-file batch/ordinal capability for production cycle owners."""

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import completion_campaign_production as campaign

ROOT = Path("/var/lib/cogs/stage2-completion-v1/cycle-authority-v1")
GRANT = ROOT / "grant.json"
MAX_BYTES = 4096
_claimed = False


class CycleAuthorityError(Exception): pass


def _require(condition):
    if not condition: raise CycleAuthorityError()


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")+b"\n"


def _pairs(rows):
    value={}
    for key,item in rows:
        _require(type(key) is str and key not in value);value[key]=item
    return value


def decode(raw):
    _require(type(raw) is bytes and 0<len(raw)<=MAX_BYTES and raw.endswith(b"\n") and b"\r" not in raw)
    try:value=json.loads(raw,object_pairs_hook=_pairs,parse_constant=lambda _x:(_ for _ in()).throw(ValueError()))
    except (UnicodeError,ValueError,TypeError,RecursionError) as error:raise CycleAuthorityError() from error
    _require(type(value) is dict and set(value)=={"version","batch_commitment","ordinal","mode","implementation_revision","control_revision","static_control_sha256","rootfs_descriptor_sha256","ami_commitment","plan_sha256","grant_commitment"}
             and value["version"]=="cogs.stage2-cycle-launch-grant/v1" and _canonical(value)==raw)
    return campaign.CycleLaunchGrant(
        value["batch_commitment"],value["ordinal"],value["mode"],value["implementation_revision"],
        value["control_revision"],value["static_control_sha256"],value["rootfs_descriptor_sha256"],
        value["ami_commitment"],value["plan_sha256"],value["grant_commitment"])


def _read_fixed(path,mode,owner):
    _require(isinstance(path,Path) and mode in {"full","readiness"}
             and type(owner) is tuple and len(owner)==2)
    parent=path.parent;seen=parent.lstat()
    _require(stat.S_ISDIR(seen.st_mode) and stat.S_IMODE(seen.st_mode)==0o700
             and (seen.st_uid,seen.st_gid)==owner)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before=os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==0o400
                 and (before.st_uid,before.st_gid)==owner and before.st_nlink==1
                 and 0<before.st_size<=MAX_BYTES)
        raw=b""
        while len(raw)<before.st_size:
            part=os.read(descriptor,min(MAX_BYTES+1-len(raw),before.st_size-len(raw)))
            _require(part);raw+=part
        _require(not os.read(descriptor,1));after=os.fstat(descriptor)
        stable=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        _require(len(raw)==before.st_size and stable(before)==stable(after))
        grant=decode(raw);_require(grant.mode==mode)
        path.unlink();directory=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(directory)
        finally:os.close(directory)
        _require(os.fstat(descriptor).st_nlink==0)
        parent.rmdir()
        ancestor=os.open(parent.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(ancestor)
        finally:os.close(ancestor)
        return grant
    finally:os.close(descriptor)


def _claim(path,mode,owner):
    global _claimed
    _require(not _claimed);_claimed=True
    return _read_fixed(path,mode,owner)


def claim_full():
    _require(os.geteuid()==0 and sys.argv==[sys.argv[0]])
    return _claim(GRANT,"full",(0,0))


def claim_readiness():
    _require(os.geteuid()==0 and sys.argv==[sys.argv[0]])
    return _claim(GRANT,"readiness",(0,0))
