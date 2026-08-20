"""Private persistent host-global ownership for the fixed NFT writer.

The lock inode and the state record are deliberately separate.  The lock is
never unlinked; the state is replaced and fsynced for every transition.  An
absent or unparseable state is not an unlocked/clean state.
"""
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import struct

import completion_kata_fdmap as fdmap

OWNER_DIR = "/var/lib/cogs-stage2-nft-owner-v1"
LOCK_NAME = "writer.lock"
STATE_NAME = "state.json"
SOURCE_ROOT = "/var/lib/cogs/stage2-completion-v1/source"
OPERATION_JOURNAL = (SOURCE_ROOT +
    "/deploy/aws-feasibility/.state/completion-v1/kata-operation-v1/operation-v1.jsonl")
CGROUP_BASE = "/sys/fs/cgroup/cogs-stage2-completion-v1"
MAX_PROCESSES = 32_768
MAX_PROCESS_FDS = 4_096
STATE_VERSION = "cogs.stage2-host-global-nft-state/v1"
LOCK_ROLE = fdmap.NFT_WRITER_LOCK
LOCK_TARGET_FD = fdmap.NFT_WRITER_LOCK_FD
ZERO = "0" * 64
HEX = frozenset("0123456789abcdef")
_PHASES = frozenset({"FREE", "ACTIVE", "RELEASING"})
_STATE_FIELDS = frozenset({
    "version", "phase", "sequence", "operation_token", "journal_binding_sha256",
    "journal_genesis_sha256", "host_boot_id", "host_netns", "predecessor_sha256",
    "cleanup_proof_sha256", "command_binding_sha256", "legacy_fence_sha256",
    "record_sha256",
})


class NftOwnerError(Exception):
    """The host-global NFT state cannot authorize another mutation."""


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii") + b"\n"


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _hex(value, zero=False):
    return (type(value) is str and len(value) == 64 and set(value) <= HEX
            and (zero or value != ZERO))


def _boot_id():
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as source:
        value = source.read(64)
    value = value.strip()
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value) is None:
        raise NftOwnerError("canonical host boot identity unavailable")
    return value


def _host_netns():
    descriptor = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        observed = os.fstat(descriptor)
        if observed.st_dev <= 0 or observed.st_ino <= 0:
            raise NftOwnerError("host network namespace identity unavailable")
        return {"device": observed.st_dev, "inode": observed.st_ino}
    finally:
        os.close(descriptor)


def _directory(path, exact_mode=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        observed = os.fstat(descriptor)
        if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != 0 or observed.st_gid != 0
                or observed.st_mode & 0o022 or exact_mode is not None
                and stat.S_IMODE(observed.st_mode) != exact_mode):
            raise NftOwnerError(f"unsafe NFT owner directory:{path}")
        return descriptor, (observed.st_dev, observed.st_ino, observed.st_mode,
                            observed.st_uid, observed.st_gid)
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent():
    opened = []
    try:
        for path in ("/", "/var", "/var/lib"):
            descriptor, _identity = _directory(path)
            opened.append(descriptor)
        parent, identity = _directory(OWNER_DIR, 0o700)
        opened.append(parent)
        return opened, parent, identity
    except BaseException:
        for descriptor in reversed(opened):
            try: os.close(descriptor)
            except OSError: pass
        raise


def _regular_identity(descriptor, mode):
    observed = os.fstat(descriptor)
    if (not stat.S_ISREG(observed.st_mode) or stat.S_IMODE(observed.st_mode) != mode
            or observed.st_uid != 0 or observed.st_gid != 0 or observed.st_nlink != 1
            or observed.st_dev <= 0 or observed.st_ino <= 0):
        raise NftOwnerError("unsafe NFT owner file identity")
    return fdmap.identity(descriptor)


def _open_lock(parent):
    descriptor = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        identity = _regular_identity(descriptor, 0o600)
        if identity.size != 0:
            raise NftOwnerError("NFT lock inode is not empty")
        command = getattr(fcntl, "F_OFD_SETLK", None)
        if command is None:
            raise NftOwnerError("nonblocking OFD locks unavailable")
        lock = struct.pack("hhqqi", fcntl.F_WRLCK, os.SEEK_SET, 0, 0, 0)
        try: fcntl.fcntl(descriptor, command, lock)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise NftOwnerError("host-global NFT writer is already owned") from error
            raise
        path = os.stat(LOCK_NAME, dir_fd=parent, follow_symlinks=False)
        if ((path.st_dev, path.st_ino) != (identity.device, identity.inode)
                or fdmap.identity(descriptor) != identity):
            raise NftOwnerError("NFT lock identity changed")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _parse_state(raw):
    if type(raw) is not bytes or not raw.endswith(b"\n") or len(raw) > 16_384 or b"\x00" in raw:
        raise NftOwnerError("bounded canonical NFT state required")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NftOwnerError("malformed NFT state") from error
    if type(value) is not dict or set(value) != _STATE_FIELDS or _canonical(value) != raw:
        raise NftOwnerError("noncanonical NFT state")
    if (value["version"] != STATE_VERSION or value["phase"] not in _PHASES
            or type(value["sequence"]) is not int or value["sequence"] < 0
            or not _hex(value["operation_token"], value["sequence"] == 0)
            or not _hex(value["journal_binding_sha256"], value["sequence"] == 0)
            or not _hex(value["journal_genesis_sha256"], value["sequence"] == 0)
            or not _hex(value["predecessor_sha256"], value["sequence"] == 0)
            or not _hex(value["cleanup_proof_sha256"], value["phase"] == "ACTIVE")
            or not _hex(value["command_binding_sha256"], value["phase"] == "ACTIVE")
            or not _hex(value["legacy_fence_sha256"]) or not _hex(value["record_sha256"])):
        raise NftOwnerError("invalid NFT state fields")
    netns = value["host_netns"]
    if (type(value["host_boot_id"]) is not str or type(netns) is not dict
            or set(netns) != {"device", "inode"}
            or any(type(netns[name]) is not int or netns[name] <= 0 for name in netns)):
        raise NftOwnerError("invalid NFT host binding")
    unsigned = {name: child for name, child in value.items() if name != "record_sha256"}
    if _digest(unsigned) != value["record_sha256"]:
        raise NftOwnerError("NFT state digest mismatch")
    if value["sequence"] == 0 and not (value["phase"] == "FREE"
            and value["operation_token"] == value["journal_binding_sha256"] ==
                value["journal_genesis_sha256"] == value["predecessor_sha256"] == ZERO):
        raise NftOwnerError("invalid initial NFT state")
    return value


def _read_state(parent):
    descriptor = os.open(STATE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = _regular_identity(descriptor, 0o600)
        if before.size > 16_384:
            raise NftOwnerError("oversized NFT state")
        raw = os.read(descriptor, 16_385)
        if len(raw) != before.size or fdmap.identity(descriptor) != before:
            raise NftOwnerError("NFT state changed while reading")
        path = os.stat(STATE_NAME, dir_fd=parent, follow_symlinks=False)
        if (path.st_dev, path.st_ino) != (before.device, before.inode):
            raise NftOwnerError("NFT state pathname substitution")
        return _parse_state(raw)
    except FileNotFoundError as error:
        raise NftOwnerError("persistent NFT state is missing") from error
    finally:
        os.close(descriptor)


def _replace_state(parent, value):
    raw = _canonical(value)
    temporary = f".state-{os.getpid()}-{os.urandom(12).hex()}"
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        _regular_identity(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0: raise NftOwnerError("short NFT state write")
            offset += written
        os.fsync(descriptor)
        if _parse_state(os.pread(descriptor, len(raw), 0)) != value:
            raise NftOwnerError("NFT state write confirmation failed")
        os.rename(temporary, STATE_NAME, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        confirmed = _read_state(parent)
        if confirmed != value:
            raise NftOwnerError("NFT state replacement confirmation failed")
    finally:
        if descriptor is not None:
            try: os.close(descriptor)
            except OSError: pass
        try: os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError: pass


def _state(phase, sequence, operation_token, journal_binding, journal_genesis,
           host_boot_id, host_netns, predecessor, cleanup, command, fence):
    value = {
        "version": STATE_VERSION, "phase": phase, "sequence": sequence,
        "operation_token": operation_token, "journal_binding_sha256": journal_binding,
        "journal_genesis_sha256": journal_genesis, "host_boot_id": host_boot_id,
        "host_netns": host_netns, "predecessor_sha256": predecessor,
        "cleanup_proof_sha256": cleanup, "command_binding_sha256": command,
        "legacy_fence_sha256": fence, "record_sha256": ZERO,
    }
    value["record_sha256"] = _digest({name: child for name, child in value.items()
                                      if name != "record_sha256"})
    return value


def _journal_bindings(journal):
    import completion_kata_operation as operation
    context = operation._command_context(journal)
    history = journal.runtime_recovery_history()
    binding = _digest({
        "operation_token": context.operation_token, "journal_key": context.journal_key,
        "host_boot_id": context.host_boot_id, "source_revision": context.source_revision,
    })
    genesis = _digest({
        "operation_token": context.operation_token, "journal_key": context.journal_key,
        "host_boot_id": context.host_boot_id,
    })
    return context, history, binding, genesis


def _bounded_proc_file(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(descriptor, limit + 1)
        if len(raw) > limit:
            raise NftOwnerError(f"bounded legacy census required:{path}")
        return raw
    finally:
        os.close(descriptor)


def _proc_start_time(pid):
    raw = _bounded_proc_file(f"/proc/{pid}/stat", 4096)
    close = raw.rfind(b")")
    fields = raw[close + 2:].split() if close > 0 else ()
    if len(fields) < 20:
        raise NftOwnerError("canonical process stat census unavailable")
    try:
        value = int(fields[19])
    except ValueError as error:
        raise NftOwnerError("canonical process start census unavailable") from error
    if value <= 0:
        raise NftOwnerError("invalid process start census")
    return value


def _source_census():
    module = os.path.realpath(__file__)
    if not (module.startswith(SOURCE_ROOT + "/") and module.endswith("completion_kata_nft_owner.py")):
        raise NftOwnerError("trusted production NFT owner source unavailable")
    root = os.stat(SOURCE_ROOT, follow_symlinks=False)
    descriptor = os.open(module, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        observed = os.fstat(descriptor)
        raw = os.read(descriptor, 131_073)
    finally:
        os.close(descriptor)
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_gid != 0
            or root.st_mode & 0o022 or not stat.S_ISREG(observed.st_mode)
            or observed.st_uid != 0 or observed.st_gid != 0
            or observed.st_mode & 0o022 or observed.st_nlink != 1
            or observed.st_size != len(raw) or len(raw) > 131_072):
        raise NftOwnerError("unsafe trusted NFT owner source")
    return {
        "root": [root.st_dev, root.st_ino, root.st_mode, root.st_uid, root.st_gid],
        "module": [observed.st_dev, observed.st_ino, observed.st_mode,
                   observed.st_uid, observed.st_gid, observed.st_size],
        "module_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _journal_census(context, provisioning):
    try:
        observed = os.stat(OPERATION_JOURNAL, follow_symlinks=False)
    except FileNotFoundError:
        if not provisioning:
            raise NftOwnerError("fixed operation journal census unavailable")
        return {"present": False}
    if provisioning:
        raise NftOwnerError("fresh-host provisioning found an operation journal")
    key = context.journal_key
    if (not stat.S_ISREG(observed.st_mode) or observed.st_uid != 0 or observed.st_gid != 0
            or stat.S_IMODE(observed.st_mode) != 0o600 or observed.st_nlink != 1
            or type(key) is not dict or key.get("device") != observed.st_dev
            or key.get("inode") != observed.st_ino):
        raise NftOwnerError("fixed operation journal identity mismatch")
    return {"present": True, "device": observed.st_dev, "inode": observed.st_ino,
            "size": observed.st_size, "mtime_ns": observed.st_mtime_ns,
            "ctime_ns": observed.st_ctime_ns}


def _cgroup_census():
    try:
        observed = os.stat(CGROUP_BASE, follow_symlinks=False)
        names = sorted(os.listdir(CGROUP_BASE))
        members = _bounded_proc_file(CGROUP_BASE + "/cgroup.procs", 262_144)
    except FileNotFoundError:
        return {"present": False}
    if not stat.S_ISDIR(observed.st_mode) or len(names) > MAX_PROCESS_FDS:
        raise NftOwnerError("bounded legacy command cgroup census unavailable")
    return {"present": True, "device": observed.st_dev, "inode": observed.st_ino,
            "names": names, "members_sha256": hashlib.sha256(members).hexdigest(),
            "members_length": len(members)}


def _process_census():
    try:
        pids = sorted(int(name) for name in os.listdir("/proc") if name.isdigit())
    except (OSError, ValueError) as error:
        raise NftOwnerError("global process census unavailable") from error
    if len(pids) > MAX_PROCESSES:
        raise NftOwnerError("bounded global process census required")
    identities, offenders = [], []
    for pid in pids:
        try:
            before = _proc_start_time(pid)
            cmdline = _bounded_proc_file(f"/proc/{pid}/cmdline", 131_072)
            cgroup = _bounded_proc_file(f"/proc/{pid}/cgroup", 65_536)
            cwd = os.readlink(f"/proc/{pid}/cwd")
            executable = os.readlink(f"/proc/{pid}/exe")
            names = sorted(os.listdir(f"/proc/{pid}/fd"), key=lambda item: int(item))
            if len(names) > MAX_PROCESS_FDS or any(not name.isdigit() for name in names):
                raise NftOwnerError("bounded process descriptor census required")
            descriptors = []
            for name in names:
                target = os.readlink(f"/proc/{pid}/fd/{name}")
                identity = os.stat(f"/proc/{pid}/fd/{name}")
                descriptors.append([int(name), target, identity.st_dev, identity.st_ino,
                                    identity.st_mode])
            after = _proc_start_time(pid)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as error:
            raise NftOwnerError(f"exact process census unavailable:{pid}") from error
        if before != after:
            raise NftOwnerError("process identity changed during legacy census")
        identities.append([pid, before])
        if pid == os.getpid():
            continue
        text = cmdline.decode("utf-8", "surrogateescape")
        reasons = []
        if SOURCE_ROOT in text or "completion_kata_" in text or "completion_local_full.py" in text:
            reasons.append("command")
        if ((cwd == SOURCE_ROOT or cwd.startswith(SOURCE_ROOT + "/"))
                and os.path.basename(executable).startswith("python")):
            reasons.append("cwd")
        if ("/cogs-stage2-completion-v1" in cgroup.decode("ascii", "strict")
                or any(target == OPERATION_JOURNAL or target.startswith(OWNER_DIR + "/")
                       or target.startswith(SOURCE_ROOT + "/") for _fd, target, *_rest in descriptors)):
            reasons.append("fd-cgroup-source")
        if reasons:
            offenders.append({
                "pid": pid, "start_time": before, "reasons": sorted(set(reasons)),
                "cmdline_sha256": hashlib.sha256(cmdline).hexdigest(),
                "cgroup_sha256": hashlib.sha256(cgroup).hexdigest(), "cwd": cwd,
                "executable": executable, "descriptors": descriptors,
            })
    return {"identities": identities, "offenders": offenders}


def _global_legacy_census(context=None, provisioning=False):
    if provisioning != (context is None):
        raise NftOwnerError("exact provisioning census mode required")
    boot_before = _boot_id()
    first = {"boot_id": boot_before, "source": _source_census(),
             "journal": _journal_census(context, provisioning),
             "cgroup": _cgroup_census(), "processes": _process_census()}
    second = {"boot_id": _boot_id(), "source": _source_census(),
              "journal": _journal_census(context, provisioning),
              "cgroup": _cgroup_census(), "processes": _process_census()}
    if first != second:
        raise NftOwnerError("fresh global legacy census changed")
    if first["cgroup"]["present"] or first["processes"]["offenders"]:
        raise NftOwnerError("global legacy process/cgroup census is not empty")
    return _digest(first)


def _legacy_fence(context, history, boot_id, host_netns):
    legacy = [row for row in history["intents"] if row["command_id"] == "NFT_REMOVE_ATOMIC"
              and row["inherited_fds"] == []]
    if legacy:
        raise NftOwnerError("legacy pending NFT deletion journal is fenced")
    census = _global_legacy_census(context)
    return _digest({
        "operation_token": context.operation_token, "journal_tip": history["terminal_sha256"],
        "source_revision": context.source_revision, "boot_id": boot_id,
        "host_netns": host_netns, "global_census_sha256": census,
    })


@dataclass
class _OwnerState:
    journal: object
    descriptors: list
    parent: int
    parent_identity: tuple
    lock_fd: int
    lock_identity: fdmap.FdIdentity
    active: dict
    child_binding_issued: bool = False


_OWNERS = {}


def _close_proven(descriptor, label):
    try:
        os.close(descriptor)
    except OSError as error:
        raise NftOwnerError(f"{label} close uncertainty:{error.errno}") from error
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno == errno.EBADF:
            return
        raise NftOwnerError(f"{label} absence proof unavailable:{error.errno}") from error
    raise NftOwnerError(f"{label} descriptor remains open")


def _ofd_lock_present(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "r", encoding="ascii") as source:
        raw = source.read(4097)
    locks = [line.split(":\t", 1)[1] for line in raw.splitlines()
             if line.startswith("lock:\t")]
    return (len(raw) <= 4096 and raw.endswith("\n") and len(locks) == 1
            and "OFDLCK ADVISORY  WRITE -1" in locks[0]
            and locks[0].endswith(" 0 EOF"))


def _require_owner(journal):
    context, _history, binding, genesis = _journal_bindings(journal)
    owner = _OWNERS.get(context.operation_token)
    if (owner is None or owner.active["journal_binding_sha256"] != binding
            or owner.active["journal_genesis_sha256"] != genesis):
        raise NftOwnerError("live NFT writer owner required; recovery cannot launch deletion")
    owner.journal = journal
    parent = os.fstat(owner.parent)
    current_descriptors, _current_parent, current_identity = _open_parent()
    try:
        if (current_identity != owner.parent_identity
                or (parent.st_dev, parent.st_ino, parent.st_mode,
                    parent.st_uid, parent.st_gid) != owner.parent_identity):
            raise NftOwnerError("NFT owner parent changed")
    finally:
        for descriptor in reversed(current_descriptors):
            os.close(descriptor)
    if (fdmap.identity(owner.lock_fd) != owner.lock_identity
            or not _ofd_lock_present(owner.lock_fd)):
        raise NftOwnerError("retained NFT lock changed")
    state = _read_state(owner.parent)
    if state != owner.active or state["phase"] != "ACTIVE":
        raise NftOwnerError("durable NFT owner state changed")
    if (state["host_boot_id"] != _boot_id() or state["host_netns"] != _host_netns()):
        raise NftOwnerError("NFT owner boot/netns mismatch")
    return owner


def acquire(journal):
    context, history, binding, genesis = _journal_bindings(journal)
    if context.operation_token in _OWNERS:
        return _require_owner(journal)
    descriptors, parent, parent_identity = _open_parent()
    lock_fd = None
    try:
        lock_fd, lock_identity = _open_lock(parent)
        free = _read_state(parent)
        boot_id, host_netns = _boot_id(), _host_netns()
        locked_context, locked_history, locked_binding, locked_genesis = _journal_bindings(journal)
        if (locked_context != context or locked_binding != binding or locked_genesis != genesis
                or locked_history["terminal_sha256"] != history["terminal_sha256"]):
            raise NftOwnerError("operation changed during NFT gate admission")
        context, history, binding, genesis = (
            locked_context, locked_history, locked_binding, locked_genesis)
        if free["phase"] != "FREE":
            raise NftOwnerError("NFT state is not FREE")
        if free["host_boot_id"] != boot_id or free["host_netns"] != host_netns:
            raise NftOwnerError("FREE NFT state boot/netns mismatch")
        if context.host_boot_id != boot_id:
            raise NftOwnerError("operation boot binding mismatch")
        fence = _legacy_fence(context, history, boot_id, host_netns)
        active = _state("ACTIVE", free["sequence"] + 1, context.operation_token,
                        binding, genesis, boot_id, host_netns, free["record_sha256"],
                        ZERO, ZERO, fence)
        _replace_state(parent, active)
        owner = _OwnerState(journal, descriptors, parent, parent_identity,
                            lock_fd, lock_identity, active)
        _OWNERS[context.operation_token] = owner
        return owner
    except BaseException:
        if lock_fd is not None:
            try: os.close(lock_fd)
            except OSError: pass
        for descriptor in reversed(descriptors):
            try: os.close(descriptor)
            except OSError: pass
        raise


def require_active(journal):
    return _require_owner(journal)


def claim_child_binding(journal):
    owner = _require_owner(journal)
    if owner.child_binding_issued:
        raise NftOwnerError("NFT deletion binding was already issued")
    owner.child_binding_issued = True
    return fdmap._claim_nft_writer_lock(owner.lock_fd, owner.lock_identity,
                                        owner.active["operation_token"])


def _successful_delete(history):
    intents = [row for row in history["intents"] if row["command_id"] == "NFT_REMOVE_ATOMIC"]
    if len(intents) != 1:
        raise NftOwnerError("unique NFT deletion intent required")
    intent = intents[0]
    inherited = intent["inherited_fds"]
    if (len(inherited) != 1 or inherited[0]["role"] != LOCK_ROLE
            or inherited[0]["target_fd"] != LOCK_TARGET_FD
            or inherited[0]["content_length"] != 0
            or inherited[0]["content_sha256"] != hashlib.sha256(b"").hexdigest()):
        raise NftOwnerError("NFT deletion lock evidence missing")
    outcomes = [row for row in history["outcomes"]
                if row["command_serial"] == intent["command_serial"]]
    if len(outcomes) != 1:
        raise NftOwnerError("unique NFT deletion outcome required")
    outcome = outcomes[0]
    required = (outcome.get("command_id", "NFT_REMOVE_ATOMIC") == "NFT_REMOVE_ATOMIC"
                and outcome.get("binding_sha256", intent["binding_sha256"]) == intent["binding_sha256"]
                and outcome["outcome"] == "exited" and outcome["status"] == 0
                and not outcome["uncertain"] and outcome["release_count"] == 1
                and outcome["leader_reaped"] and outcome["descendants_reaped"]
                and outcome["cgroup_empty"] and outcome["cgroup_removed"]
                and outcome["pipes_eof"] and not outcome["errors"]
                and outcome["stdout_length"] == 0
                and outcome["stdout_sha256"] == hashlib.sha256(b"").hexdigest()
                and outcome["stderr_length"] == 0 and not outcome["stdout_truncated"]
                and not outcome["stderr_truncated"])
    if not required:
        raise NftOwnerError("NFT deletion process settlement incomplete")
    preexecs = [row for row in history.get("preexecs", ())
                if row["command_serial"] == intent["command_serial"]]
    if len(preexecs) != 1 or os.path.lexists(preexecs[0]["cgroup_path"]):
        raise NftOwnerError("NFT deletion cgroup remains")
    try:
        import completion_kata_process as process
        current = process._proc_row(preexecs[0]["pid"])
        if current[4] == preexecs[0]["proc_start_time"]:
            raise NftOwnerError("NFT deletion child remains")
    except FileNotFoundError:
        pass
    return intent, outcome


def _cleanup_command_evidence(owner, history, cleanup_target):
    removals = [row for row in history["intents"]
                if row["command_id"] == "NFT_REMOVE_ATOMIC"]
    if removals:
        intent, outcome = _successful_delete(history)
        return _digest({
            "binding_sha256": intent["binding_sha256"],
            "command_serial": intent["command_serial"], "outcome": outcome,
            "cleanup_target": cleanup_target,
        })
    nft_mutations = [row for row in history["intents"] if row["command_id"] in {
        "NFT_INSTALL", "NFT_INSTALL_OWNED", "NFT_REMOVE", "NFT_REMOVE_ATOMIC"}]
    if cleanup_target != "network" or nft_mutations or owner.child_binding_issued:
        raise NftOwnerError("successful NFT deletion evidence required")
    return _digest({"cleanup_target": cleanup_target, "nft_mutations": [],
                    "deletion_binding_issued": False})


def settle_free(journal, cleanup_target):
    owner = _require_owner(journal)
    if cleanup_target not in {"network", "firewall"}:
        raise NftOwnerError("fixed NFT cleanup target required")
    context, history, binding, genesis = _journal_bindings(journal)
    if (binding != owner.active["journal_binding_sha256"]
            or genesis != owner.active["journal_genesis_sha256"]
            or context.operation_token != owner.active["operation_token"]):
        raise NftOwnerError("NFT cleanup journal binding changed")
    expected_phase = "NETWORK_ABSENT" if cleanup_target == "network" else "FIREWALL_ABSENT"
    if history["phase"] != expected_phase or history["tip"] not in {
            "NETWORK_CLEANUP_SETTLED_V2", "FIREWALL_CLEANUP_SETTLED_V2"}:
        raise NftOwnerError("durable NFT cleanup settlement absent")
    command = _cleanup_command_evidence(owner, history, cleanup_target)
    cleanup = _digest({
        "journal_terminal_sha256": history["terminal_sha256"], "phase": history["phase"],
        "tip": history["tip"], "command_binding_sha256": command,
    })
    releasing = _state("RELEASING", owner.active["sequence"] + 1,
                       context.operation_token, binding, genesis, _boot_id(), _host_netns(),
                       owner.active["record_sha256"], cleanup, command,
                       owner.active["legacy_fence_sha256"])
    _replace_state(owner.parent, releasing)
    retained_lock = owner.lock_fd
    owner.lock_fd = -1
    _close_proven(retained_lock, "retained NFT writer lock")
    probe, probe_identity = _open_lock(owner.parent)
    if probe_identity != owner.lock_identity:
        try: os.close(probe)
        except OSError: pass
        raise NftOwnerError("NFT writer lock changed during absence proof")
    _close_proven(probe, "NFT writer lock absence probe")
    free = _state("FREE", releasing["sequence"] + 1, context.operation_token,
                  binding, genesis, releasing["host_boot_id"], releasing["host_netns"],
                  releasing["record_sha256"], cleanup, command,
                  releasing["legacy_fence_sha256"])
    _replace_state(owner.parent, free)
    owner.active = free
    _OWNERS.pop(context.operation_token, None)
    for descriptor in reversed(owner.descriptors):
        try: os.close(descriptor)
        except OSError:
            # Directory descriptors convey no writer authority. FREE was made
            # durable only after both writer-lock OFDs were proven absent.
            pass
    return free


def provision_initial_free():
    """Perform the trusted, zero-input, one-time fresh-host provisioning."""
    if os.geteuid() != 0 or os.path.dirname(OWNER_DIR) != "/var/lib" or not re.fullmatch(
            r"[A-Za-z0-9._-]+", os.path.basename(OWNER_DIR)):
        raise NftOwnerError("fixed root provisioning path required")
    fence = _global_legacy_census(provisioning=True)
    parent_descriptors = []
    try:
        for path in ("/", "/var", "/var/lib"):
            descriptor, _identity = _directory(path)
            parent_descriptors.append(descriptor)
        varlib = parent_descriptors[-1]
        previous = os.umask(0o077)
        try:
            os.mkdir(os.path.basename(OWNER_DIR), 0o700, dir_fd=varlib)
        finally:
            if os.umask(previous) != 0o077:
                raise NftOwnerError("provisioning umask changed")
        os.fsync(varlib)
        descriptors, parent, _identity = _open_parent()
        parent_descriptors.extend(descriptors)
        lock = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                       os.O_CLOEXEC, 0o600, dir_fd=parent)
        try:
            _regular_identity(lock, 0o600)
            os.fsync(lock)
        finally:
            _close_proven(lock, "provisioned NFT lock")
        os.fsync(parent)
        value = _state("FREE", 0, ZERO, ZERO, ZERO, _boot_id(), _host_netns(), ZERO,
                       _digest({"initial": "provisioned", "global_census_sha256": fence}),
                       _digest({"initial": "no-command"}), fence)
        _replace_state(parent, value)
        return value
    except FileExistsError as error:
        raise NftOwnerError("NFT owner is already provisioned or nonclean") from error
    except BaseException:
        # A partial directory is intentionally retained as nonclean. Admission
        # never treats a missing state as FREE.
        raise
    finally:
        for descriptor in reversed(parent_descriptors):
            try: os.close(descriptor)
            except OSError: pass


def initial_free_for_tests(legacy_fence_sha256, boot_id=None, host_netns=None):
    """Return bytes for explicit test fixtures; it performs no I/O."""
    if not _hex(legacy_fence_sha256):
        raise NftOwnerError("explicit legacy fence proof required")
    value = _state("FREE", 0, ZERO, ZERO, ZERO, boot_id or _boot_id(),
                   host_netns or _host_netns(), ZERO, _digest({"initial": "provisioned"}),
                   _digest({"initial": "no-command"}), legacy_fence_sha256)
    return _canonical(value)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 1:
        raise SystemExit(64)
    try:
        provision_initial_free()
    except (NftOwnerError, OSError, ValueError):
        raise SystemExit(2) from None
