"""Closed Kata runtime/spec/process/share-state model for Stage 2.

This module never executes a command and never reads ``/proc`` or the Kata
share directory.  It constructs fixed command specifications and classifies
bounded snapshots supplied by an eventual trusted issuer.  The committed fake
snapshots are explicitly unqualified; consequently no production owner can be
opened by this slice.
"""
from dataclasses import dataclass
from enum import Enum
import copy
import hashlib
import json
import re
import completion_kata_actions as actions

BASE = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1"
INPUT_SHARE = BASE + "/kata-input-v1/share"
ROOTFS_CANDIDATE = BASE + "/rootfs-v1/" + "b" * 64 + "/rootfs"
NAMESPACE = "cogs-stage2-completion-v1"
CONTAINER_ID = SANDBOX_ID = "cogs-stage2-ssh-v1"
RUNTIME = "io.containerd.kata.v2"
RUNTIME_CONFIG = "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml"
NETNS_PATH = "/run/netns/cogs-stage2-ssh"
SHARE_ROOT = "/run/kata-containers/shared/sandboxes/cogs-stage2-ssh-v1"
CONTAINERD_VERSION = "2.2.1"
OCI_VERSION = "1.3.0"
QUALIFICATION_CANDIDATE = "UNQUALIFIED_OFFLINE_FAKE_CONTAINERD_KATA_S4_V1"
MAX_JSON = 1_048_576
MAX_JSON_DEPTH = 24
MAX_JSON_ITEMS = 512
MAX_PROC_ROWS = 4096
MAX_CMDLINE = 16_384
MAX_MOUNTINFO = 4_194_304
MAX_MOUNT_LINES = 4096
MAX_SHARE_PER_DIRECTORY = 64
MAX_SHARE_DEPTH = 4
MAX_SHARE_TOTAL = 256
HEX = frozenset("0123456789abcdef")
BOOTSTRAP = b"""set -eu
umask 077
/bin/mkdir -p /run/sshd /run/cogs-stage2-ssh/work
/bin/chown 0:0 /run/sshd /run/cogs-stage2-ssh/work
/bin/chmod 0755 /run/sshd
/bin/chmod 0700 /run/cogs-stage2-ssh/work
[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- /run/sshd)" = "0:0:755:directory" ]
[ "$(/usr/bin/stat -c '%u:%g:%a:%F' -- /run/cogs-stage2-ssh/work)" = "0:0:700:directory" ]
[ ! -e /run/cogs-stage2-ssh/sshd.pid ]
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
"""


class KataRuntimeError(Exception):
    """A fixed runtime contract or ownership observation was not exact."""


# Kept as an alias for the already published S1 API.
KataMountContractError = KataRuntimeError


@dataclass(frozen=True)
class MountRecord:
    type: str
    source: str
    destination: str
    options: tuple[str, ...]


@dataclass(frozen=True)
class CommandSpec:
    command_id: actions.CommandId
    argv: tuple[str, ...]
    stdin: bytes
    deadline_class: str


class Observation(Enum):
    ABSENT = "absent"
    EXACT = "exact"
    PRESERVE = "preserve"


@dataclass(frozen=True)
class ProcessRecord:
    role: str
    pid: int
    ppid: int
    starttime: int
    executable: str
    executable_device: int
    executable_inode: int
    cmdline: tuple[str, ...]
    namespaces: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ProcessClassification:
    disposition: Observation
    records: tuple[ProcessRecord, ...]
    reason: str


@dataclass(frozen=True)
class ShareEntry:
    path: str
    kind: str
    device: int
    inode: int
    mount_id: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class ShareClassification:
    disposition: Observation
    entries: tuple[ShareEntry, ...]
    mountpoints: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class RuntimeSnapshot:
    owned: bool
    container: Observation
    task: str
    processes: Observation
    network: Observation
    share: Observation
    mount_baseline: Observation
    firewall: Observation
    readiness_revoked: bool = False
    term_attempted: bool = False
    kill_permitted: bool = False


class TeardownAction(Enum):
    PRESERVE = "PRESERVE"
    COMPLETE = "COMPLETE"
    REVOKE_READINESS = "REVOKE_READINESS"
    OBSERVE_TASK = "OBSERVE_TASK"
    TASK_TERM = "CTR_TASK_TERM"
    TASK_KILL = "CTR_TASK_KILL"
    REMOVE_NETWORK = "REMOVE_NETWORK"
    TASK_REMOVE = "CTR_TASK_REMOVE"
    CONTAINER_REMOVE = "CTR_CONTAINER_REMOVE"
    OBSERVE_PROCESSES = "OBSERVE_PROCESSES"
    OBSERVE_SHARE = "OBSERVE_SHARE"
    REMOVE_FIREWALL = "REMOVE_FIREWALL"


def _fail(condition, message="runtime contract"):
    if not condition:
        raise KataRuntimeError(message)


def _make_mount_contract():
    mounts = (
        ("proc", "proc", "/proc", ("nosuid", "noexec", "nodev")),
        ("tmpfs", "tmpfs", "/dev", ("nosuid", "strictatime", "mode=755", "size=65536k")),
        ("devpts", "devpts", "/dev/pts", ("nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5")),
        ("tmpfs", "shm", "/dev/shm", ("nosuid", "noexec", "nodev", "mode=1777", "size=65536k")),
        ("mqueue", "mqueue", "/dev/mqueue", ("nosuid", "noexec", "nodev")),
        ("sysfs", "sysfs", "/sys", ("nosuid", "noexec", "nodev", "ro")),
        ("tmpfs", "tmpfs", "/run", ("nosuid", "strictatime", "mode=755", "size=65536k")),
        ("tmpfs", "tmpfs", "/run/cogs-stage2-ssh", ("rw", "nosuid", "nodev", "noexec", "mode=0700", "size=67108864", "nr_inodes=16384")),
        ("bind", INPUT_SHARE + "/ssh_host_ed25519_key", "/run/cogs-stage2-ssh/ssh_host_ed25519_key", ("bind", "ro", "nosuid", "nodev", "noexec", "private")),
        ("bind", INPUT_SHARE + "/authorized_keys", "/run/cogs-stage2-ssh/authorized_keys", ("bind", "ro", "nosuid", "nodev", "noexec", "private")),
        ("bind", INPUT_SHARE + "/fixture", "/run/cogs-stage2-ssh/input", ("bind", "ro", "nosuid", "nodev", "noexec", "private")),
    )
    dumps = json.dumps

    def canonical_mount_json():
        value = [{"destination": dst, "options": list(options), "source": src, "type": type_}
                 for type_, src, dst, options in mounts]
        return dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode() + b"\n"

    digest = hashlib.sha256(canonical_mount_json()).hexdigest()

    def validate_stored_spec(stored_spec):
        _fail(type(stored_spec) is dict and all(type(key) is str for key in stored_spec) and "mounts" in stored_spec)
        rows = stored_spec["mounts"]
        _fail(type(rows) is list and len(rows) == len(mounts))
        for row, expected in zip(rows, mounts, strict=True):
            type_, source, destination, options = expected
            _fail(type(row) is dict and set(row) == {"destination", "options", "source", "type"})
            _fail(all(type(key) is str for key in row))
            _fail(type(row["type"]) is str and row["type"] == type_)
            _fail(type(row["source"]) is str and row["source"] == source)
            _fail(type(row["destination"]) is str and row["destination"] == destination)
            _fail(type(row["options"]) is list and all(type(item) is str for item in row["options"]))
            _fail(tuple(row["options"]) == options)
        return digest

    def custom_mount_argv():
        result = []
        for type_, source, destination, options in mounts[7:]:
            fields = (type_, source, destination, *options)
            _fail(all(type(item) is str and item.isascii() and item.isprintable() for item in fields))
            _fail(all("," not in item for item in fields) and all(":" not in item for item in options))
            result.extend(("--mount", f"type={type_},src={source},dst={destination},options={':'.join(options)}"))
        return tuple(result)

    snapshots = tuple(MountRecord(type_, source, destination, options)
                      for type_, source, destination, options in mounts)
    return snapshots, digest, canonical_mount_json, validate_stored_spec, custom_mount_argv


(CANONICAL_MOUNTS, MOUNT_LIST_SHA256, canonical_mount_json,
 validate_stored_spec, custom_mount_argv) = _make_mount_contract()
del _make_mount_contract


# Registry-backed, one-shot test capability.  It cannot be constructed from a
# root path, input digest, netns name, or caller boolean.
def _permit_routes():
    seal = object()
    states = {}

    class _LaunchPermit:
        __slots__ = ()
        def __new__(cls, key=None):
            _fail(key is seal, "sealed launch permit")
            return super().__new__(cls)

    def candidate():
        permit = _LaunchPermit(seal)
        states[permit] = {
            "root": ROOTFS_CANDIDATE, "mount": MOUNT_LIST_SHA256,
            "input": "1" * 64, "network": NETNS_PATH, "used": False,
            "qualification": QUALIFICATION_CANDIDATE,
        }
        return permit

    def claim(permit):
        state = states.get(permit)
        _fail(type(permit) is _LaunchPermit and state is not None and not state["used"],
              "operation-owned root/input/network permit required")
        _fail(state["qualification"] == QUALIFICATION_CANDIDATE,
              "unqualified candidate invariant")
        state["used"] = True
        return dict(state)

    return candidate, claim


_make_fake_launch_permit_for_tests, _claim_launch_permit = _permit_routes()
del _permit_routes


def _open_production_owner():
    """Fail closed until operation/root/input/network and tool issuers exist."""
    raise KataRuntimeError("production runtime owner is unavailable: issuers unqualified")


def ctr_run_spec(permit):
    """Consume the one operation-owned candidate bundle and return fixed bytes."""
    state = _claim_launch_permit(permit)
    _fail(state["mount"] == MOUNT_LIST_SHA256 and state["network"] == NETNS_PATH)
    argv = (
        "/usr/bin/ctr", "--namespace", NAMESPACE, "run",
        "--runtime", RUNTIME, "--runtime-config-path", RUNTIME_CONFIG,
        "--rootfs", "--read-only", "--detach",
        "--with-ns", "network:" + NETNS_PATH,
        *custom_mount_argv(), state["root"], CONTAINER_ID,
        "/bin/sh", "-c", BOOTSTRAP.decode("ascii"),
    )
    return CommandSpec(actions.CommandId.CTR_RUN, argv, b"", "runtime-start")


def fixed_command_specs_for_tests():
    """Exact observer and non-force teardown argv; specifications only."""
    ctr = "/usr/bin/ctr"
    prefix = (ctr, "--namespace", NAMESPACE)
    rows = (
        (actions.CommandId.CTR_CONTAINER_INFO, prefix + ("containers", "info", CONTAINER_ID), "observer"),
        (actions.CommandId.CTR_CONTAINER_LIST, prefix + ("containers", "list"), "observer"),
        (actions.CommandId.CTR_TASK_LIST, prefix + ("tasks", "list"), "observer"),
        (actions.CommandId.CTR_TASK_TERM, prefix + ("tasks", "kill", "--signal", "SIGTERM", CONTAINER_ID), "task-term"),
        (actions.CommandId.CTR_TASK_KILL, prefix + ("tasks", "kill", "--signal", "SIGKILL", CONTAINER_ID), "task-kill"),
        (actions.CommandId.CTR_TASK_REMOVE, prefix + ("tasks", "rm", CONTAINER_ID), "remove"),
        (actions.CommandId.CTR_CONTAINER_REMOVE, prefix + ("containers", "rm", CONTAINER_ID), "remove"),
    )
    return tuple(CommandSpec(command, argv, b"", deadline) for command, argv, deadline in rows)


_CAPABILITIES = (
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD",
    "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
)
_MASKED = (
    "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
    "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware", "/proc/scsi",
)
_READONLY = (
    "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
)


def expected_oci_spec():
    """Return a fresh complete fixed OCI candidate, never mutable authority."""
    mounts = json.loads(canonical_mount_json())
    return {
        "ociVersion": OCI_VERSION,
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0, "additionalGids": []},
            "args": ["/bin/sh", "-c", BOOTSTRAP.decode("ascii")],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/",
            "capabilities": {name: list(_CAPABILITIES) for name in
                             ("bounding", "effective", "inheritable", "permitted", "ambient")},
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
            "noNewPrivileges": False,
        },
        "root": {"path": "rootfs", "readonly": True},
        "hostname": CONTAINER_ID,
        "mounts": mounts,
        "annotations": {},
        "linux": {
            "resources": {"devices": [{"allow": False, "access": "rwm"}]},
            "namespaces": [
                {"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
                {"type": "network", "path": NETNS_PATH},
            ],
            "maskedPaths": list(_MASKED),
            "readonlyPaths": list(_READONLY),
        },
    }


def _exact_scalar_tree(value, depth=0):
    _fail(depth <= MAX_JSON_DEPTH, "JSON depth")
    if type(value) is dict:
        _fail(len(value) <= MAX_JSON_ITEMS and all(type(key) is str for key in value), "JSON object")
        for child in value.values():
            _exact_scalar_tree(child, depth + 1)
    elif type(value) is list:
        _fail(len(value) <= MAX_JSON_ITEMS, "JSON array")
        for child in value:
            _exact_scalar_tree(child, depth + 1)
    else:
        _fail(value is None or type(value) in (str, int, bool), "JSON scalar")


class _Pairs(list):
    pass


def _load_json(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_JSON and b"\x00" not in raw, "bounded JSON")
    try:
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_Pairs,
                            parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        def convert(value, depth=0):
            _fail(depth <= MAX_JSON_DEPTH, "JSON depth")
            if type(value) is _Pairs:
                _fail(len(value) <= MAX_JSON_ITEMS, "JSON object bound")
                result = {}
                for key, child in value:
                    _fail(type(key) is str and key not in result, "duplicate JSON key")
                    result[key] = convert(child, depth + 1)
                return result
            if type(value) is list:
                _fail(len(value) <= MAX_JSON_ITEMS, "JSON array bound")
                return [convert(child, depth + 1) for child in value]
            _fail(value is None or type(value) in (str, int, bool), "JSON scalar")
            return value
        return convert(parsed)
    except KataRuntimeError:
        raise
    except BaseException as error:
        raise KataRuntimeError("invalid JSON") from error


def _keys(value, required, optional=()):
    _fail(type(value) is dict and set(value) == set(required) | set(optional), "stored schema")
    _fail(all(type(key) is str for key in value), "stored key type")


def _timestamp(value):
    _fail(type(value) is str and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", value) is not None,
        "timestamp")


def validate_stored_info(raw_or_value):
    """Validate the exact containerd 2.2.1 info candidate and complete spec."""
    value = _load_json(raw_or_value) if type(raw_or_value) is bytes else raw_or_value
    _exact_scalar_tree(value)
    _keys(value, ("ID", "Labels", "Image", "Runtime", "SnapshotKey", "Snapshotter",
                  "CreatedAt", "UpdatedAt", "Extensions", "Spec"))
    _fail(value["ID"] == CONTAINER_ID and value["Image"] == "" and value["Labels"] == {})
    _fail(value["SnapshotKey"] == "" and value["Snapshotter"] == "" and value["Extensions"] == {})
    _timestamp(value["CreatedAt"]); _timestamp(value["UpdatedAt"])
    runtime = value["Runtime"]
    _keys(runtime, ("Name", "Options"))
    _fail(runtime["Name"] == RUNTIME)
    _fail(runtime["Options"] == {
        "type_url": "io.containerd.kata.v2.options",
        "config_path": RUNTIME_CONFIG,
    }, "runtime options/config")
    spec = value["Spec"]
    _fail(type(spec) is dict and spec == expected_oci_spec(), "complete OCI spec drift")
    return validate_stored_spec(spec)


def parse_container_list(raw):
    """Parse the complete fixed-width ctr 2.2.1 container list output."""
    _fail(type(raw) is bytes and 0 < len(raw) <= 65_536 and raw.endswith(b"\n") and b"\x00" not in raw)
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeError as error:
        raise KataRuntimeError("container list encoding") from error
    _fail(lines and re.fullmatch(r"CONTAINER\s+IMAGE\s+RUNTIME", lines[0]) is not None)
    rows = []
    for line in lines[1:]:
        fields = line.split()
        _fail(len(fields) == 3 and all(field.isascii() and field.isprintable() for field in fields))
        rows.append(tuple(fields))
    _fail(len(rows) <= 64 and len(rows) == len(set(rows)), "container list bound/duplicate")
    return tuple(rows)


def classify_container_list(raw):
    rows = parse_container_list(raw)
    matches = [row for row in rows if row[0] == CONTAINER_ID]
    if not matches:
        return Observation.ABSENT
    if len(matches) != 1 or matches[0] != (CONTAINER_ID, "-", RUNTIME):
        return Observation.PRESERVE
    return Observation.EXACT


def parse_task_list(raw):
    """Parse exact ctr task rows; PID and status alone never grant ownership."""
    _fail(type(raw) is bytes and 0 < len(raw) <= 65_536 and raw.endswith(b"\n") and b"\x00" not in raw)
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeError as error:
        raise KataRuntimeError("task list encoding") from error
    _fail(lines and re.fullmatch(r"TASK\s+PID\s+STATUS", lines[0]) is not None)
    rows = []
    for line in lines[1:]:
        fields = line.split()
        _fail(len(fields) == 3 and fields[1].isdigit())
        pid = int(fields[1]); status = fields[2]
        _fail(0 < pid < (1 << 31) and status in {"RUNNING", "STOPPED", "PAUSED", "PAUSING", "UNKNOWN"})
        rows.append((fields[0], pid, status))
    _fail(len(rows) <= 64 and len(rows) == len(set(rows)), "task list bound/duplicate")
    return tuple(rows)


def classify_task_list(raw, expected_pid=None):
    _fail(expected_pid is None or type(expected_pid) is int and 0 < expected_pid < (1 << 31))
    matches = [row for row in parse_task_list(raw) if row[0] == CONTAINER_ID]
    if not matches:
        return "absent"
    if len(matches) != 1 or expected_pid is None or matches[0][1] != expected_pid:
        return "preserve"
    return matches[0][2].lower()


def unqualified_stored_info_fixture_for_tests():
    value = {
        "ID": CONTAINER_ID, "Labels": {}, "Image": "", "Runtime": {
            "Name": RUNTIME, "Options": {
                "type_url": "io.containerd.kata.v2.options", "config_path": RUNTIME_CONFIG,
            },
        },
        "SnapshotKey": "", "Snapshotter": "",
        "CreatedAt": "2026-07-24T00:00:00Z", "UpdatedAt": "2026-07-24T00:00:01Z",
        "Extensions": {}, "Spec": expected_oci_spec(),
    }
    return {"qualification": QUALIFICATION_CANDIDATE, "value": value}


def _uint(value, minimum=0, maximum=(1 << 63) - 1):
    _fail(type(value) is int and minimum <= value <= maximum, "unsigned integer")
    return value


def _path(value):
    _fail(type(value) is str and value.startswith("/") and "//" not in value and "\x00" not in value)
    _fail(all(part not in {".", ".."} for part in value.split("/")[1:]), "absolute path")
    return value


def _proc_record(row):
    _keys(row, ("role", "pid", "ppid", "starttime", "executable", "executable_device",
                "executable_inode", "cmdline", "namespaces"))
    role = row["role"]
    _fail(type(role) is str and role in {"shim", "qemu", "virtiofsd", "other"})
    pid = _uint(row["pid"], 1, (1 << 31) - 1)
    ppid = _uint(row["ppid"], 0, (1 << 31) - 1)
    starttime = _uint(row["starttime"], 1)
    executable = _path(row["executable"])
    device = _uint(row["executable_device"]); inode = _uint(row["executable_inode"], 1)
    command = row["cmdline"]
    _fail(type(command) is list and 1 <= len(command) <= 256 and
          all(type(item) is str and item and "\x00" not in item and len(item.encode()) <= MAX_CMDLINE for item in command))
    _fail(sum(len(item.encode()) + 1 for item in command) <= MAX_CMDLINE)
    namespaces = row["namespaces"]
    expected_ns = ("ipc", "mnt", "net", "pid", "user", "uts")
    _fail(type(namespaces) is dict and tuple(sorted(namespaces)) == expected_ns)
    for name, identity in namespaces.items():
        _fail(type(name) is str and type(identity) is str and
              re.fullmatch(rf"{name}:\[[1-9][0-9]*\]", identity) is not None, "namespace identity")
    return ProcessRecord(role, pid, ppid, starttime, executable, device, inode,
                         tuple(command), tuple(sorted(namespaces.items())))


def classify_process_snapshot(snapshot, baseline=()):
    """Classify a complete, bounded offline /proc enumeration.

    Early exit, duplicate roles, replacement, uncertain ancestry, or namespace
    drift is ``PRESERVE`` rather than absence.  ``baseline`` contains exact
    process identities observed before launch and may not disappear/reappear as
    one of the owned roles.
    """
    _fail(type(snapshot) is dict and set(snapshot) == {"complete", "early_exit", "rows", "qualification"})
    _fail(snapshot["qualification"] == QUALIFICATION_CANDIDATE, "unqualified fixture marker")
    _fail(type(snapshot["complete"]) is bool and type(snapshot["early_exit"]) is bool)
    rows = snapshot["rows"]
    _fail(type(rows) is list and len(rows) <= MAX_PROC_ROWS)
    records = tuple(_proc_record(row) for row in rows)
    _fail(len({record.pid for record in records}) == len(records), "duplicate PID")
    _fail(type(baseline) is tuple and all(type(item) is ProcessRecord for item in baseline))
    if not snapshot["complete"] or snapshot["early_exit"]:
        return ProcessClassification(Observation.PRESERVE, records, "incomplete-or-early-exit")
    exact_exec = {
        "shim": "/opt/kata/bin/containerd-shim-kata-v2",
        "qemu": "/opt/kata/bin/qemu-system-x86_64",
        "virtiofsd": "/opt/kata/libexec/virtiofsd",
    }
    derived = {path: role for role, path in exact_exec.items()}
    suspicious = tuple(item for item in records if
                       (item.executable in derived and item.role != derived[item.executable]) or
                       (item.role != "other" and item.executable != exact_exec[item.role]) or
                       (item.role == "other" and SANDBOX_ID in item.cmdline))
    if suspicious:
        return ProcessClassification(Observation.PRESERVE, suspicious, "role-derivation")
    owned = tuple(item for item in records if item.role != "other")
    if not owned:
        return ProcessClassification(Observation.ABSENT, (), "complete-absence")
    by_role = {role: tuple(item for item in owned if item.role == role)
               for role in ("shim", "qemu", "virtiofsd")}
    if any(len(by_role[role]) != 1 for role in by_role):
        return ProcessClassification(Observation.PRESERVE, owned, "role-cardinality")
    shim, qemu, virtiofsd = by_role["shim"][0], by_role["qemu"][0], by_role["virtiofsd"][0]
    if any(item.executable != exact_exec[item.role] or item.cmdline[0] != item.executable
           or SANDBOX_ID not in item.cmdline for item in owned):
        return ProcessClassification(Observation.PRESERVE, owned, "executable-or-cmdline")
    if qemu.ppid != shim.pid or virtiofsd.ppid != shim.pid or not (
            shim.starttime <= qemu.starttime and shim.starttime <= virtiofsd.starttime):
        return ProcessClassification(Observation.PRESERVE, owned, "ancestry-or-starttime")
    ns = {item.role: dict(item.namespaces) for item in owned}
    if ns["qemu"]["net"] != ns["shim"]["net"] or ns["virtiofsd"]["mnt"] != ns["shim"]["mnt"]:
        return ProcessClassification(Observation.PRESERVE, owned, "namespace-correlation")
    baseline_ids = {(item.pid, item.starttime, item.executable_device, item.executable_inode) for item in baseline}
    if any((item.pid, item.starttime, item.executable_device, item.executable_inode) in baseline_ids for item in owned):
        return ProcessClassification(Observation.PRESERVE, owned, "baseline-collision")
    return ProcessClassification(Observation.EXACT, owned, "exact-owned-runtime")


def _mount_unescape(raw):
    output = bytearray(); index = 0
    while index < len(raw):
        if raw[index:index + 1] == b"\\":
            _fail(index + 4 <= len(raw) and raw[index + 1:index + 4] in {b"040", b"011", b"012", b"134"},
                  "mount escape")
            output.append(int(raw[index + 1:index + 4], 8)); index += 4
        else:
            _fail(raw[index] not in {0, 10, 13}, "mount byte")
            output.append(raw[index]); index += 1
    try:
        return output.decode("utf-8", "strict")
    except UnicodeError as error:
        raise KataRuntimeError("mount encoding") from error


def parse_mountinfo(raw):
    """Parse all supplied mountinfo rows, rejecting truncation and duplicates."""
    _fail(type(raw) is bytes and 0 < len(raw) <= MAX_MOUNTINFO and raw.endswith(b"\n") and b"\x00" not in raw)
    lines = raw.splitlines()
    _fail(1 <= len(lines) <= MAX_MOUNT_LINES and all(0 < len(line) <= 16_384 for line in lines))
    result = []
    for line in lines:
        fields = line.split(b" "); _fail(fields.count(b"-") == 1)
        separator = fields.index(b"-")
        _fail(separator >= 6 and separator + 4 == len(fields), "mountinfo shape")
        _fail(fields[0].isdigit() and fields[1].isdigit() and b":" in fields[2])
        mount_id, parent_id = int(fields[0]), int(fields[1])
        major_minor = fields[2].split(b":")
        _fail(mount_id > 0 and parent_id > 0 and len(major_minor) == 2 and all(item.isdigit() for item in major_minor))
        root = _mount_unescape(fields[3]); point = _mount_unescape(fields[4])
        _path(root); _path(point)
        options = fields[5].decode("ascii", "strict").split(",")
        _fail(options and len(options) == len(set(options)) and all(options))
        optional = tuple(field.decode("ascii", "strict") for field in fields[6:separator])
        fs_type = fields[separator + 1].decode("ascii", "strict")
        source = _mount_unescape(fields[separator + 2])
        result.append((mount_id, parent_id, int(major_minor[0]), int(major_minor[1]),
                       root, point, tuple(options), optional, fs_type, source))
    _fail(len({row[0] for row in result}) == len(result) and
          len({row[5] for row in result}) == len(result), "duplicate mount")
    return tuple(result)


def _share_entry(row):
    _keys(row, ("path", "kind", "device", "inode", "mount_id", "mode", "uid", "gid", "nofollow"))
    path = row["path"]
    _fail(type(path) is str and (path == "." or not path.startswith("/") and
          all(part not in {"", ".", ".."} for part in path.split("/"))), "share relative path")
    _fail(row["nofollow"] is True, "nofollow proof")
    kind = row["kind"]
    _fail(type(kind) is str and kind in {"directory", "file"}, "share kind")
    mode = _uint(row["mode"], 0, 0o7777)
    return ShareEntry(path, kind, _uint(row["device"]), _uint(row["inode"], 1),
                      _uint(row["mount_id"], 1), mode, _uint(row["uid"]), _uint(row["gid"]))


def classify_share_snapshot(snapshot, mountinfo):
    """Classify only the deterministic Kata root; this grants no mutation."""
    _fail(type(snapshot) is dict and set(snapshot) == {"root", "complete", "rows", "qualification"})
    _fail(snapshot["root"] == SHARE_ROOT and snapshot["qualification"] == QUALIFICATION_CANDIDATE)
    _fail(type(snapshot["complete"]) is bool)
    rows = snapshot["rows"]
    _fail(type(rows) is list and len(rows) <= MAX_SHARE_TOTAL)
    entries = tuple(_share_entry(row) for row in rows)
    _fail(len({item.path for item in entries}) == len(entries), "duplicate share path")
    if not snapshot["complete"]:
        return ShareClassification(Observation.PRESERVE, entries, (), "incomplete-enumeration")
    if not entries:
        # Complete absence still requires complete mountinfo proving no mount at
        # or below the deterministic root.
        mounts = parse_mountinfo(mountinfo)
        nested = tuple(row[5] for row in mounts if row[5] == SHARE_ROOT or row[5].startswith(SHARE_ROOT + "/"))
        disposition = Observation.ABSENT if not nested else Observation.PRESERVE
        return ShareClassification(disposition, (), nested, "complete-absence" if not nested else "mounted-absent-root")
    root = tuple(item for item in entries if item.path == ".")
    if len(root) != 1 or root[0].kind != "directory":
        return ShareClassification(Observation.PRESERVE, entries, (), "root-identity")
    counts = {}
    paths = {item.path: item for item in entries}
    for item in entries:
        depth = 0 if item.path == "." else len(item.path.split("/"))
        if depth > MAX_SHARE_DEPTH:
            return ShareClassification(Observation.PRESERVE, entries, (), "depth-bound")
        parent = "." if depth <= 1 else item.path.rpartition("/")[0]
        if item.path != "." and (parent not in paths or paths[parent].kind != "directory"):
            return ShareClassification(Observation.PRESERVE, entries, (), "missing-parent")
        counts[parent] = counts.get(parent, 0) + (item.path != ".")
    if any(count > MAX_SHARE_PER_DIRECTORY for count in counts.values()):
        return ShareClassification(Observation.PRESERVE, entries, (), "directory-bound")
    mounts = parse_mountinfo(mountinfo)
    nested = tuple(row for row in mounts if row[5] == SHARE_ROOT or row[5].startswith(SHARE_ROOT + "/"))
    by_point = {row[5]: row for row in nested}
    for point, mount in by_point.items():
        relative = "." if point == SHARE_ROOT else point[len(SHARE_ROOT) + 1:]
        entry = paths.get(relative)
        device = (mount[3] & 0xff) | (mount[2] << 8) | ((mount[3] & ~0xff) << 12) | ((mount[2] & ~0xfff) << 32)
        if entry is None or entry.mount_id != mount[0] or entry.device != device:
            return ShareClassification(Observation.PRESERVE, entries, tuple(by_point), "mount-correlation")
    # Every entry's mount id must be the deepest containing complete mount row.
    for item in entries:
        absolute = SHARE_ROOT if item.path == "." else SHARE_ROOT + "/" + item.path
        containing = [row for row in mounts if absolute == row[5] or absolute.startswith(row[5].rstrip("/") + "/")]
        if not containing:
            return ShareClassification(Observation.PRESERVE, entries, tuple(by_point), "missing-containing-mount")
        deepest = max(containing, key=lambda row: len(row[5]))
        if item.mount_id != deepest[0]:
            return ShareClassification(Observation.PRESERVE, entries, tuple(by_point), "entry-mount-mismatch")
    return ShareClassification(Observation.EXACT, entries, tuple(by_point), "bounded-observed-leaves")


def recovery_class(snapshot):
    """Closed ownership result; names without a durable owner never adopt."""
    _fail(type(snapshot) is RuntimeSnapshot)
    if not snapshot.owned:
        if (snapshot.container is Observation.ABSENT and snapshot.task == "absent" and
                snapshot.processes is Observation.ABSENT and snapshot.network is Observation.ABSENT and
                snapshot.share is Observation.ABSENT and snapshot.mount_baseline is Observation.EXACT and
                snapshot.firewall is Observation.ABSENT):
            return "unowned_absent"
        return "preserve_no_adoption"
    values = (snapshot.container, snapshot.processes, snapshot.network, snapshot.share,
              snapshot.mount_baseline, snapshot.firewall)
    if Observation.PRESERVE in values or snapshot.task in {"preserve", "unknown", "paused", "pausing"}:
        return "preserve"
    if snapshot.container is Observation.ABSENT and snapshot.task == "absent":
        if snapshot.processes is Observation.ABSENT and snapshot.network is Observation.ABSENT and \
           snapshot.share is Observation.ABSENT and snapshot.mount_baseline is Observation.EXACT and \
           snapshot.firewall is Observation.ABSENT:
            return "owned_absent"
        return "owned_cleanup"
    if snapshot.container is Observation.EXACT and snapshot.task in {"running", "stopped", "absent"}:
        return "owned_task_absent" if snapshot.task == "absent" else "owned_" + snapshot.task
    return "preserve"


def next_teardown_action(snapshot):
    """Return one ordered action recommendation; never issue it."""
    _fail(type(snapshot) is RuntimeSnapshot)
    classification = recovery_class(snapshot)
    if classification in {"preserve", "preserve_no_adoption"}:
        return TeardownAction.PRESERVE
    if classification in {"unowned_absent", "owned_absent"}:
        return TeardownAction.COMPLETE
    if not snapshot.readiness_revoked:
        return TeardownAction.REVOKE_READINESS
    if snapshot.task == "running":
        if not snapshot.term_attempted:
            return TeardownAction.TASK_TERM
        return TeardownAction.TASK_KILL if snapshot.kill_permitted else TeardownAction.OBSERVE_TASK
    if snapshot.task not in {"stopped", "absent"}:
        return TeardownAction.PRESERVE
    if snapshot.network is not Observation.ABSENT:
        return TeardownAction.REMOVE_NETWORK if snapshot.network is Observation.EXACT else TeardownAction.PRESERVE
    # A stopped exact task must be deleted before its exact container; neither
    # command has --force. The caller supplies a fresh snapshot after each step.
    if snapshot.task == "stopped":
        return TeardownAction.TASK_REMOVE
    if snapshot.container is Observation.EXACT:
        return TeardownAction.CONTAINER_REMOVE
    if snapshot.container is not Observation.ABSENT:
        return TeardownAction.PRESERVE
    if snapshot.processes is not Observation.ABSENT:
        return TeardownAction.OBSERVE_PROCESSES if snapshot.processes is Observation.EXACT else TeardownAction.PRESERVE
    if snapshot.share is not Observation.ABSENT or snapshot.mount_baseline is not Observation.EXACT:
        return TeardownAction.OBSERVE_SHARE
    if snapshot.firewall is not Observation.ABSENT:
        return TeardownAction.REMOVE_FIREWALL if snapshot.firewall is Observation.EXACT else TeardownAction.PRESERVE
    return TeardownAction.COMPLETE


def container_remove_after_task(snapshot):
    """Separate post-task decision used after a fresh task-absent observation."""
    _fail(type(snapshot) is RuntimeSnapshot and snapshot.owned)
    if (snapshot.readiness_revoked and snapshot.task == "absent" and
            snapshot.network is Observation.ABSENT and snapshot.container is Observation.EXACT):
        return TeardownAction.CONTAINER_REMOVE
    return TeardownAction.PRESERVE


def source_invariants_for_tests():
    """Machine-checkable non-authority assertions for hostile static tests."""
    specs = fixed_command_specs_for_tests()
    return {
        "qualification": QUALIFICATION_CANDIDATE,
        "production_available": False,
        "command_count": len(specs),
        "no_force": all("--force" not in item.argv and "-f" not in item.argv for item in specs),
        "share_mutations": (),
        "mount_digest": MOUNT_LIST_SHA256,
    }
