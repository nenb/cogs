"""ADR0099 fixed runtime owner; V1 bytes stay compatible and final composition stays closed."""
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
import base64, copy, fcntl, hashlib, json, os, re, socket, stat, time
import completion_kata_actions as actions
import completion_kata_command_policy as command_policy
import completion_kata_inputs as kata_inputs
import completion_kata_network as kata_network
import completion_kata_operation as kata_operation
import completion_kata_owner as owner_helpers
import completion_kata_prestage_runtime as prestage_runtime
import completion_rootfs_fs as rootfs_fs
import completion_rootfs_lease as rootfs_lease
BASE = "/var/lib/cogs/stage2-completion-v1/source/deploy/aws-feasibility/.state/completion-v1"
INPUT_SHARE = BASE + "/kata-input-v1/share"
ROOTFS_CANDIDATE = BASE + "/rootfs-v1/" + "b" * 64 + "/rootfs"
NAMESPACE = "cogs-stage2-completion-v1"
CONTAINER_ID = SANDBOX_ID = "cogs-stage2-ssh-v1"
RUNTIME = "io.containerd.kata.v2"
RUNTIME_CONFIG = command_policy.RUNTIME_CONFIG
KATA_BASE_CONFIG = "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml"
KATA_CONFIG_SHA256 = "7ecd072a35da55f5abc76d604a610cf3f2d543c7de0cefc4d1a81028facd2cae"
COMMITTED_EXECUTABLE_SHA256 = MappingProxyType({BASE + "/kata-runtime-v1/bin/containerd": "f5d70cf9a249a70a70c379ba8f7259ea91122650cc06103bc0fc44a04dbc54da", BASE + "/kata-runtime-v1/bin/ctr": "448b1d7a2da84b6265dc4685afcc6c69a6299de43b942b8a3d6d540f6585d1db", "/opt/kata/bin/qemu-system-x86_64": "1e4968d9cce98c7cba8f9e3488236cba56993d9747f268d03b0284f3df2b012d"})
NETNS_PATH = "/run/netns/cogs-stage2-ssh"
SHARE_ROOT = "/run/kata-containers/shared/sandboxes/cogs-stage2-ssh-v1"
CONTAINERD_VERSION = "2.2.1"; OCI_VERSION = "1.3.0"
QUALIFICATION_CANDIDATE = "UNQUALIFIED_OFFLINE_FAKE_CONTAINERD_KATA_S4_V1"
V2 = "cogs.stage2-kata-runtime-owner/v2"
RUNTIME_ROOT = BASE + "/kata-runtime-v1"; RUNTIME_ALIAS = command_policy.RUNTIME_ALIAS; CONTAINERD_ADDRESS = command_policy.CONTAINERD_ADDRESS; CONTAINERD_ROOT = command_policy.CONTAINERD_ROOT; CONTAINERD_STATE = command_policy.CONTAINERD_STATE
STAGED_CONTAINERD = RUNTIME_ROOT + "/bin/containerd"; STAGED_CTR = RUNTIME_ROOT + "/bin/ctr"
CONTAINERD_CONFIG = RUNTIME_ROOT + "/containerd.toml"; CONTAINERD_TTRPC_ADDRESS = CONTAINERD_ADDRESS + ".ttrpc"; MAX_UNIX_PATH = 107; CONTAINERD_SHIM_ENDPOINT = CONTAINERD_STATE + "/io.containerd.runtime.v2.task/" + NAMESPACE + "/" + CONTAINER_ID + "/shim.sock"
if any(len(path.encode("ascii")) > MAX_UNIX_PATH for path in (CONTAINERD_ADDRESS, CONTAINERD_TTRPC_ADDRESS, CONTAINERD_ROOT, CONTAINERD_STATE, CONTAINERD_SHIM_ENDPOINT)): raise RuntimeError("containerd AF_UNIX path")
KATA_VM_DIRECTORY = "/run/vc/vm/cogs-stage2-ssh-v1"
KATA_QMP_SOCKET = KATA_VM_DIRECTORY + "/qmp.sock"
OBSERVER_QMP_SOCKET = KATA_VM_DIRECTORY + "/extra-monitor.sock"
CONTAINERD_CONFIG_BYTES = (f'''version = 3
root = "{CONTAINERD_ROOT}"
state = "{CONTAINERD_STATE}"
disabled_plugins = ["io.containerd.cri.v1.images", "io.containerd.cri.v1.runtime"]
[grpc]
  address = "{CONTAINERD_ADDRESS}"
  uid = 0
  gid = 0
[debug]
  address = ""
  level = "warn"
[metrics]
  address = ""
''').encode("ascii")
CONTAINERD_CONFIG_SHA256 = hashlib.sha256(CONTAINERD_CONFIG_BYTES).hexdigest()
MAX_JSON = 1_048_576
MAX_JSON_DEPTH = 24
MAX_JSON_ITEMS = 512
RUNTIME_OPTIONS_TYPE_URL = "runtimeoptions.v1.Options"
MAX_RUNTIME_OPTIONS_WIRE = 512
MAX_RUNTIME_OPTIONS_BASE64 = 4 * ((MAX_RUNTIME_OPTIONS_WIRE + 2) // 3)
MAX_PROC_ROWS = 4096
MAX_CMDLINE = 16_384
CTR_NS_FD = 202
CTR_NS_TEMPLATE = "/proc/{ctr-child-pid}/fd/202"
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
    type: str; source: str; destination: str; options: tuple[str, ...]
@dataclass(frozen=True)
class CommandSpec:
    command_id: actions.CommandId; argv: tuple[str, ...]; stdin: bytes; deadline_class: str
class Observation(Enum):
    ABSENT = "absent"
    EXACT = "exact"
    PRESERVE = "preserve"
@dataclass(frozen=True)
class ProcessRecord:
    role: str; pid: int; ppid: int; starttime: int; executable: str; executable_device: int
    executable_inode: int; cmdline: tuple[str, ...]; namespaces: tuple[tuple[str, str], ...]
@dataclass(frozen=True)
class ProcessClassification:
    disposition: Observation; records: tuple[ProcessRecord, ...]; reason: str
@dataclass(frozen=True)
class ShareEntry:
    path: str; kind: str; device: int; inode: int; mount_id: int; mode: int; uid: int; gid: int
@dataclass(frozen=True)
class ShareClassification:
    disposition: Observation; entries: tuple[ShareEntry, ...]; mountpoints: tuple[str, ...]; reason: str
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
    _LaunchPermit = owner_helpers.sealed_type(
        "_LaunchPermit", seal, KataRuntimeError, "sealed launch permit")
    def candidate():
        permit = _LaunchPermit(seal)
        states[permit] = {
            "root": ROOTFS_CANDIDATE, "mount": MOUNT_LIST_SHA256,
            "input": "1" * 64, "network": NETNS_PATH, "used": False,
            "qualification": QUALIFICATION_CANDIDATE,
        }
        return permit
    def operation_candidate(network_grant):
        import completion_kata_network as network
        retained = network._consume_runtime_network(network_grant)
        expected = operation_netns_path(retained["operation_token"])
        _fail(retained["path"] == expected and retained["identity"]["name"] == expected.rsplit("/", 1)[-1],
              "operation network grant")
        permit = _LaunchPermit(seal)
        states[permit] = {"root": ROOTFS_CANDIDATE, "mount": MOUNT_LIST_SHA256,
            "input": "1" * 64, "network": expected, "used": False, "preexec": False, "released": False,
            "descriptor_issued": False,
            "qualification": QUALIFICATION_CANDIDATE, "operation_token": retained["operation_token"],
            "network_grant": network_grant}
        return permit
    def claim(permit):
        state = states.get(permit)
        _fail(type(permit) is _LaunchPermit and state is not None and not state["used"],
              "operation-owned root/input/network permit required")
        _fail(state["qualification"] == QUALIFICATION_CANDIDATE,
              "unqualified candidate invariant")
        if "network_grant" in state:
            import completion_kata_network as network
            retained = network._verify_runtime_network(state["network_grant"])
            _fail(retained["path"] == state["network"], "launch network replaced")
        state["used"] = True
        return dict(state)
    def preexec(permit, child_pid):
        state = states.get(permit)
        _fail(type(permit) is _LaunchPermit and state is not None and state["used"] and
              not state.get("preexec", False) and "network_grant" in state, "live launch network hold")
        import completion_kata_network as network
        retained = network._verify_runtime_network(state["network_grant"])
        _fail(retained["path"] == state["network"] and retained["operation_token"] == state["operation_token"],
              "preexec network replaced")
        _fail(type(child_pid) is int and child_pid > 1, "ctr child pid")
        state["preexec"] = True; state["launch_path"] = CTR_NS_TEMPLATE.replace("{ctr-child-pid}", str(child_pid))
        return {**retained, "launch_path": state["launch_path"]}
    def release(permit):
        state = states.get(permit)
        _fail(type(permit) is _LaunchPermit and state is not None and state.get("preexec") is True and
              not state["released"], "preexec release order")
        state["released"] = True
    def descriptor(permit):
        state = states.get(permit)
        _fail(type(permit) is _LaunchPermit and state is not None and state["used"] and
              not state["descriptor_issued"], "one-use ctr namespace descriptor")
        state["descriptor_issued"] = True
        import completion_kata_network as network
        return network._runtime_network_descriptor(state["network_grant"])
    def launch_path(permit):
        state = states.get(permit)
        _fail(type(permit) is _LaunchPermit and state is not None and state["released"], "released ctr binding")
        return state["launch_path"]
    def held(permit):
        state = states.get(permit)
        _fail(type(permit) is _LaunchPermit and state is not None and state["used"] and "network_grant" in state,
              "live network hold absent")
        return state["network_grant"]
    return candidate, operation_candidate, claim, preexec, release, descriptor, launch_path, held

(_make_fake_launch_permit_for_tests, _make_operation_launch_permit,
 _claim_launch_permit, _preexec_launch_network, _release_launch_preexec,
 _retain_launch_network_descriptor, _resolved_launch_network_path,
 _stored_launch_network_grant) = _permit_routes()
del _permit_routes

def _runtime_mount_grant_routes():
    owners = owner_helpers.Registry(
        "RuntimeMountOwner", KataRuntimeError, "exact unused runtime owner required",
        sealed_message="sealed runtime mount owner")
    grants = owner_helpers.Registry(
        "RuntimeMountGrant", KataRuntimeError, "runtime mount lineage mismatch",
        sealed_message="sealed runtime mount grant")
    RuntimeMountOwner, RuntimeMountGrant = owners.kind, grants.kind
    def synthetic_owner(operation_token, mounted_input, control):
        _fail(os.environ.get("COGS_KATA_SYNTHETIC_RUNTIME_V1") == "1"
              and type(operation_token) is str and len(operation_token) == 64
              and type(mounted_input) is rootfs_fs.HeldNode
              and type(control) is rootfs_fs.OperationControl,
              "synthetic runtime owner admission")
        generation = rootfs_fs._observe_node(
            mounted_input.identity_fd, mounted_input.operation_fd, control)
        return owners.issue([operation_token, mounted_input, control, generation, False])
    def issue(owner):
        state = owners.require(owner)
        _fail(not state[4], "exact unused runtime owner required")
        state[4] = True
        return grants.issue([*state[:4], False])
    def claim(grant, operation_token):
        state = grants.require(grant)
        _fail(not state[4] and state[0] == operation_token
              and rootfs_fs._observe_node(
                  state[1].identity_fd, state[1].operation_fd, state[2]) == state[3],
              "runtime mount lineage mismatch")
        state[4] = True
        return state[1], state[2]
    return RuntimeMountOwner, RuntimeMountGrant, synthetic_owner, issue, claim

(RuntimeMountOwner, RuntimeMountGrant, _make_synthetic_runtime_mount_owner_for_tests,
 _issue_runtime_mount_grant, _claim_runtime_mount_grant) = _runtime_mount_grant_routes()
del _runtime_mount_grant_routes

def _open_production_owner():
    """Fail closed until operation/root/input/network and tool issuers exist."""
    raise KataRuntimeError("production runtime owner is unavailable: issuers unqualified")

def operation_netns_path(operation_token):
    """Return the sole operation-owned runtime namespace path."""
    _fail(type(operation_token) is str and re.fullmatch(r"[0-9a-f]{64}", operation_token), "operation token")
    return "/run/netns/c42n" + operation_token[:10]

def _ctr_metadata_argv():
    return (STAGED_CTR, "--address", CONTAINERD_ADDRESS, "--namespace", NAMESPACE,
            "containers", "create", "--config", RUNTIME_ROOT + "/metadata-fixture.json",
            "--runtime", RUNTIME, "--runtime-config-path", RUNTIME_CONFIG, CONTAINER_ID)

def ctr_run_spec(permit):
    """Consume the metadata fixture bundle; child PID resolves retained fd 202."""
    state = _claim_launch_permit(permit)
    _fail(state["mount"] == MOUNT_LIST_SHA256 and (state["network"] == NETNS_PATH or
          re.fullmatch(r"/run/netns/c42n[0-9a-f]{10}", state["network"])),
          "operation network path")
    return CommandSpec(actions.CommandId.CTR_RUN, _ctr_metadata_argv(), b"", "runtime-start")

def _validate_ctr_launch_intent(intent):
    argv = tuple(intent["argv"]); metadata = argv == _ctr_metadata_argv()
    root = next((item for item in argv if re.fullmatch(re.escape(command_policy.BASE) +
                 r"/rootfs-v1/operation-([0-9a-f]{64})/rootfs", item)), None)
    production = root is not None and argv == command_policy.ctr_run_argv(
        root.rsplit("operation-", 1)[1].split("/", 1)[0])
    _fail(intent["executable_role"] == "ctr" and intent["executable_path"] == STAGED_CTR
          and (metadata or production) and intent["command_id"] == "CTR_RUN"
          and intent["stdin_hex"] == "" and (metadata or "network:" + CTR_NS_TEMPLATE in argv),
          "fixed ctr fd launch intent")

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
    "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP",
    "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
)
_MASKED = (
    "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
    "/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/sys/firmware", "/proc/scsi",
)
_READONLY = (
    "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
)

def _oci_spec(network_path):
    """Return a fresh reviewed OCI candidate for an internally derived nsfs path."""
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
                {"type": "network", "path": network_path},
            ],
            "maskedPaths": list(_MASKED),
            "readonlyPaths": list(_READONLY),
        },
    }

def expected_oci_spec():
    """Return the historically reviewed fixed-alias OCI candidate."""
    return _oci_spec(NETNS_PATH)


def _expected_operation_oci_spec(operation_token, launch_path=None):
    return _oci_spec(operation_netns_path(operation_token) if launch_path is None else launch_path)


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


def _durable_ctr_launch_path(history):
    """Select the sole successful durable CTR_RUN preexec fd binding."""
    runs = [row for row in history["intents"] if row["command_id"] == "CTR_RUN"]
    _fail(len(runs) == 1); intent = runs[0]; serial = intent["command_serial"]
    preexecs = [row for row in history["preexecs"] if row["command_serial"] == serial]
    outcomes = [row for row in history["outcomes"] if row["command_serial"] == serial]
    _fail(len(outcomes) == 1); outcome = outcomes[0]
    if not preexecs:
        _fail(outcome["outcome"] == "not-started" or outcome["outcome"] == "uncertain" and outcome["release_count"] == 0, "durable ctr launch binding"); return None
    _fail(len(preexecs) == 1); preexec = preexecs[0]
    _fail(all(row["command_id"] == "CTR_RUN" and row["binding_sha256"] == intent["binding_sha256"] for row in (preexec, outcome))
          and preexec["namespace_fd"] == CTR_NS_FD and preexec["namespace_path"] == CTR_NS_TEMPLATE.replace("{ctr-child-pid}", str(preexec["pid"])), "durable ctr launch binding")
    return preexec["namespace_path"] if outcome["outcome"] == "exited" and outcome["status"] == 0 and not outcome["uncertain"] else None


def _runtime_config_path(options):
    """Decode ctr 2.2.1's JSON rendering of the runtimeoptions protobuf Any."""
    _keys(options, ("type_url", "value"))
    _fail(options["type_url"] == RUNTIME_OPTIONS_TYPE_URL, "runtime options type URL")
    encoded = options["value"]
    _fail(type(encoded) is str and 0 < len(encoded) <= MAX_RUNTIME_OPTIONS_BASE64, "runtime options base64 bound")
    try:
        encoded_ascii = encoded.encode("ascii", "strict")
        wire = base64.b64decode(encoded_ascii, validate=True)
    except (UnicodeError, ValueError) as error:
        raise KataRuntimeError("invalid runtime options base64") from error
    _fail(0 < len(wire) <= MAX_RUNTIME_OPTIONS_WIRE and base64.b64encode(wire) == encoded_ascii,
          "non-canonical runtime options base64")
    # runtimeoptions.v1.Options field 2 is config_path. This invocation sets no
    # other field, so accepting anything else would widen stored ownership.
    _fail(wire[0] == 0x12, "runtime options config_path field")
    length = 0; offset = 1
    for index in range(2):
        _fail(offset < len(wire), "runtime options length")
        octet = wire[offset]; offset += 1; length |= (octet & 0x7f) << (7 * index)
        if octet < 0x80: break
    else: _fail(False, "runtime options length bound")
    _fail((index == 0 or length >= 128) and offset + length == len(wire),
          "runtime options malformed/duplicate field")
    try: config_path = wire[offset:].decode("utf-8", "strict")
    except UnicodeError as error: raise KataRuntimeError("runtime options config_path encoding") from error
    _fail(config_path == RUNTIME_CONFIG, "runtime options config_path")
    return config_path


def validate_stored_info(raw_or_value, network_grant=None, launch_path=None):
    """Validate stored info against the historical alias or an exact live owner grant."""
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
    _runtime_config_path(runtime["Options"])
    spec = value["Spec"]
    if network_grant is None:
        expected_spec = expected_oci_spec()
    else:
        import completion_kata_network as network
        retained = network._verify_runtime_network(network_grant)
        expected_spec = _expected_operation_oci_spec(retained["operation_token"], launch_path)
        _fail(retained["path"] == operation_netns_path(retained["operation_token"]), "stored network grant")
    _fail(type(spec) is dict and spec == expected_spec, "complete OCI spec drift")
    return validate_stored_spec(spec)


def _ctr_table(raw, header):
    _fail(type(raw) is bytes and 0 < len(raw) <= 65_536
          and raw.endswith(b"\n") and b"\x00" not in raw)
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeError as error:
        raise KataRuntimeError("ctr table encoding") from error
    _fail(lines and tuple(lines[0].split()) == header
          and all(line and "\t" not in line and all(char == " " or char.isprintable()
                  and char.isascii() for char in line) for line in lines))
    return lines[1:]


def parse_container_list(raw):
    """Parse the complete fixed-width ctr 2.2.1 container list output."""
    rows = []
    for line in _ctr_table(raw, ("CONTAINER", "IMAGE", "RUNTIME")):
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
    rows = []
    for line in _ctr_table(raw, ("TASK", "PID", "STATUS")):
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
def classify_ctr_observation(info, containers, tasks, expected_pid=None, network_grant=None, launch_path=None):
    """Classify exact observer envelopes; only a later successful list proves absence."""
    _fail(all(type(row) is tuple and len(row) == 3 and type(row[0]) is int and 0 <= row[0] <= 255
              and type(row[1]) is type(row[2]) is bytes and len(row[1]) <= 65_536 and len(row[2]) <= 65_536
              for row in (info, containers, tasks)), "ctr observer envelope")
    _fail(containers[0] == tasks[0] == 0 and containers[2] == tasks[2] == b"", "list observer failure")
    container = classify_container_list(containers[1]); task = classify_task_list(tasks[1], expected_pid); mount = None
    if container is Observation.EXACT:
        if info[0] != 0 or info[2] or network_grant is not None and launch_path is None: container = Observation.PRESERVE
        else: mount = validate_stored_info(info[1], network_grant, launch_path)
    elif container is Observation.ABSENT and (info[0] == 0 or launch_path is not None):
        if info[0] == 0:
            _fail(not info[2])
            if network_grant is None or launch_path is not None: validate_stored_info(info[1], network_grant, launch_path)
        container = Observation.PRESERVE
    return {"container": container, "task": task, "mount": mount}
def unqualified_stored_info_fixture_for_tests():
    value = {
        "ID": CONTAINER_ID, "Labels": {}, "Image": "", "Runtime": {
            "Name": RUNTIME, "Options": {
                "type_url": RUNTIME_OPTIONS_TYPE_URL,
                "value": base64.b64encode(b"\x12" + bytes((0x80 | (len(RUNTIME_CONFIG) & 0x7f),
                                                      len(RUNTIME_CONFIG) >> 7))
                              + RUNTIME_CONFIG.encode()).decode("ascii"),
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
def classify_process_snapshot(snapshot, baseline=(), host_netns=None, operation_netns=None):
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
    if (ns["shim"]["net"] != host_netns or ns["qemu"]["net"] != operation_netns or
            ns["virtiofsd"]["net"] != operation_netns or ns["virtiofsd"]["mnt"] != ns["shim"]["mnt"]):
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
# V2 is separate: all historical v1 byte snapshots above remain unchanged.
def fixed_command_specs_v2():
    result = []
    for old in fixed_command_specs_for_tests():
        argv = (STAGED_CTR, "--address", CONTAINERD_ADDRESS, *old.argv[1:])
        result.append(CommandSpec(old.command_id, argv, old.stdin, old.deadline_class))
    return tuple(result)
def ctr_run_spec_v2(rootfs_token):
    return CommandSpec(actions.CommandId.CTR_RUN, command_policy.ctr_run_argv(rootfs_token),
                       b"", "runtime-start")
def private_containerd_spec_v2():
    return CommandSpec(actions.CommandId.CONTAINERD_START, (
        STAGED_CONTAINERD, "--address", CONTAINERD_ADDRESS, "--root", CONTAINERD_ROOT,
        "--state", CONTAINERD_STATE, "--config", CONTAINERD_CONFIG,
    ), b"", "runtime-start")
def _start_private_containerd(journal, executable):
    import completion_kata_process as process
    return process._start_fixed_daemon(journal, executable)
def _canonical_fact(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                        allow_nan=False).encode() + b"\n").hexdigest()
def _file_identity(seen):
    return tuple(getattr(seen, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))

def _read_held_file(descriptor, maximum):
    before = os.fstat(descriptor); raw = bytearray(); offset = 0
    while len(raw) <= maximum:
        part = os.pread(descriptor, min(65_536, maximum + 1 - len(raw)), offset)
        if not part: break
        raw.extend(part); offset += len(part)
    _fail(len(raw) <= maximum and _file_identity(os.fstat(descriptor)) == _file_identity(before),
          "held file changed")
    return bytes(raw), before

def _read_bounded(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        chunks = bytearray()
        while len(chunks) <= maximum:
            part = os.read(descriptor, min(1_048_576, maximum + 1 - len(chunks)))
            if not part: break
            chunks.extend(part)
        _fail(len(chunks) <= maximum, "bounded host read")
        return bytes(chunks)
    finally:
        os.close(descriptor)
def _runtime_netns_root(netns):
    if netns is None: return None
    _fail(type(netns) is dict and set(netns) == {"operation_token", "identity", "path"})
    identity = netns["identity"]
    _fail(type(identity) is dict and set(identity) == {
        "mount_id", "parent_id", "device", "inode_device", "inode", "name"}
        and type(identity["inode"]) is int and identity["inode"] > 0
        and re.fullmatch(r"c42n[0-9a-f]{10}", identity["name"]) is not None
        and netns["path"] == "/run/netns/" + identity["name"])
    return f"net:[{identity['inode']}]"


def _proc_snapshot(attested, netns, host_netns):
    import completion_kata_process as process
    expected = {item.path: item for item in attested}
    netns_root = _runtime_netns_root(netns)
    roles = {"/opt/kata/bin/containerd-shim-kata-v2": "shim",
             "/opt/kata/bin/qemu-system-x86_64": "qemu",
             "/opt/kata/libexec/virtiofsd": "virtiofsd"}
    names = os.listdir("/proc")
    _fail(len(names) <= 131072 and all(type(name) is str for name in names), "complete proc listing")
    rows = []
    for name in names:
        if not name.isdigit(): continue
        pid = int(name)
        try: executable = os.readlink(f"/proc/{pid}/exe")
        except FileNotFoundError: continue
        if executable not in roles: continue
        before = process._proc_row(pid); _fail(executable in expected, "unattested runtime executable")
        descriptor = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
        try:
            identity = process.fdmap.identity(descriptor)
            generation = process._host_generation(descriptor)
            item = expected[executable]
            _fail(generation == item.generation and process._digest_fd(descriptor, identity.size) == item.sha256,
                  "runtime executable generation/digest")
        finally: os.close(descriptor)
        row = process._proc_row(pid); _fail(row == before, "runtime process changed")
        command = _read_bounded(f"/proc/{pid}/cmdline", MAX_CMDLINE).rstrip(b"\0").split(b"\0")
        namespaces = {kind: os.readlink(f"/proc/{pid}/ns/{kind}")
                      for kind in ("ipc", "mnt", "net", "pid", "user", "uts")}
        expected_netns = {"shim": host_netns, "qemu": netns_root,
                          "virtiofsd": netns_root}
        _fail(os.readlink("/proc/self/ns/net") == host_netns and namespaces["net"] == expected_netns[roles[executable]]
              and process._proc_row(pid) == row, "Kata 3.32 role/netns correlation")
        rows.append({"role": roles[executable], "pid": pid, "ppid": row[1], "starttime": row[4],
                     "executable": executable, "executable_device": identity.device,
                     "executable_inode": identity.inode,
                     "cmdline": [part.decode("utf-8", "strict") for part in command],
                     "namespaces": namespaces})
    value = {"complete": True, "early_exit": False, "rows": rows,
             "qualification": QUALIFICATION_CANDIDATE}
    return classify_process_snapshot(value, host_netns=host_netns,
                                     operation_netns=netns_root)
def _retirement_identity_rows(baseline, snapshot, disappeared):
    """Validate one complete role-retirement observation without mutation."""
    _fail(type(baseline) is dict and set(baseline) == {"shim", "qemu", "virtiofsd"}
          and type(snapshot) is ProcessClassification and type(disappeared) is set,
          "runtime retirement observation")
    current = {}
    for row in snapshot.records:
        _fail(row.role not in current and row.role in baseline, "duplicate/foreign runtime role")
        expected = baseline[row.role]
        identity = {"role": row.role, "pid": row.pid, "starttime": row.starttime,
                    "executable": row.executable, "executable_device": row.executable_device,
                    "executable_inode": row.executable_inode,
                    "namespaces": [list(item) for item in row.namespaces]}
        retained = {name: expected[name] for name in identity}
        _fail(identity == retained, "runtime role identity replacement")
        _fail(row.role not in disappeared, "runtime role reappeared")
        current[row.role] = row
    return current, disappeared | (set(baseline) - set(current))

QMP_LINE_LIMIT = 65_536
QMP_TOTAL_LIMIT = 262_144
QMP_MESSAGE_LIMIT = 64
QMP_IDS = ("cogs-capabilities-v1", "cogs-status-v1", "cogs-kvm-v1")


def _deadline_remaining(deadline):
    remaining = deadline - time.monotonic()
    _fail(remaining > 0, "QMP observation deadline")
    return remaining


def _qemu_current(qemu):
    process = __import__("completion_kata_process")
    row = process._proc_row(qemu.pid)
    _fail(row[1] == qemu.ppid and row[4] == qemu.starttime
          and os.readlink(f"/proc/{qemu.pid}/exe") == qemu.executable,
          "QEMU identity changed")
    executable = os.stat(f"/proc/{qemu.pid}/exe")
    _fail((executable.st_dev, executable.st_ino) ==
          (qemu.executable_device, qemu.executable_inode),
          "QEMU executable generation changed")
    return row


def _qemu_argv(qemu):
    _qemu_current(qemu)
    raw = _read_bounded(f"/proc/{qemu.pid}/cmdline", MAX_CMDLINE)
    _fail(raw.endswith(b"\0") and 1 < len(raw) <= MAX_CMDLINE,
          "complete NUL-framed QEMU argv")
    fields = raw[:-1].split(b"\0")
    _fail(fields and all(fields), "empty QEMU argument")
    try:
        argv = tuple(item.decode("utf-8", "strict") for item in fields)
    except UnicodeError as error:
        raise KataRuntimeError("QEMU argv encoding") from error
    _fail(argv[0] == qemu.executable and "-qmp-pretty" not in argv,
          "QEMU argv executable/protocol")
    positions = [index for index, item in enumerate(argv) if item == "-qmp"]
    _fail(len(positions) == 2 and all(index + 1 < len(argv) for index in positions),
          "exactly two QMP frontends required")
    values = [argv[index + 1] for index in positions]
    observer = "unix:path=" + OBSERVER_QMP_SOCKET + ",server=on,wait=off"
    private = tuple(re.fullmatch(r"unix:fd=([1-9][0-9]*),server=on,wait=off", item)
                    for item in values)
    private = tuple(match for match in private if match is not None)
    _fail(values.count(observer) == 1 and len(private) == 1
          and sum(OBSERVER_QMP_SOCKET in item for item in argv) == 1,
          "QMP frontend argv differs")
    private_fd = int(private[0].group(1))
    _fail(private_fd <= 1_048_576, "QMP inherited fd bound")
    _qemu_current(qemu)
    return raw, hashlib.sha256(raw).hexdigest(), private_fd


def _unix_listeners(raw):
    _fail(type(raw) is bytes and 0 < len(raw) <= 1_048_576
          and raw.endswith(b"\n") and b"\0" not in raw,
          "bounded /proc/net/unix")
    lines = raw.splitlines()
    _fail(1 <= len(lines) <= MAX_PROC_ROWS
          and lines[0].split() == [b"Num", b"RefCount", b"Protocol", b"Flags",
                                   b"Type", b"St", b"Inode", b"Path"],
          "unix table header")
    result = []
    for line in lines[1:]:
        fields = line.split()
        _fail(7 <= len(fields) <= 8 and fields[0].endswith(b":"),
              "unix table row")
        if len(fields) == 8 and fields[7] in {
                KATA_QMP_SOCKET.encode("ascii"), OBSERVER_QMP_SOCKET.encode("ascii")}:
            _fail(fields[3] == b"00010000" and fields[4] == b"0001"
                  and fields[5] == b"01" and fields[6].isdigit()
                  and int(fields[6]) > 0, "QMP listener row")
            result.append((fields[7].decode("ascii"), int(fields[6])))
    return tuple(result)


def _qemu_socket_fds(qemu, listeners):
    names = os.listdir(f"/proc/{qemu.pid}/fd")
    _fail(len(names) <= 65_536 and all(name.isdigit() for name in names),
          "bounded QEMU fd listing")
    links = []
    for name in names:
        try:
            links.append((int(name), os.readlink(f"/proc/{qemu.pid}/fd/{name}")))
        except FileNotFoundError:
            continue
    result = {}
    for path, inode in listeners:
        matches = tuple(fd for fd, target in links if target == f"socket:[{inode}]")
        _fail(len(matches) == 1, "QMP listener must have one QEMU fd")
        result[path] = (inode, matches[0])
    _fail(len(result) == 2
          and result[KATA_QMP_SOCKET][0] != result[OBSERVER_QMP_SOCKET][0]
          and result[KATA_QMP_SOCKET][1] != result[OBSERVER_QMP_SOCKET][1],
          "QMP frontends must be distinct")
    return result


def _qmp_socket_generation(path, observer=False):
    seen = os.lstat(path)
    _fail(stat.S_ISSOCK(seen.st_mode) and seen.st_uid == seen.st_gid == 0,
          "root-owned QMP socket")
    if observer:
        mode = stat.S_IMODE(seen.st_mode)
        _fail(bool(mode & stat.S_IWUSR) and not mode & (stat.S_IWGRP | stat.S_IWOTH),
              "observer QMP socket write policy")
    return tuple(getattr(seen, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_ctime_ns"))


def _observer_snapshot(qemu):
    _qemu_current(qemu)
    directory = os.lstat(KATA_VM_DIRECTORY)
    _fail(stat.S_ISDIR(directory.st_mode) and not stat.S_ISLNK(directory.st_mode)
          and directory.st_uid == directory.st_gid == 0
          and stat.S_IMODE(directory.st_mode) == 0o750,
          "Kata VM directory access policy")
    argv_raw, argv_sha256, private_argv_fd = _qemu_argv(qemu)
    private = _qmp_socket_generation(KATA_QMP_SOCKET)
    observer = _qmp_socket_generation(OBSERVER_QMP_SOCKET, True)
    rows = _unix_listeners(_read_bounded("/proc/net/unix", 1_048_576))
    _fail(len(rows) == 2 and {path for path, _inode in rows} ==
          {KATA_QMP_SOCKET, OBSERVER_QMP_SOCKET},
          "exact dual QMP listeners")
    fds = _qemu_socket_fds(qemu, rows)
    _fail(set(fds) == {KATA_QMP_SOCKET, OBSERVER_QMP_SOCKET}
          and fds[KATA_QMP_SOCKET][1] == private_argv_fd,
          "QMP pathname/listener/fd binding")
    _qemu_current(qemu)
    return {
        "directory": tuple(getattr(directory, name) for name in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_ctime_ns")),
        "private": private, "observer": observer, "fds": fds,
        "private_argv_fd": private_argv_fd,
        "argv_sha256": argv_sha256, "argv_size": len(argv_raw),
    }


def _qmp_event(value):
    _fail(type(value) is dict and set(value) in (
        {"event", "timestamp"}, {"event", "data", "timestamp"}),
        "malformed QMP event")
    _fail(type(value["event"]) is str and 0 < len(value["event"]) <= 128
          and value["event"].isascii() and value["event"].isprintable())
    stamp = value["timestamp"]
    _fail(type(stamp) is dict and set(stamp) == {"seconds", "microseconds"}
          and type(stamp["seconds"]) is int and stamp["seconds"] >= 0
          and type(stamp["microseconds"]) is int
          and 0 <= stamp["microseconds"] < 1_000_000)
    if "data" in value:
        _fail(type(value["data"]) is dict, "QMP event data")
    return True


def _qmp_exchange(client, deadline):
    """Run the only admitted QMP sequence with one deadline and strict IDs."""
    buffer = bytearray(); total = 0; messages = 0; seen_ids = set()

    def receive():
        nonlocal total, messages
        while b"\n" not in buffer:
            _fail(len(buffer) <= QMP_LINE_LIMIT, "oversized QMP line")
            client.settimeout(_deadline_remaining(deadline))
            try:
                chunk = client.recv(min(16_384, QMP_TOTAL_LIMIT + 1 - total))
            except (TimeoutError, socket.timeout) as error:
                raise KataRuntimeError("QMP observation timeout") from error
            _fail(chunk, "QMP EOF")
            total += len(chunk)
            _fail(total <= QMP_TOTAL_LIMIT, "QMP total byte bound")
            buffer.extend(chunk)
        line, _, remainder = buffer.partition(b"\n")
        buffer[:] = remainder
        _fail(0 < len(line) <= QMP_LINE_LIMIT and b"\r" not in line,
              "QMP line framing")
        messages += 1
        _fail(messages <= QMP_MESSAGE_LIMIT, "QMP message count")
        return _load_json(bytes(line))

    greeting = receive()
    _fail(type(greeting) is dict and set(greeting) == {"QMP"}, "QMP greeting")
    description = greeting["QMP"]
    _fail(type(description) is dict and set(description) == {"version", "capabilities"}
          and type(description["capabilities"]) is list
          and len(description["capabilities"]) <= 32
          and all(type(item) is str and 0 < len(item) <= 128
                  for item in description["capabilities"]), "QMP greeting shape")
    version = description["version"]
    _fail(type(version) is dict and set(version) == {"qemu", "package"}
          and type(version["package"]) is str and len(version["package"]) <= 256,
          "QMP greeting version")
    qemu_version = version["qemu"]
    _fail(type(qemu_version) is dict and set(qemu_version) == {"major", "minor", "micro"}
          and tuple(qemu_version[name] for name in ("major", "minor", "micro")) == (11, 0, 1),
          "pinned QEMU greeting version")

    answers = []
    for command, request_id in zip(
            ("qmp_capabilities", "query-status", "query-kvm"), QMP_IDS, strict=True):
        request = json.dumps({"execute": command, "id": request_id},
                             sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode("ascii") + b"\n"
        client.settimeout(_deadline_remaining(deadline))
        client.sendall(request)
        while True:
            value = receive()
            if type(value) is dict and "event" in value:
                _qmp_event(value)
                continue
            _fail(type(value) is dict and set(value) == {"return", "id"},
                  "QMP terminal response shape/error")
            response_id = value["id"]
            _fail(type(response_id) is str and response_id in QMP_IDS
                  and response_id not in seen_ids and response_id == request_id,
                  "QMP response ID mismatch/duplicate")
            seen_ids.add(response_id); answers.append(value["return"]); break
    # Every byte already received is framed and classified. A terminal object
    # cannot trail the fixed sequence, and an incomplete object is residue.
    while buffer:
        _fail(b"\n" in buffer, "partial trailing QMP message")
        line, _, remainder = buffer.partition(b"\n"); buffer[:] = remainder
        _fail(0 < len(line) <= QMP_LINE_LIMIT and b"\r" not in line,
              "trailing QMP line framing")
        messages += 1; _fail(messages <= QMP_MESSAGE_LIMIT, "QMP message count")
        _qmp_event(_load_json(bytes(line)))
    capabilities, status, kvm = answers
    _fail(capabilities == {}, "QMP capabilities response")
    _fail(type(status) is dict and set(status) == {"running", "singlestep", "status"}
          and type(status["running"]) is bool and status["singlestep"] is False
          and status["status"] in {"running", "paused"}
          and status["running"] == (status["status"] == "running"),
          "QMP status response")
    _fail(kvm == {"enabled": True, "present": True}, "QMP KVM disabled")
    return status, kvm


def _qmp_absent():
    _fail(not os.path.lexists(KATA_QMP_SOCKET)
          and not os.path.lexists(OBSERVER_QMP_SOCKET)
          and not os.path.lexists(KATA_VM_DIRECTORY),
          "QMP/VM residue remains without QEMU")
    rows = _unix_listeners(_read_bounded("/proc/net/unix", 1_048_576))
    _fail(not rows, "QMP listener remains without QEMU")
    return {"state": "absent", "private_socket": "absent",
            "observer_socket": "absent"}


def _qmp_kvm(processes, deadline=None):
    qemu = next((row for row in processes.records if row.role == "qemu"), None)
    if qemu is None:
        return _qmp_absent()
    deadline = time.monotonic() + 2.0 if deadline is None else deadline
    _deadline_remaining(deadline)
    before = _observer_snapshot(qemu)
    client = socket.socket(socket.AF_UNIX,
                           socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
    try:
        client.settimeout(_deadline_remaining(deadline))
        # This literal is deliberately the only production connect target.
        client.connect(OBSERVER_QMP_SOCKET)
        status, _kvm = _qmp_exchange(client, deadline)
    finally:
        client.close()
    after = _observer_snapshot(qemu)
    _fail(after == before, "QMP socket/argv/process generation changed")

    device_fd = os.open("/dev/kvm", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    matches = []
    try:
        device = os.fstat(device_fd); _fail(stat.S_ISCHR(device.st_mode), "KVM device kind")
        for name in os.listdir(f"/proc/{qemu.pid}/fd"):
            try:
                if name.isdigit() and os.readlink(f"/proc/{qemu.pid}/fd/{name}") == "/dev/kvm":
                    matches.append(name)
            except FileNotFoundError:
                pass
        _fail(len(matches) == 1, "one QEMU /dev/kvm fd")
        descriptor = os.open(f"/proc/{qemu.pid}/fd/{matches[0]}",
                             os.O_RDONLY | os.O_CLOEXEC)
        try:
            duplicate = os.fstat(descriptor); _qemu_current(qemu)
            _fail((duplicate.st_rdev, duplicate.st_dev, duplicate.st_ino) ==
                  (device.st_rdev, device.st_dev, device.st_ino)
                  and fcntl.ioctl(descriptor, 0xAE00, 0) == 12,
                  "QEMU KVM API/device")
        finally:
            os.close(descriptor)
    finally:
        os.close(device_fd)
    _deadline_remaining(deadline)
    _fail(_observer_snapshot(qemu) == before, "post-KVM QMP identity changed")
    return {"state": status["status"], "qemu_pid": qemu.pid,
            "qemu_starttime": qemu.starttime,
            "qemu_executable_device": qemu.executable_device,
            "qemu_executable_inode": qemu.executable_inode,
            "qemu_argv_sha256": before["argv_sha256"],
            "observer_qmp_device": before["observer"][0],
            "observer_qmp_inode": before["observer"][1],
            "private_qmp_device": before["private"][0],
            "private_qmp_inode": before["private"][1],
            "kvm_device": device.st_dev, "kvm_inode": device.st_ino,
            "kvm_rdev": device.st_rdev, "kvm_api": 12,
            "kvm_present": True, "kvm_enabled": True,
            "status": status}
def _share_generation(seen):
    return {"device": seen.st_dev, "inode": seen.st_ino, "mode": stat.S_IMODE(seen.st_mode),
            "uid": seen.st_uid, "gid": seen.st_gid, "ctime_ns": seen.st_ctime_ns}

def _share_fact(retained=None):
    """Classify the exact share without turning pathname presence into authority."""
    _fail(retained is None or type(retained) is dict, "retained share identity")
    mountinfo = _read_bounded("/proc/self/mountinfo", MAX_MOUNTINFO)
    digest = hashlib.sha256(mountinfo).hexdigest()
    mounts = parse_mountinfo(mountinfo)
    if not os.path.lexists(SHARE_ROOT):
        classified = classify_share_snapshot({"root": SHARE_ROOT, "complete": True, "rows": [],
            "qualification": QUALIFICATION_CANDIDATE}, mountinfo)
        _fail(classified.disposition is Observation.ABSENT, "mounted absent share")
        return {"state": "absent", "mount_sha256": digest}
    held = []
    def mount_id(descriptor):
        raw = _read_bounded(f"/proc/self/fdinfo/{descriptor}", 4096)
        rows = [row for row in raw.splitlines() if row.startswith(b"mnt_id:\t")]
        _fail(len(rows) == 1 and rows[0][8:].isdigit(), "share mount id"); return int(rows[0][8:])
    def row(relative, descriptor):
        seen = os.fstat(descriptor); directory = stat.S_ISDIR(seen.st_mode)
        _fail(directory or stat.S_ISREG(seen.st_mode), "share entry kind")
        _fail(seen.st_uid == seen.st_gid == 0 and stat.S_IMODE(seen.st_mode) == (0o700 if directory else 0o600),
              "share entry mode")
        return {"path": relative, "kind": "directory" if directory else "file", "device": seen.st_dev,
            "inode": seen.st_ino, "mount_id": mount_id(descriptor), "mode": stat.S_IMODE(seen.st_mode),
            "uid": seen.st_uid, "gid": seen.st_gid, "nofollow": True}
    def walk(relative, descriptor, depth):
        _fail(depth <= MAX_SHARE_DEPTH, "share depth")
        names = os.listdir(descriptor); _fail(len(names) <= MAX_SHARE_PER_DIRECTORY, "share directory bound")
        for name in sorted(names):
            _fail(type(name) is str and name not in {"", ".", ".."} and "/" not in name and "\0" not in name)
            child = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=descriptor); held.append(child)
            relative_child = name if relative == "." else relative + "/" + name
            rows.append(row(relative_child, child)); _fail(len(rows) <= MAX_SHARE_TOTAL, "share total bound")
            if rows[-1]["kind"] == "directory": walk(relative_child, child, depth + 1)
    root_fd = os.open(SHARE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    held.append(root_fd); rows = [row(".", root_fd)]
    try:
        walk(".", root_fd, 0)
        classified = classify_share_snapshot({"root": SHARE_ROOT, "complete": True, "rows": rows,
            "qualification": QUALIFICATION_CANDIDATE}, mountinfo)
        _fail(classified.disposition is Observation.EXACT, "exact share census")
        generation = _share_generation(os.fstat(root_fd))
        parent = os.open(os.path.dirname(SHARE_ROOT), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try: parent_generation = _share_generation(os.fstat(parent))
        finally: os.close(parent)
        entries = [(item.path, item.device, item.inode, item.mode) for item in classified.entries]
        layout = hashlib.sha256(json.dumps(entries, separators=(",", ":")).encode()).hexdigest()
        base = {"entries": entries, "mountpoints": classified.mountpoints,
                "mount_sha256": digest, "root_generation": generation,
                "parent_generation": parent_generation, "layout_sha256": layout}
        if classified.mountpoints:
            return {"state": "active-exact", **base}
        if (len(classified.entries) == 1 and retained is not None
                and generation == retained.get("root_generation")
                and parent_generation == retained.get("parent_generation")):
            return {"state": "owned-empty-residue", **base}
        return {"state": "preserve", **base}
    finally:
        for descriptor in reversed(held): os.close(descriptor)

def _remove_owned_empty_share(retained):
    parent_path, name = os.path.split(SHARE_ROOT)
    parent = os.open(parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        _fail(_share_generation(os.fstat(parent)) == retained["parent_generation"], "share parent replacement")
        root = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
        try:
            _fail(_share_generation(os.fstat(root)) == retained["root_generation"] and not os.listdir(root),
                  "share residue replacement/nonempty")
            mountinfo = _read_bounded("/proc/self/mountinfo", MAX_MOUNTINFO)
            _fail(not any(row[5] == SHARE_ROOT or row[5].startswith(SHARE_ROOT + "/")
                          for row in parse_mountinfo(mountinfo)), "share residue mounted")
        finally: os.close(root)
        observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _fail(_share_generation(observed) == retained["root_generation"], "share residue changed before rmdir")
        os.rmdir(name, dir_fd=parent); os.fsync(parent)
        try: os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: pass
        else: _fail(False, "share residue remains")
    finally: os.close(parent)
def _purge_owned_tree(parent_fd, name, depth=0):
    _fail(depth <= 8 and type(name) is str and name not in {"", ".", ".."} and "/" not in name)
    observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISDIR(observed.st_mode):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            names = os.listdir(descriptor); _fail(len(names) <= 256)
            for child in sorted(names): _purge_owned_tree(descriptor, child, depth + 1)
            os.fsync(descriptor)
        finally: os.close(descriptor)
        os.rmdir(name, dir_fd=parent_fd)
    else: os.unlink(name, dir_fd=parent_fd)
    os.fsync(parent_fd)
def _runtime_alias():
    try: seen = os.lstat(RUNTIME_ALIAS)
    except FileNotFoundError: return False
    _fail(stat.S_ISLNK(seen.st_mode) and seen.st_uid == seen.st_gid == 0 and os.readlink(RUNTIME_ALIAS) == RUNTIME_ROOT, "runtime alias ownership"); return True
def _set_runtime_alias(present):
    descriptor = os.open("/run", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW); seen = os.fstat(descriptor)
    _fail(stat.S_ISDIR(seen.st_mode) and seen.st_uid == seen.st_gid == 0 and stat.S_IMODE(seen.st_mode) == 0o755, "runtime alias parent")
    if present: _fail(not _runtime_alias()); os.symlink(RUNTIME_ROOT, RUNTIME_ALIAS); os.chown(RUNTIME_ALIAS, 0, 0, follow_symlinks=False)
    else: _fail(_runtime_alias()); os.unlink(RUNTIME_ALIAS)
    _fail(_runtime_alias() == present); os.fsync(descriptor); os.close(descriptor)
def _activate_prepared_containerd(journal, completion, control, prepared_grant=None):
    """Add mutable daemon state to the already verified static runtime root."""
    _fail(type(completion) is rootfs_fs.HeldNode
          and type(control) is rootfs_fs.OperationControl)
    parent = completion.operation_fd.number; temporary = ".kata-runtime-v1.staging"
    history = journal.runtime_recovery_history()
    if not history["runtime_prepared"]:
        kata_operation._record_runtime_prepared(journal, prepared_grant)
        history = journal.runtime_recovery_history()
    if not history["runtime_stage_intents"]:
        journal.record_runtime_stage_intent({"operation_token": history["operation_token"],
            "policy_version": command_policy.RUNTIME_POLICY_VERSION,
            "policy_sha256": command_policy.RUNTIME_POLICY_SHA256, "temporary_name": temporary})
    names = os.listdir(parent)
    _fail(not history["runtime_staged"], "runtime already staged")
    # Immutable preparation publishes only the exact static bin directory.
    # This mutable launch transaction verifies those bytes in place and adds
    # only daemon configuration/state; it never extracts executable custody.
    if temporary in names or "kata-runtime-v1" not in names:
        journal.record_uncertain("identity-mismatch")
        raise KataRuntimeError("immutable prepared runtime absent")
    runtime_fd = os.open("kata-runtime-v1", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=parent)
    try:
        _fail(set(os.listdir(runtime_fd)) == {"bin", "configuration-qemu-observer.toml"},
              "prepared runtime observer configuration differs")
        bin_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=runtime_fd)
        try:
            _fail(set(os.listdir(bin_fd)) == {"containerd", "ctr"})
            for path, expected_size, digest, mode in command_policy.CONTAINERD_EXTRACTION:
                name = path.rpartition("/")[2]
                descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=bin_fd)
                try:
                    seen = os.fstat(descriptor)
                    _fail(stat.S_ISREG(seen.st_mode) and seen.st_uid == seen.st_gid == 0
                          and seen.st_nlink == 1 and stat.S_IMODE(seen.st_mode) == mode
                          and seen.st_size == expected_size)
                    offset = 0; digest_seen = hashlib.sha256()
                    while offset < expected_size:
                        chunk = os.read(descriptor, min(1024 * 1024, expected_size - offset)); _fail(chunk)
                        digest_seen.update(chunk); offset += len(chunk)
                    _fail(not os.read(descriptor, 1) and digest_seen.hexdigest() == digest)
                finally: os.close(descriptor)
        finally: os.close(bin_fd)
        config = os.open("containerd.toml", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                         0o600, dir_fd=runtime_fd)
        try:
            offset = 0
            while offset < len(CONTAINERD_CONFIG_BYTES):
                count = os.write(config, CONTAINERD_CONFIG_BYTES[offset:]); _fail(count > 0); offset += count
            os.fchown(config, 0, 0); os.fchmod(config, 0o600); os.fsync(config)
        finally: os.close(config)
        for name in ("r", "t"): os.mkdir(name, 0o700, dir_fd=runtime_fd); descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=runtime_fd); os.fchown(descriptor, 0, 0); os.fchmod(descriptor, 0o700); os.close(descriptor)
        os.fsync(runtime_fd); os.fsync(parent); _set_runtime_alias(True)
    except BaseException:
        os.close(runtime_fd)
        if _runtime_alias(): _set_runtime_alias(False)
        if "kata-runtime-v1" in os.listdir(parent): _purge_owned_tree(parent, "kata-runtime-v1")
        raise
    else:
        os.close(runtime_fd)
    runtime = bin_node = None; nodes = []
    try:
        runtime = rootfs_fs._open_path_node(completion, rootfs_fs._name("kata-runtime-v1"), "directory", control)
        bin_node = rootfs_fs._open_path_node(runtime, rootfs_fs._name("bin"), "directory", control)
        for parent_node, name, kind in ((bin_node, "containerd", "file"), (bin_node, "ctr", "file"),
                (runtime, "containerd.toml", "file"), (runtime, "r", "directory"),
                (runtime, "t", "directory")):
            nodes.append(rootfs_fs._open_path_node(parent_node, rootfs_fs._name(name), kind, control))
        for node, manifest in zip(nodes[:2], command_policy.CONTAINERD_EXTRACTION, strict=True):
            _fail(hashlib.sha256(rootfs_fs._read_regular(node, manifest[1], control)).hexdigest() == manifest[2])
        _fail(rootfs_fs._read_regular(nodes[2], len(CONTAINERD_CONFIG_BYTES), control) == CONTAINERD_CONFIG_BYTES)
        context = kata_operation._command_context(journal)
        body = {"operation_token": context.operation_token, "policy_version": command_policy.RUNTIME_POLICY_VERSION,
                "policy_sha256": command_policy.RUNTIME_POLICY_SHA256,
                "archive_sha256": command_policy.CONTAINERD_ARCHIVE_SHA256,
                "archive_size": command_policy.CONTAINERD_ARCHIVE_SIZE,
                "extraction_sha256": command_policy.CONTAINERD_EXTRACTION_SHA256,
                "runtime_generation": kata_operation._generation_value(runtime.generation),
                **{name: kata_operation._generation_value(node.generation) for name, node in zip(
                    ("containerd_generation", "ctr_generation", "config_generation", "root_generation",
                     "state_generation"), nodes, strict=True)}}
        journal.record_runtime_staged(body); return runtime
    except BaseException:
        if runtime is not None: rootfs_fs._close_node(runtime)
        if _runtime_alias(): _set_runtime_alias(False)
        if "kata-runtime-v1" in os.listdir(parent): _purge_owned_tree(parent, "kata-runtime-v1")
        raise
    finally:
        for node in nodes: rootfs_fs._close_node(node)
        if bin_node is not None: rootfs_fs._close_node(bin_node)
def _runtime_owner_routes():
    seal = object(); attestations = {}; daemons = {}; owners = {}; socket_contract = (("s", ".s.removing"), ("s.ttrpc", ".s.ttrpc.removing")); all_socket_names = {name for pair in socket_contract for name in pair}
    _Attestation = owner_helpers.sealed_type("_Attestation", seal, KataRuntimeError)
    _Daemon = owner_helpers.sealed_type("_Daemon", seal, KataRuntimeError)
    _Owner = owner_helpers.sealed_type("_Owner", seal, KataRuntimeError)
    def stable(left, right): return all(left[field] == right[field] for field in kata_operation.GEN_KEYS[:7])
    def socket_identity(observed, expected, name, active, quarantine):
        if name == active: return observed == expected
        return name == quarantine and all(observed[field] == expected[field] for field in kata_operation.GEN_KEYS[:-1])
    def snapshot_child(snapshot, name):
        for child_name, generation in snapshot.children:
            if child_name == name: return generation
        return None
    def open_snapshot_child(parent, snapshot, name, kind, control):
        generation = snapshot_child(snapshot, name)
        if generation is None: return None
        node = rootfs_fs._open_path_node(parent, name, kind, control)
        try: _fail(node.generation == generation, "runtime child pathname replacement")
        except BaseException as error: rootfs_fs._close_node(node, error)
        return node
    def inventory(node):
        import completion_kata_process as process
        top = kata_operation._generation_value(node.generation); _fail(top["kind"] == "directory" and top["mode"] == 0o700 and top["uid"] == top["gid"] == 0); rows = []
        def walk(parent, depth):
            _fail(depth <= 8); names = os.listdir(parent); _fail(len(names) <= 256)
            for name in names:
                _fail(type(name) is str and name not in {"", ".", ".."} and "/" not in name and "\0" not in name); descriptor = os.open(name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    seen = process._host_generation(descriptor); _fail(seen["mount_id"] == top["mount_id"] and seen["device"] == top["device"] and seen["uid"] == seen["gid"] == 0); rows.append((seen["device"], seen["inode"])); _fail(len(rows) <= 4096)
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
                        try: walk(child, depth + 1)
                        finally: os.close(child)
                finally: os.close(descriptor)
        walk(node.operation_fd.number, 0); return tuple(rows)
    def retain_daemon(journal, completion, process_owner, control, prepared_grant=None):
        import completion_kata_process as process
        history = journal.runtime_recovery_history()
        if history["tip"] in {"COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2", "COMMAND_OUTPUT_V3"}: process._recover_pending_fixed(journal); history = journal.runtime_recovery_history()
        active = len(history["daemon_retained"]) == len(history["daemon_outcomes"]) + 1
        stopped = len(history["daemon_retained"]) == len(history["daemon_outcomes"]) == 1
        inactive = not history["daemon_retained"] and not history["daemon_outcomes"]
        staged_only = inactive and bool(history["runtime_stage_intents"])
        pristine = inactive and not history["runtime_stage_intents"] and not history["runtime_staged"]
        if pristine:
            prepared = prestage_runtime.retain(journal, completion, prepared_grant, control)
            value = _Daemon(seal); daemons[value] = [journal, completion, None, control, None, None,
                None, None, None, None, {}, prepared]; return value
        if active and process_owner is None: process_owner = process._reopen_fixed_daemon(journal)
        _fail(type(completion) is rootfs_fs.HeldNode and type(control) is rootfs_fs.OperationControl and ((stopped or staged_only or pristine) and process_owner is None or active and
                   process._verify_fixed_daemon(process_owner, journal) == history["daemon_retained"][-1]))
        completion_snapshot = rootfs_fs._enumerate_stable(completion, control)
        completion_names = {name.text for name in completion_snapshot.names}
        if (inactive and not history["runtime_staged"]
                and (completion_names & {".kata-runtime-v1.staging", "kata-runtime-v1"} or _runtime_alias())):
            journal.record_uncertain("identity-mismatch")
            raise KataRuntimeError("identity-free staged runtime residue")
        runtime_name = rootfs_fs._name("kata-runtime-v1")
        observed = snapshot_child(completion_snapshot, runtime_name)
        if observed is None:
            _fail(stopped or staged_only or pristine, "active private runtime root absent"); runtime = config = root = daemon_state = None; socket_names = set()
        else:
            runtime = open_snapshot_child(completion, completion_snapshot, runtime_name, "directory", control)
            runtime_snapshot = rootfs_fs._enumerate_stable(runtime, control)
            names = {name.text for name in runtime_snapshot.names}; base_names = {"bin", "configuration-qemu-observer.toml", "containerd.toml", "r", "t"}; socket_names = names & all_socket_names; expected = base_names | socket_names
            _fail(_runtime_alias() and names <= expected and all(len(names & set(pair)) <= 1 for pair in socket_contract) and (not active or names == base_names | {pair[0] for pair in socket_contract}), "private runtime names")
            def optional(name, kind): return open_snapshot_child(
                runtime, runtime_snapshot, rootfs_fs._name(name), kind, control)
            config = optional("containerd.toml", "file"); root = optional("r", "directory"); daemon_state = optional("t", "directory")
            _fail(stopped or staged_only or pristine or all(node is not None for node in (config, root, daemon_state)))
            if config is not None: _fail(rootfs_fs._read_regular(config, len(CONTAINERD_CONFIG_BYTES), control) == CONTAINERD_CONFIG_BYTES)
            if history["runtime_staged"]:
                staged = history["runtime_staged"][0]; _fail(len(history["runtime_staged"]) == 1)
                current = kata_operation._generation_value(runtime.generation); _fail(all(staged["runtime_generation"][field] == current[field] for field in kata_operation.GEN_KEYS[:7]))
                for field, node in (("config_generation", config), ("root_generation", root), ("state_generation", daemon_state)):
                    if node is not None: _fail(staged[field] == kata_operation._generation_value(node.generation) if field == "config_generation" else stable(staged[field], kata_operation._generation_value(node.generation)))
        retained = None if inactive else history["daemon_retained"][-1]; sockets = {active_name: None for active_name, _quarantine in socket_contract}
        for active_name, quarantine in socket_contract:
            matches = socket_names & {active_name, quarantine}
            if not matches: continue
            name = matches.pop(); descriptor = os.open(name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=runtime.operation_fd.number)
            expected_generation = None if retained is None else retained["socket_generations"][active_name]["generation"]
            if expected_generation is None or not socket_identity(process._host_generation(descriptor, "socket"), expected_generation, name, active_name, quarantine): os.close(descriptor); _fail(False, "foreign daemon socket")
            sockets[active_name] = (descriptor, name)
        _fail(not active or all(sockets[name] is not None for name, _quarantine in socket_contract)); inventories = {name: inventory(node) for name, node in (("root", root), ("state", daemon_state)) if node is not None}
        value = _Daemon(seal); daemons[value] = [journal, completion, process_owner, control, runtime, config, root, daemon_state, retained, sockets, inventories]
        return value
    def issue_attestation_core(executable_owner, config, control, roles):
        import completion_kata_process as process
        import completion_kata_preparation as preparation
        _fail(type(config) is rootfs_fs.HeldNode
              and type(control) is rootfs_fs.OperationControl,
              "fixed runtime attestation inputs")
        executables = []; base_fd = -1
        try:
            for role in roles: executables.append(process._claim_attested_executable(executable_owner, role))
            expected = (("containerd", STAGED_CONTAINERD), ("ctr", STAGED_CTR),
                        ("shim", "/opt/kata/bin/containerd-shim-kata-v2"), ("qemu", "/opt/kata/bin/qemu-system-x86_64"),
                        ("virtiofsd", "/opt/kata/libexec/virtiofsd"))[-len(roles):]
            _fail(tuple((item.role, item.path) for item in executables) == expected,
                  "fixed runtime executable roles")
            raw = rootfs_fs._read_regular(config, 4_194_304, control)
            base_fd = os.open(KATA_BASE_CONFIG, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            base, base_seen = _read_held_file(base_fd, 1_048_576)
            _fail(hashlib.sha256(base).hexdigest() == KATA_CONFIG_SHA256
                  and len(base) == preparation.KATA_BASE_CONFIGURATION_SIZE
                  and _file_identity(os.stat(KATA_BASE_CONFIG, follow_symlinks=False))
                      == _file_identity(base_seen), "fixed Kata base configuration")
            derived = preparation.derive_observer_configuration(base)
            digest = hashlib.sha256(raw).hexdigest()
            _fail(raw == derived and config.generation.key.kind == "file"
                  and config.generation.mode == 0o400
                  and config.generation.uid == config.generation.gid == 0,
                  "fixed active Kata observer configuration")
            value = _Attestation(seal)
            attestations[value] = [tuple(executables), config, control, digest,
                                   hashlib.sha256(base).hexdigest(), base_fd,
                                   _file_identity(base_seen)]
            base_fd = -1
            return value
        except BaseException as primary:
            errors = [primary]
            if base_fd >= 0:
                try: os.close(base_fd)
                except BaseException as error: errors.append(error)
            for executable in reversed(executables):
                try: process._release_attested_executable(executable)
                except BaseException as error: errors.append(error)
            if len(errors) == 1: raise
            raise BaseExceptionGroup("runtime attestation issuance failure", errors)
    def issue_attestation(executable_owner, config, control):
        return issue_attestation_core(executable_owner, config, control,
            ("containerd", "ctr", "shim", "qemu", "virtiofsd"))
    def issue_cleanup_attestation(executable_owner, config, control):
        return issue_attestation_core(executable_owner, config, control, ("shim", "qemu", "virtiofsd"))
    def discard_attestation(value):
        import completion_kata_process as process
        state = attestations.pop(value, None)
        _fail(state is not None, "fixed runtime attestation")
        errors = []
        for executable in reversed(state[0]):
            try: process._release_attested_executable(executable)
            except BaseException as error: errors.append(error)
        if len(state) == 7:
            try: os.close(state[5])
            except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("runtime attestation close", errors)
    def verify_attestation(value):
        import completion_kata_process as process
        state = attestations.get(value); _fail(state is not None)
        if len(state) == 4:
            # Historical offline fixtures inject a non-node sentinel directly
            # into closure state; no production issuer can create this shape.
            executables, config, control, digest = state
            _fail(type(config) is not rootfs_fs.HeldNode)
            raw = rootfs_fs._read_regular(config, 4_194_304, control)
            _fail(hashlib.sha256(raw).hexdigest() == digest)
            return executables
        executables, config, control, digest, base_digest, base_fd, base_identity = state
        raw = rootfs_fs._read_regular(config, 4_194_304, control)
        import completion_kata_preparation as preparation
        base, base_seen = _read_held_file(base_fd, 1_048_576)
        _fail(hashlib.sha256(raw).hexdigest() == digest
              and hashlib.sha256(base).hexdigest() == base_digest == KATA_CONFIG_SHA256
              and _file_identity(base_seen) == base_identity
              and _file_identity(os.stat(KATA_BASE_CONFIG, follow_symlinks=False)) == base_identity
              and raw == preparation.derive_observer_configuration(base)
              and rootfs_fs._observe_node(config.identity_fd, config.operation_fd,
                                           control) == config.generation)
        for item in executables:
            identity = process.fdmap.identity(item.descriptor); _fail(process._host_generation(item.descriptor) == item.generation and process._digest_fd(item.descriptor, identity.size) == item.sha256)
        return executables
    def verify_daemon(value, allow_unlinked=False):
        state = daemons.get(value); _fail(state is not None and type(allow_unlinked) is bool); history = state[0].runtime_recovery_history(); retained = state[8]
        _fail(len(history["daemon_retained"]) in {len(history["daemon_outcomes"]), len(history["daemon_outcomes"]) + 1} and
              (retained is None and not history["daemon_retained"] or history["daemon_retained"][-1] == retained))
        runtime_snapshot = None if state[4] is None else rootfs_fs._enumerate_stable(state[4], state[3])
        if state[5] is not None:
            _fail(rootfs_fs._read_regular(state[5], len(CONTAINERD_CONFIG_BYTES), state[3]) == CONTAINERD_CONFIG_BYTES)
            named = snapshot_child(runtime_snapshot, rootfs_fs._name("containerd.toml")); _fail(named == state[5].generation, "containerd config pathname replacement")
        if state[4] is not None:
            observed = rootfs_fs._observe_node(state[4].identity_fd, state[4].operation_fd, state[3])
            _fail(stable(kata_operation._generation_value(observed), kata_operation._generation_value(state[4].generation)))
        if state[5] is not None:
            _fail(rootfs_fs._observe_node(state[5].identity_fd, state[5].operation_fd, state[3]) == state[5].generation)
        _fail((state[4] is None) != _runtime_alias(), "runtime alias residue")
        for index, name in ((6, "r"), (7, "t")):
            node = state[index]
            if node is not None:
                observed = rootfs_fs._observe_node(node.identity_fd, node.operation_fd, state[3]); named = snapshot_child(runtime_snapshot, rootfs_fs._name(name))
                _fail(stable(kata_operation._generation_value(observed), kata_operation._generation_value(node.generation)) and named is not None and stable(kata_operation._generation_value(named), kata_operation._generation_value(node.generation))); state[10][name] = inventory(node)
        import completion_kata_process as process
        if state[4] is not None:
            names = set(os.listdir(state[4].operation_fd.number))
            for active_name, quarantine in socket_contract:
                held = state[9][active_name]; expected = retained["socket_generations"][active_name]["generation"] if retained is not None else None
                if held is None: _fail(not names & {active_name, quarantine} and len(history["daemon_retained"]) == len(history["daemon_outcomes"]), "daemon socket absent while active"); continue
                descriptor, name = held; seen = process._host_generation(descriptor, "socket")
                if allow_unlinked and name not in names:
                    _fail(not names & {active_name, quarantine} and seen["nlink"] == 0 and all(seen[field] == expected[field] for field in kata_operation.GEN_KEYS[:4]), "unlinked daemon socket identity")
                else:
                    _fail(socket_identity(seen, expected, name, active_name, quarantine)); fresh = os.open(name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=state[4].operation_fd.number)
                    try: _fail(process._host_generation(fresh, "socket") == seen, "containerd socket pathname replacement")
                    finally: os.close(fresh)
        if len(history["daemon_retained"]) == len(history["daemon_outcomes"]) + 1: _fail(all(state[9][name] is not None and state[9][name][1] == name for name, _quarantine in socket_contract) and process._verify_fixed_daemon(state[2], state[0]) == retained)
        return retained
    def compose(journal, lease, inputs, network, attestation, daemon, control):
        history = journal.runtime_recovery_history(); _fail(history["phase"] in {"NETWORK_READY", "RUNTIME_READY", "SSH_READY", "READINESS_REVOKED",
              "OWNERSHIP_OBSERVED", "TASK_STOPPED", "TASK_ABSENT", "RUNTIME_ABSENT", "NETWORK_ABSENT", "CONTAINER_ABSENT", "SHARE_ABSENT", "FIREWALL_ABSENT", "CONTAINERD_ABSENT", "UNCERTAIN", "RUNTIME_CLEANUP_ONLY"})
        _fail(type(lease) is rootfs_lease.RetainedRootfsLease and lease.disposition == "held"); reference = rootfs_lease._verify(lease, control)
        input_grant = kata_inputs._claim_runtime_inputs(inputs, journal); network_grant = (None if history["runtime_network_released"] or history["phase"] in {"NETWORK_ABSENT", "CONTAINER_ABSENT",
            "SHARE_ABSENT", "FIREWALL_ABSENT", "CONTAINERD_ABSENT", "RUNTIME_CLEANUP_ONLY"} else kata_network._claim_runtime_network(network, journal))
        input_binding = kata_inputs._consume_runtime_inputs(input_grant)
        netns = None if network_grant is None else kata_network._verify_runtime_network(network_grant); host_netns = os.readlink("/proc/self/ns/net"); _fail(re.fullmatch(r"net:\[[1-9][0-9]*\]", host_netns) is not None, "host netns baseline")
        verify_attestation(attestation); verify_daemon(daemon); owner = _Owner(seal); owners[owner] = [journal, lease, reference, input_binding, netns,
            attestation, daemon, control, input_grant, network_grant, inputs, network, host_netns,
            None if not history["runtime_role_identities"] else tuple(history["runtime_role_identities"][0]["roles"]),
            None if not history["runtime_share_identities"] else {name: history["runtime_share_identities"][0][name]
                for name in ("root_generation", "parent_generation", "layout_sha256")}]
        return owner
    def recover_pending(state, stop=True):
        history = state[0].runtime_recovery_history()
        if history["tip"] in {"COMMAND_INTENT_V2", "COMMAND_PREEXEC_V2", "COMMAND_OUTPUT_V3"}:
            import completion_kata_process as process
            process._recover_pending_fixed(state[0])
            if stop: raise KataRuntimeError("cleanup-only uncertain command")
        return history
    def verify_consumption(owner, journal, command_id):
        state = owners.get(owner); _fail(type(owner) is _Owner and state is not None and state[0] is journal)
        rootfs_lease._verify(state[1], state[7]); verify_attestation(state[5]); verify_daemon(state[6])
        if command_id == "CTR_RUN":
            kata_inputs._verify_runtime_inputs(state[8]); _fail(kata_network._verify_runtime_network(state[9]) == state[4])
    def start_composed(journal, lease, inputs, network, attestation, completion, control):
        executables = verify_attestation(attestation)
        daemon_owner = _start_private_containerd(journal, executables[0])
        daemon = None
        try:
            daemon = retain_daemon(journal, completion, daemon_owner, control)
            return compose(journal, lease, inputs, network, attestation, daemon, control)
        except BaseException as error:
            failures = [error]
            try:
                if daemon is not None: shutdown_daemon(daemon)
                else:
                    import completion_kata_process as process
                    process._stop_fixed_daemon(daemon_owner, journal)
            except BaseException as cleanup_error: failures.append(cleanup_error)
            if len(failures) == 1: raise
            raise BaseExceptionGroup("runtime composition/rollback failure", failures)
    def bind_mount(owner):
        state = owners.get(owner); _fail(state is not None, "fixed runtime owner")
        identity, generations = state[3]
        _fail(identity.operation_token == state[0].command_context().operation_token
              and generations, "fixed runtime input binding")
        return kata_operation._record_runtime_mount_from_owner(
            state[0], identity.manifest_sha256,
            kata_operation._generation_value(generations[-1]))
    def launch(owner):
        import completion_kata_process as process
        state = owners.get(owner); _fail(state is not None); recover_pending(state)
        history = state[0].runtime_recovery_history(); _fail(history["phase"] == "NETWORK_READY")
        runs = [row for row in history["intents"] if row["command_id"] == "CTR_RUN"]; _fail(len(runs) <= 1)
        root = rootfs_lease._verify(state[1], state[7]); _fail(root == state[2] and state[4] is not None); kata_inputs._verify_runtime_inputs(state[8]); netns = kata_network._verify_runtime_network(state[9])
        _fail(netns == state[4]); retained = verify_daemon(state[6]); executables = verify_attestation(state[5]); ctr = executables[1]
        probe = step(owner, "NETWORK_READY", 1, actions.CommandId.CTR_CONTAINER_LIST); _fail(classify_container_list(probe[0]) is Observation.ABSENT and not probe[1] and verify_daemon(state[6]) == retained, "usable retained containerd before launch")
        history = state[0].runtime_recovery_history(); runs = [row for row in history["intents"] if row["command_id"] == "CTR_RUN"]; _fail(len(runs) <= 1)
        if not runs:
            permit = _make_operation_launch_permit(state[9])
            launch = _claim_launch_permit(permit)
            _fail(launch["operation_token"] == history["operation_token"]
                  and launch["network"] == operation_netns_path(history["operation_token"])
                  and launch["mount"] == MOUNT_LIST_SHA256)
            outcome, durable = process._transact_fixed(
                state[0], process._bind_ctr_run_extension(root.token), ctr,
                daemon_owner=daemons[state[6]][2], consumption_owner=owner,
                launch_permit=permit)
        else:
            run = runs[0]; matches = [row for row in history["outcomes"] if row["command_serial"] == run["command_serial"]]
            _fail(len(matches) == 1, "CTR_RUN resume outcome")
            durable = kata_operation.DurableCommandOutcome(run["command_serial"], "CTR_RUN", run["binding_sha256"], matches[0])
        success = durable.body["outcome"] == "exited" and durable.body["status"] == 0 and not durable.body["uncertain"]
        if not success:
            _fail(not durable.body["uncertain"], "uncertain CTR_RUN preserved")
            state[0].revoke_readiness(); raise KataRuntimeError("certain CTR_RUN failure")
        _fail(verify_daemon(state[6]) == retained, "retained daemon changed during launch")
        fact = {"version": V2, "command": "CTR_RUN", "binding": durable.binding_sha256, "observation_binding": probe[2]["binding_sha256"], "daemon_binding": retained["binding_sha256"], "daemon_pid": retained["pid"], "daemon_starttime": retained["proc_start_time"], "daemon_sockets": {name: _canonical_fact(retained["socket_generations"][name]) for name, _quarantine in socket_contract}, "journal": state[0].runtime_recovery_history()["terminal_sha256"]}
        state[0].settle_runtime_phase("RUNTIME_READY", _canonical_fact(fact)); return fact
    def saved_output(state, phase, index, command_id):
        history = state[0].runtime_recovery_history(); intents = [row for row in history["intents"] if row["lifecycle_phase"] == phase]
        if len(intents) <= index: return None
        intent = intents[index]; _fail(intent["command_id"] == command_id.value)
        outcomes = [row for row in history["outcomes"] if row["command_serial"] == intent["command_serial"]]; outputs = [row for row in history["outputs"] if row["command_serial"] == intent["command_serial"]]
        _fail(len(outcomes) == len(outputs) == 1 and outcomes[0]["outcome"] == "exited" and not outcomes[0]["uncertain"])
        stdout, stderr = bytes.fromhex(outputs[0]["stdout_hex"]), bytes.fromhex(outputs[0]["stderr_hex"])
        _fail(outcomes[0]["stdout_sha256"] == hashlib.sha256(stdout).hexdigest() and outcomes[0]["stderr_sha256"] == hashlib.sha256(stderr).hexdigest()
              and (outcomes[0]["status"] == 0 and not stderr or command_id is actions.CommandId.CTR_CONTAINER_INFO and outcomes[0]["status"] != 0))
        return stdout, stderr, outcomes[0]
    def command(owner, command_id, observer=False):
        import completion_kata_process as process
        state = owners[owner]; recover_pending(state); verify_daemon(state[6]); executables = verify_attestation(state[5]); ctr = executables[1]; fixed = process._bind_ctr_extension(command_id)
        outcome, durable = process._transact_fixed(state[0], fixed, ctr, daemon_owner=daemons[state[6]][2], consumption_owner=owner)
        kata_operation._durable_command_output(state[0], durable.command_serial, durable.command_id, durable.binding_sha256, outcome.stdout, outcome.stderr)
        certain = outcome.outcome == "exited" and outcome.errors == () and outcome.reaped and not durable.body["uncertain"]
        if observer:
            _fail(certain and (outcome.status == 0 and not outcome.stderr or command_id is actions.CommandId.CTR_CONTAINER_INFO and outcome.status != 0), "fixed ctr observer")
            return outcome.stdout, outcome.stderr, durable.body
        _fail(certain and outcome.status == 0 and not outcome.stderr, "fixed ctr command"); return outcome.stdout, durable.body
    def step(owner, phase, index, command_id):
        saved = saved_output(owners[owner], phase, index, command_id); return command(owner, command_id, True) if saved is None else saved
    def observe(owner):
        state = owners[owner]; recover_pending(state); history = state[0].runtime_recovery_history(); netns = state[4]
        _fail(history["phase"] in {"RUNTIME_READY", "READINESS_REVOKED"})
        sequence = ((actions.CommandId.CTR_CONTAINER_INFO, actions.CommandId.CTR_CONTAINER_LIST, actions.CommandId.CTR_TASK_LIST) if history["phase"] == "RUNTIME_READY" else
                    (actions.CommandId.CTR_TASK_LIST, actions.CommandId.CTR_CONTAINER_INFO, actions.CommandId.CTR_CONTAINER_LIST))
        results = [step(owner, history["phase"], index, item) for index, item in enumerate(sequence)]
        values = [(row[2]["status"], row[0], row[1]) for row in results]
        if history["phase"] == "RUNTIME_READY": info, containers, tasks = values
        else: tasks, info, containers = values
        processes = _proc_snapshot(verify_attestation(state[5]), netns, state[12]); shim = next((row for row in processes.records if row.role == "shim"), None)
        ctr = classify_ctr_observation(info, containers, tasks, None if shim is None else shim.pid,
                                       state[9], _durable_ctr_launch_path(history)); container, task, mount = ctr["container"], ctr["task"], ctr["mount"]
        forward_observation = history["phase"] == "RUNTIME_READY"
        if forward_observation: state[0].record_platform_observation("qmp-intent")
        try:
            qmp = _qmp_kvm(processes)
        except BaseException:
            # A failed terminal-marker write leaves the read-only QMP intent
            # uncertain and therefore unable to mint a receipt.
            if forward_observation: state[0].record_platform_observation("qmp-failure")
            raise
        if forward_observation:
            qmp_passed = qmp.get("kvm_present") is True and qmp.get("kvm_enabled") is True
            state[0].record_platform_observation("qmp-pass" if qmp_passed else "qmp-failure")
            history = state[0].runtime_recovery_history()
        share = _share_fact(); verify_daemon(state[6]); fact = {"version": V2, "journal": history["terminal_sha256"], "mount": mount, "container": container.value, "task": task, "task_pid": None if shim is None else shim.pid,
                "processes": processes.disposition.value, "qmp": qmp, "share": share}
        return fact
    def inactive_fact(state):
        history = state[0].runtime_recovery_history(); processes = _proc_snapshot(verify_attestation(state[5]), state[4], state[12]); qmp = _qmp_kvm(processes); share = _share_fact()
        _fail(not history["daemon_retained"] and not history["daemon_outcomes"] and not any(row["command_id"] == "CTR_RUN" for row in history["intents"]), "unstarted runtime history differs")
        _fail(processes.disposition is Observation.ABSENT and qmp["state"] == "absent" and share["state"] == "absent", "unstarted runtime residue is foreign")
        return {"version": V2, "journal": history["terminal_sha256"], "mount": None, "container": "absent", "task": "absent", "task_pid": None, "processes": "absent", "qmp": qmp, "share": share}
    def settle_inactive(state, phase, field=None):
        fact = inactive_fact(state); value = fact if field is None else fact[field]
        state[0].settle_runtime_phase(phase, _canonical_fact(value)); return value
    def role_identity(row, generation):
        return {"role": row.role, "pid": row.pid, "starttime": row.starttime,
                "executable": row.executable, "executable_device": row.executable_device,
                "executable_inode": row.executable_inode, "executable_generation": generation,
                "namespaces": [list(item) for item in row.namespaces]}
    def ownership(owner):
        state = owners[owner]
        fact = (inactive_fact(state) if daemons[state[6]][8] is None else observe(owner))
        values = {"task": "exact-owned" if fact["task"] in {"running", "stopped"} else fact["task"],
            "container": "exact-owned" if fact["container"] == "exact" else fact["container"],
            "runtime": "exact-owned" if fact["processes"] == "exact" else fact["processes"],
            "share": "exact-owned" if fact["share"]["state"] == "active-exact" else fact["share"]["state"]}
        _fail(set(values.values()) <= {"exact-owned", "absent"})
        history = state[0].runtime_recovery_history()
        if values["runtime"] == "exact-owned":
            executables = verify_attestation(state[5]); attested = {item.role: item.generation for item in executables}
            processes = _proc_snapshot(executables, state[4], state[12])
            _fail(processes.disposition is Observation.EXACT, "runtime role ownership changed")
            roles = tuple(sorted((role_identity(row, attested[row.role]) for row in processes.records),
                                 key=lambda row: ("shim", "qemu", "virtiofsd").index(row["role"])))
            body = {"operation_token": history["operation_token"], "roles": list(roles)}
            if not history["runtime_role_identities"]: state[0].record_runtime_role_identities(body)
            else: _fail(history["runtime_role_identities"] == (body,), "runtime role identity replacement")
            state[13] = roles
        if values["share"] == "exact-owned":
            share_body = {"operation_token": history["operation_token"], **{name: fact["share"][name]
                          for name in ("root_generation", "parent_generation", "layout_sha256")}}
            if not history["runtime_share_identities"]: state[0].record_runtime_share_identity(share_body)
            else: _fail(history["runtime_share_identities"] == (share_body,), "share identity replacement")
            state[14] = {name: share_body[name] for name in
                         ("root_generation", "parent_generation", "layout_sha256")}
        state[0].settle_runtime_phase("OWNERSHIP_OBSERVED", _canonical_fact(fact), values); return fact
    def phase_progress(state, phase):
        history = state[0].runtime_history()
        return tuple(row["command_id"] for row in history["intents"] if row["lifecycle_phase"] == phase)
    def identity_body(state, shim):
        return {"operation_token": state[0].runtime_recovery_history()["operation_token"], "pid": shim.pid, "starttime": shim.starttime, "executable_device": shim.executable_device, "executable_inode": shim.executable_inode, "namespaces": [list(row) for row in shim.namespaces]}
    def same_identity(shim, body):
        return shim is not None and (shim.pid, shim.starttime, shim.executable_device, shim.executable_inode, [list(row) for row in shim.namespaces]) == (body["pid"], body["starttime"], body["executable_device"], body["executable_inode"], body["namespaces"])
    def task_fact(owner, phase, index, expected_pid):
        state = owners[owner]; raw = step(owner, phase, index, actions.CommandId.CTR_TASK_LIST)[0]; processes = _proc_snapshot(verify_attestation(state[5]), state[4], state[12])
        shim = next((row for row in processes.records if row.role == "shim"), None); pid = (None if shim is None else shim.pid) if expected_pid is None else expected_pid
        task = classify_task_list(raw, pid); return {"task": task, "task_pid": pid, "processes": processes.disposition.value}, shim
    def await_runtime_roles_absent(state):
        """Observation-only, identity-stable retirement under one boottime deadline."""
        import completion_kata_process as process
        history = state[0].runtime_recovery_history()
        _fail(len(history["runtime_role_identities"]) == 1, "durable runtime role identities absent")
        baseline = {row["role"]: row for row in history["runtime_role_identities"][0]["roles"]}
        _fail(set(baseline) == {"shim", "qemu", "virtiofsd"})
        disappeared = set(); consecutive = 0; observations = 0
        count = command_policy.RUNTIME_RETIREMENT_OBSERVATIONS
        interval = command_policy.RUNTIME_RETIREMENT_INTERVAL_NS
        start = process._boottime_ns(); deadline = start + count * interval
        for ordinal in range(count):
            target = start + ordinal * interval
            remaining = target - process._boottime_ns()
            if remaining > 0: time.sleep(remaining / 1_000_000_000)
            executables = verify_attestation(state[5]); attested = {item.role: item.generation for item in executables}
            snapshot = _proc_snapshot(executables, state[4], state[12])
            observations += 1
            current, disappeared = _retirement_identity_rows(baseline, snapshot, disappeared)
            for role, row in current.items():
                _fail(role_identity(row, attested[role]) == baseline[role],
                      "runtime executable generation replacement")
            qmp = _qmp_kvm(snapshot)
            all_absent = not current and qmp.get("state") == "absent"
            consecutive = consecutive + 1 if all_absent else 0
            if consecutive == 2:
                return {"operation_token": history["operation_token"], "observations": observations,
                        "roles": {role: "absent" for role in ("shim", "qemu", "virtiofsd")},
                        "qmp": "absent"}
            if process._boottime_ns() >= deadline: break
        raise KataRuntimeError("bounded runtime role retirement not observed")
    def release_network(owner):
        state = owners[owner]; history = state[0].runtime_recovery_history()
        _fail(history["phase"] == "RUNTIME_ABSENT", "runtime network release order")
        if history["runtime_network_released"]:
            _fail(state[9] is None and state[11] is None, "released runtime network reopened")
            return history["runtime_network_released"][0]
        _fail(state[11] is not None and state[9] is not None, "runtime network owner absent")
        released = kata_network._close_runtime_network(state[11], state[9])
        state[9] = state[11] = None
        _fail(released == {"owner_closed": True, "grants_closed": True,
                           "registry_empty": True, "closed_grants": 1},
              "runtime network registry not empty")
        body = {"operation_token": history["operation_token"], "owner_closed": True,
                "grants_closed": True, "registry_empty": True, "proof_sha256": "0" * 64}
        body["proof_sha256"] = _canonical_fact({name: value for name, value in body.items()
                                                  if name != "proof_sha256"})
        state[0].record_runtime_network_released(body); return body
    def cleanup(owner):
        state = owners[owner]; recover_pending(state, False); history = state[0].runtime_recovery_history(); phase = history["phase"]
        _fail(phase in {"NETWORK_READY", "OWNERSHIP_OBSERVED", "TASK_STOPPED", "TASK_ABSENT",
                        "RUNTIME_ABSENT", "NETWORK_ABSENT", "CONTAINER_ABSENT", "FIREWALL_ABSENT",
                        "CONTAINERD_ABSENT", "UNCERTAIN", "RUNTIME_CLEANUP_ONLY"})
        if phase == "RUNTIME_CLEANUP_ONLY":
            try: shutdown_daemon(state[6])
            finally: close(owner)
            return {"runtime": "cleanup-only-absent"}
        if phase in {"UNCERTAIN", "NETWORK_READY"}:
            terminal = history["outcomes"][-1]["command_id"] if phase == "UNCERTAIN" and history["tip"] == "COMMAND_OUTCOME_V2" else None
            daemon_cut = phase == "UNCERTAIN" and history["tip"] == "DAEMON_OUTCOME_V2"
            if daemon_cut and history["daemon_outcomes"][-1]["uncertain"]:
                raise KataRuntimeError("uncertain daemon closure preserved")
            if terminal in {"CTR_RUN", "CTR_TASK_TERM", "CTR_TASK_KILL"} or daemon_cut:
                target = state[0].resume_runtime_cleanup()
                return ownership(owner) if target in {"RUNTIME_READY", "READINESS_REVOKED"} else cleanup(owner)
            try: shutdown_daemon(state[6])
            finally: close(owner)
            return {"runtime": "cleanup-only-absent"}
        if phase == "OWNERSHIP_OBSERVED":
            ownership_rows = history["runtime_ownership"]; _fail(len(ownership_rows) == 1)
            if ownership_rows[0]["task"] == "absent":
                _fail(ownership_rows[0]["runtime"] == "absent", "task-absent runtime still owned")
                fact = {"runtime": "absent", "roles": {role: "absent" for role in ("shim", "qemu", "virtiofsd")}}
                state[0].settle_runtime_phase("RUNTIME_ABSENT", _canonical_fact(fact)); return fact
            _fail(daemons[state[6]][8] is not None)
            progress = phase_progress(state, phase); identities = history["runtime_identities"]
            if not identities:
                before, shim = task_fact(owner, phase, 0, None)
                _fail(before["task"] in {"running", "stopped"} and shim is not None)
                state[0].record_runtime_identity(identity_body(state, shim)); identities = state[0].runtime_recovery_history()["runtime_identities"]
            _fail(len(identities) == 1); baseline = identities[0]; pid = baseline["pid"]
            progress = phase_progress(state, phase)
            if "CTR_TASK_TERM" not in progress:
                fresh = _proc_snapshot(verify_attestation(state[5]), state[4], state[12]); shim = next(
                    (row for row in fresh.records if row.role == "shim"), None)
                _fail(same_identity(shim, baseline), "full task identity before TERM")
                _out, term = command(owner, actions.CommandId.CTR_TASK_TERM)
                _fail(term["release_count"] == 1 and term["outcome"] == "exited" and term["status"] == 0
                      and not term["uncertain"], "successful released TERM")
            progress = phase_progress(state, phase)
            if progress.count("CTR_TASK_LIST") < 2:
                limit = time.monotonic_ns() + 2_000_000_000
                while time.monotonic_ns() < limit:
                    fresh = _proc_snapshot(verify_attestation(state[5]), state[4], state[12]); shim = next(
                        (row for row in fresh.records if row.role == "shim"), None)
                    _fail(shim is None or same_identity(shim, baseline), "replacement after TERM")
                    if shim is None: break
                    time.sleep(0.01)
            after, shim = task_fact(owner, phase, 2, pid)
            _fail(shim is None or same_identity(shim, baseline), "full task identity after TERM")
            if after["task"] in {"stopped", "absent"}:
                state[0].settle_runtime_phase("TASK_STOPPED", _canonical_fact(after)); return after
            _fail(after["task"] == "running" and same_identity(shim, baseline))
            progress = phase_progress(state, phase)
            if "CTR_TASK_KILL" not in progress: command(owner, actions.CommandId.CTR_TASK_KILL)
            import completion_kata_process as process
            history = state[0].runtime_recovery_history(); kill = next(row for row in history["intents"] if row["lifecycle_phase"] == phase and row["command_id"] == "CTR_TASK_KILL")
            count, interval = command_policy.RUNTIME_POST_KILL_OBSERVATIONS, command_policy.RUNTIME_POST_KILL_INTERVAL_NS
            start = kill["deadline_boottime_ns"] - kill["duration_ns"]; final = min(kill["deadline_boottime_ns"], start + count * interval)
            for ordinal in range(max(0, phase_progress(state, phase).count("CTR_TASK_LIST") - 2), count):
                remaining = start + (ordinal + 1) * interval - process._boottime_ns()
                if remaining > 0: time.sleep(remaining / 1_000_000_000)
                stopped, shim = task_fact(owner, phase, 4 + ordinal, pid); _fail(shim is None or same_identity(shim, baseline), "replacement after KILL")
                if stopped["task"] in {"stopped", "absent"}: state[0].settle_runtime_phase("TASK_STOPPED", _canonical_fact(stopped)); return stopped
                _fail(stopped["task"] == "running")
                if process._boottime_ns() >= final: break
            raise KataRuntimeError("post-KILL final observation remained running")
        if phase == "TASK_STOPPED":
            _fail(daemons[state[6]][8] is not None)
            progress = phase_progress(state, phase); ownership = history["runtime_ownership"]; _fail(len(ownership) == 1)
            proven = ownership[0]["task"] == "absent"
            if not proven and "CTR_TASK_REMOVE" not in progress: command(owner, actions.CommandId.CTR_TASK_REMOVE)
            raw = step(owner, phase, 0 if proven else 1, actions.CommandId.CTR_TASK_LIST)[0]
            _fail(classify_task_list(raw, None) == "absent"); fact = {"task": "absent"}
            state[0].settle_runtime_phase("TASK_ABSENT", _canonical_fact(fact)); return fact
        if phase == "TASK_ABSENT":
            if history["runtime_role_absence"]:
                _fail(len(history["runtime_role_absence"]) == 1)
                fact = history["runtime_role_absence"][0]
            elif history["runtime_ownership"][0]["runtime"] == "absent":
                fact = {"runtime": "absent"}
            else:
                fact = await_runtime_roles_absent(state)
                state[0].record_runtime_role_absence(fact)
            state[0].settle_runtime_phase("RUNTIME_ABSENT", _canonical_fact(fact)); return fact
        if phase == "RUNTIME_ABSENT":
            return phase
        if phase == "NETWORK_ABSENT":
            if not history["runtime_ownership"]:
                share = inactive_fact(state)["share"]
                state[0].settle_runtime_phase("SHARE_ABSENT", _canonical_fact(share)); return share
            _fail(daemons[state[6]][8] is not None)
            progress = phase_progress(state, phase); ownership = history["runtime_ownership"]; _fail(len(ownership) == 1)
            proven = ownership[0]["container"] == "absent"
            if not proven and "CTR_CONTAINER_REMOVE" not in progress: command(owner, actions.CommandId.CTR_CONTAINER_REMOVE)
            raw = step(owner, phase, 0 if proven else 1, actions.CommandId.CTR_CONTAINER_LIST)[0]
            _fail(classify_container_list(raw) is Observation.ABSENT)
            fact = {"container": "absent"}; state[0].settle_runtime_phase("CONTAINER_ABSENT", _canonical_fact(fact)); return fact
        if phase == "CONTAINER_ABSENT":
            share = _share_fact(state[14])
            if share["state"] == "owned-empty-residue":
                _remove_owned_empty_share(state[14]); share = _share_fact(state[14])
            _fail(share["state"] == "absent", "share/mount residue")
            state[0].settle_runtime_phase("SHARE_ABSENT", _canonical_fact(share)); return share
        if phase == "FIREWALL_ABSENT":
            shutdown_daemon(state[6]); fact = {"containerd": "absent"}
            state[0].settle_runtime_phase("CONTAINERD_ABSENT", _canonical_fact(fact)); return fact
        return {"containerd": "absent"}
    def remove_tree(descriptor, depth=0):
        _fail(depth <= 8, "private runtime depth")
        names = os.listdir(descriptor); _fail(len(names) <= 256, "private runtime entry bound")
        for name in sorted(names):
            _fail(type(name) is str and name not in {"", ".", ".."} and "/" not in name)
            observed = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(observed.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=descriptor)
                try: remove_tree(child, depth + 1)
                finally: os.close(child)
                os.rmdir(name, dir_fd=descriptor)
            else:
                os.unlink(name, dir_fd=descriptor)
            os.fsync(descriptor)
    def discard_socket(state, allow_unlinked):
        import completion_kata_process as process
        if state[4] is None: _fail(not any(state[9].values())); return
        parent = state[4].operation_fd.number; names = set(os.listdir(parent)); verified = {}
        for active_name, quarantine in socket_contract:
            held = state[9][active_name]
            if held is None: _fail(not names & {active_name, quarantine}, "foreign daemon socket"); continue
            descriptor, name = held; expected = state[8]["socket_generations"][active_name]["generation"]; seen = process._host_generation(descriptor, "socket")
            if allow_unlinked and name not in names:
                _fail(not names & {active_name, quarantine} and seen["nlink"] == 0 and all(seen[field] == expected[field] for field in kata_operation.GEN_KEYS[:4]), "unlinked daemon socket identity"); verified[active_name] = None; continue
            _fail(name in names and socket_identity(seen, expected, name, active_name, quarantine)); fresh = os.open(name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            try: _fail(process._host_generation(fresh, "socket") == seen, "daemon socket replacement")
            finally: os.close(fresh)
            verified[active_name] = seen
        for active_name, quarantine in socket_contract:
            held = state[9][active_name]
            if held is None: continue
            descriptor, name = held; expected = state[8]["socket_generations"][active_name]["generation"]
            if verified[active_name] is None: os.close(descriptor); state[9][active_name] = None; continue
            if name != quarantine:
                _fail(quarantine not in names); os.rename(name, quarantine, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent); state[9][active_name] = (descriptor, quarantine); names.remove(name); names.add(quarantine)
            renamed = process._host_generation(descriptor, "socket"); _fail(socket_identity(renamed, expected, quarantine, active_name, quarantine), "quarantined socket identity")
            fresh = os.open(quarantine, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            try: _fail(process._host_generation(fresh, "socket") == renamed, "quarantined socket replacement")
            finally: os.close(fresh)
            os.unlink(quarantine, dir_fd=parent); os.fsync(parent); unlinked = process._host_generation(descriptor, "socket"); _fail(unlinked["nlink"] == 0 and all(unlinked[field] == expected[field] for field in kata_operation.GEN_KEYS[:4]), "daemon socket unlink proof"); os.close(descriptor); state[9][active_name] = None; names.remove(quarantine)
        _fail(not set(os.listdir(parent)) & all_socket_names and not any(state[9].values()), "daemon sockets absence")
    def shutdown_daemon(daemon):
        import completion_kata_process as process
        state = daemons[daemon]; history = state[0].runtime_recovery_history()
        if len(state) > 11 and state[11] is not None:
            prestage_runtime.cleanup(state[11]); daemons.pop(daemon); return
        def closed(value): return not value["uncertain"] and all(value[name] for name in ("leader_reaped", "descendants_reaped", "cgroup_empty", "cgroup_removed"))
        starts = [intent for intent in history["intents"] if intent["command_id"] == "CONTAINERD_START" and any(kata_operation._same_command_v2(preexec, intent) for preexec in history["preexecs"]) and not any(kata_operation._same_command_v2(retained, intent) for retained in history["daemon_retained"])]
        unclosed = [outcome for intent in starts for outcome in history["outcomes"] if kata_operation._same_command_v2(outcome, intent) and (outcome["uncertain"] or not closed(outcome))]
        _fail(not unclosed, "uncertain pre-retention daemon closure preserved")
        if history["daemon_outcomes"] and len(history["daemon_outcomes"]) == len(history["daemon_retained"]):
            _fail(closed(history["daemon_outcomes"][-1]), "uncertain daemon closure preserved")
        verify_daemon(daemon)
        if len(history["daemon_outcomes"]) < len(history["daemon_retained"]): process._stop_fixed_daemon(state[2], state[0])
        history = state[0].runtime_recovery_history(); certain = state[8] is not None
        _fail((len(history["daemon_outcomes"]) == len(history["daemon_retained"]) and
               closed(history["daemon_outcomes"][-1])) if certain else
              not history["daemon_retained"] and not history["daemon_outcomes"],
              "exact daemon closure required")
        verify_daemon(daemon, certain); discard_socket(state, certain) if certain else None
        if state[4] is not None:
            for index, name in ((7, "t"), (6, "r")):
                node = state[index]
                if node is not None: remove_tree(node.operation_fd.number); rootfs_fs._close_node(node); os.rmdir(name, dir_fd=state[4].operation_fd.number); os.fsync(state[4].operation_fd.number)
            if state[5] is not None: rootfs_fs._close_node(state[5])
            _set_runtime_alias(False); remove_tree(state[4].operation_fd.number); rootfs_fs._close_node(state[4])
            os.rmdir("kata-runtime-v1", dir_fd=state[1].operation_fd.number); os.fsync(state[1].operation_fd.number)
        if ".kata-runtime-v1.staging" in os.listdir(state[1].operation_fd.number): _purge_owned_tree(state[1].operation_fd.number, ".kata-runtime-v1.staging")
        _fail("kata-runtime-v1" not in os.listdir(state[1].operation_fd.number) and not _runtime_alias(), "private runtime absence"); daemons.pop(daemon, None)
    def close(owner):
        import completion_kata_process as process
        state = owners.pop(owner, None); _fail(type(owner) is _Owner and state is not None)
        errors = []
        try: kata_inputs._close_runtime_inputs(state[10])
        except BaseException as error: errors.append(error)
        if state[11] is not None:
            try: kata_network._close_runtime_network(state[11])
            except BaseException as error: errors.append(error)
        try: discard_attestation(state[5])
        except BaseException as error: errors.append(error)
        if errors: raise BaseExceptionGroup("fixed runtime owner close", errors)
    def reconstruct(journal, lease, input_owner, network_owner, executable_owner, completion, config, control,
                    prepared_grant=None):
        """Rebuild private cleanup indexes without issuing a start or launch."""
        _fail(journal.runtime_recovery_history()["phase"] != "UNCERTAIN")
        history = journal.runtime_recovery_history()
        issuance = (issue_cleanup_attestation if history["runtime_prepared"] and
                    not history["runtime_stage_intents"] and not history["runtime_staged"] else issue_attestation)
        attestation = issuance(executable_owner, config, control)
        try:
            daemon = retain_daemon(journal, completion, None, control, prepared_grant)
            return compose(journal, lease, input_owner, network_owner, attestation, daemon, control)
        except BaseException as primary:
            try: discard_attestation(attestation)
            except BaseException as error: raise BaseExceptionGroup("runtime cleanup reconstruction", (primary, error))
            raise
    def cleanup_staged(daemon):
        state = daemons.get(daemon); _fail(type(daemon) is _Daemon and state is not None and state[8] is None); shutdown_daemon(daemon); return {"runtime": "staged-absent"}
    return (issue_attestation, discard_attestation, retain_daemon, compose,
            reconstruct, start_composed, bind_mount, launch, observe, ownership, cleanup, release_network, close,
            cleanup_staged, verify_consumption, shutdown_daemon, verify_daemon)
(_issue_fixed_runtime_attestation, _discard_fixed_runtime_attestation,
 _retain_private_containerd, _compose_fixed_runtime, _reconstruct_fixed_runtime,
 _start_composed_runtime,
 _bind_fixed_runtime_mount, _launch_fixed_runtime,
 _observe_fixed_runtime,
 _record_fixed_runtime_ownership, _cleanup_fixed_runtime, _release_fixed_runtime_network, _close_fixed_runtime,
 _cleanup_staged_runtime, _verify_runtime_consumption, _shutdown_private_containerd,
 _verify_private_containerd) = _runtime_owner_routes()
del _runtime_owner_routes
