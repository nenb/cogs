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
import posixpath
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


_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_SCHEMA_KEYS = frozenset({
    "$schema", "$id", "title", "$defs", "$ref", "type", "const", "enum",
    "required", "additionalProperties", "properties", "items", "prefixItems",
    "minItems", "maxItems", "uniqueItems", "contains", "minContains",
    "maxContains", "minimum", "maximum", "minLength", "maxLength", "pattern",
    "allOf", "anyOf",
})
_SCHEMA_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})


def _bounded_schema_tree(value, budget, depth=0):
    _fail(depth <= 32, "schema/value depth")
    budget[0] += 1
    _fail(budget[0] <= 32_768, "schema/value node bound")
    if type(value) is dict:
        _fail(len(value) <= 1024, "schema/value object bound")
        _fail(all(type(key) is str and len(key.encode()) <= 4096 for key in value),
              "schema/value key")
        for child in value.values():
            _bounded_schema_tree(child, budget, depth + 1)
        return
    if type(value) is list:
        _fail(len(value) <= 1024, "schema/value array bound")
        for child in value:
            _bounded_schema_tree(child, budget, depth + 1)
        return
    scalar = value is None or type(value) in {str, int, bool, float}
    _fail(scalar, "schema/value scalar")
    finite = type(value) is not float or value == value and abs(value) != float("inf")
    _fail(finite, "schema/value scalar")
    if type(value) is str:
        _fail(len(value.encode()) <= MAX_JSON, "schema/value string bound")


def _json_equal(left, right):
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if set(left) != set(right):
            return False
        return all(_json_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        if len(left) != len(right):
            return False
        return all(_json_equal(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def _schema_ref(schema, root):
    reference = schema["$ref"]
    _fail(type(reference) is str and reference.startswith("#/$defs/"), "schema local ref")
    name = reference.removeprefix("#/$defs/")
    _fail(name and "/" not in name and "~" not in name, "schema ref path")
    definitions = root.get("$defs")
    _fail(type(definitions) is dict and name in definitions, "schema ref target")
    return name, definitions[name]


def _safe_schema_pattern(pattern):
    _fail(type(pattern) is str and 2 <= len(pattern) <= 256, "schema pattern")
    _fail(pattern.startswith("^") and pattern.endswith("$"), "schema anchored pattern")
    _fail(not any(char in pattern for char in "()|\\*?"), "schema unsafe pattern")
    repetitions = re.findall(r"\{([0-9]+)(?:,([0-9]+))?\}", pattern)
    _fail(all(int(value) <= 4096 for pair in repetitions for value in pair if value),
          "schema pattern repetition")
    try:
        return re.compile(pattern)
    except (re.error, OverflowError) as error:
        raise KataRuntimeError("schema pattern") from error


def _schema_child_nodes(schema):
    if type(schema) is not dict:
        return ()
    children = []
    for keyword in ("$defs", "properties"):
        if type(schema.get(keyword)) is dict:
            children.extend(schema[keyword].values())
    for keyword in ("items", "contains"):
        if keyword in schema:
            children.append(schema[keyword])
    for keyword in ("prefixItems", "allOf", "anyOf"):
        if type(schema.get(keyword)) is list:
            children.extend(schema[keyword])
    return tuple(children)


def _reject_recursive_refs(root):
    definitions = root.get("$defs", {})
    graph = {}
    for name, definition in definitions.items():
        references = set()
        pending = [definition]
        while pending:
            node = pending.pop()
            if type(node) is dict and "$ref" in node:
                target, _unused = _schema_ref(node, root)
                references.add(target)
            pending.extend(_schema_child_nodes(node))
        graph[name] = references
    complete = set()

    def visit(name, active):
        _fail(len(active) <= 32, "schema ref depth")
        _fail(name not in active, "recursive schema ref")
        if name in complete:
            return
        for child in graph[name]:
            visit(child, active | {name})
        complete.add(name)

    for name in graph:
        visit(name, set())


def _check_schema(schema, root, depth=0, root_node=False):
    _fail(depth <= 32, "schema recursion depth")
    if type(schema) is bool:
        return
    _fail(type(schema) is dict, "schema node")
    _fail(set(schema) <= _SCHEMA_KEYS, "unsupported schema keyword")
    metadata = {"$schema", "$id", "title", "$defs"} & set(schema)
    _fail(root_node or not metadata, "nested schema metadata")
    if "$schema" in schema:
        _fail(schema["$schema"] == _SCHEMA_DRAFT, "schema draft")
    if "$id" in schema:
        _fail(type(schema["$id"]) is str and 0 < len(schema["$id"]) <= 512, "schema id")
    if "title" in schema:
        _fail(type(schema["title"]) is str and 0 < len(schema["title"]) <= 512, "schema title")
    if "$defs" in schema:
        definitions = schema["$defs"]
        _fail(type(definitions) is dict and 1 <= len(definitions) <= 512, "schema defs")
        for name, child in definitions.items():
            _fail(type(name) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name) is not None,
                  "schema def name")
            _check_schema(child, root, depth + 1)
    if "$ref" in schema:
        _schema_ref(schema, root)
    if "type" in schema:
        _fail(type(schema["type"]) is str and schema["type"] in _SCHEMA_TYPES, "schema type")
    if "enum" in schema:
        choices = schema["enum"]
        _fail(type(choices) is list and choices, "schema enum")
        for index, choice in enumerate(choices):
            _fail(not any(_json_equal(choice, prior) for prior in choices[:index]), "schema enum duplicate")
    if "required" in schema:
        required = schema["required"]
        _fail(type(required) is list and all(type(name) is str for name in required), "schema required")
        _fail(len(required) == len(set(required)), "schema required duplicate")
    if "additionalProperties" in schema:
        _fail(type(schema["additionalProperties"]) is bool, "schema additional properties")
    if "properties" in schema:
        properties = schema["properties"]
        _fail(type(properties) is dict and all(type(name) is str for name in properties),
              "schema properties")
        for child in properties.values():
            _check_schema(child, root, depth + 1)
    for keyword in ("items", "contains"):
        if keyword in schema:
            _check_schema(schema[keyword], root, depth + 1)
    if "prefixItems" in schema:
        _fail(type(schema["prefixItems"]) is list, "schema prefix items")
        for child in schema["prefixItems"]:
            _check_schema(child, root, depth + 1)
    for keyword in ("allOf", "anyOf"):
        if keyword in schema:
            _fail(type(schema[keyword]) is list and schema[keyword], "schema composition")
            for child in schema[keyword]:
                _check_schema(child, root, depth + 1)
    for keyword in ("minItems", "maxItems", "minContains", "maxContains", "minLength", "maxLength"):
        if keyword in schema:
            _fail(type(schema[keyword]) is int and schema[keyword] >= 0, "schema integer bound")
    for keyword in ("minimum", "maximum"):
        if keyword in schema:
            _fail(type(schema[keyword]) in {int, float}, "schema numeric bound")
    for minimum, maximum in (("minItems", "maxItems"), ("minContains", "maxContains"),
                             ("minLength", "maxLength"), ("minimum", "maximum")):
        if minimum in schema and maximum in schema:
            _fail(schema[minimum] <= schema[maximum], "schema inverted bound")
    if "uniqueItems" in schema:
        _fail(type(schema["uniqueItems"]) is bool, "schema unique items")
    if "pattern" in schema:
        _safe_schema_pattern(schema["pattern"])
    _fail("minContains" not in schema or "contains" in schema, "schema minContains context")
    _fail("maxContains" not in schema or "contains" in schema, "schema maxContains context")


def _schema_type_matches(expected, value):
    if expected == "object":
        return type(value) is dict
    if expected == "array":
        return type(value) is list
    if expected == "string":
        return type(value) is str
    if expected == "integer":
        return type(value) is int
    if expected == "number":
        return type(value) in {int, float}
    if expected == "boolean":
        return type(value) is bool
    return value is None


def _schema_matches(schema, value, root, active_refs=(), depth=0):
    _fail(depth <= 64, "schema evaluation depth")
    if type(schema) is bool:
        return schema
    if "$ref" in schema:
        name, target = _schema_ref(schema, root)
        _fail(name not in active_refs, "recursive schema ref")
        if not _schema_matches(target, value, root, active_refs + (name,), depth + 1):
            return False
    if "type" in schema and not _schema_type_matches(schema["type"], value):
        return False
    if "const" in schema and not _json_equal(value, schema["const"]):
        return False
    if "enum" in schema and not any(_json_equal(value, item) for item in schema["enum"]):
        return False
    if "allOf" in schema:
        if not all(_schema_matches(child, value, root, active_refs, depth + 1)
                   for child in schema["allOf"]):
            return False
    if "anyOf" in schema:
        if not any(_schema_matches(child, value, root, active_refs, depth + 1)
                   for child in schema["anyOf"]):
            return False
    if type(value) is dict:
        required = schema.get("required", [])
        if any(name not in value for name in required):
            return False
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and not set(value) <= set(properties):
            return False
        for name, child in properties.items():
            if name in value and not _schema_matches(child, value[name], root, active_refs, depth + 1):
                return False
    if type(value) is list:
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems")
        if len(value) < minimum or maximum is not None and len(value) > maximum:
            return False
        prefix = schema.get("prefixItems", [])
        for child, item in zip(prefix, value):
            if not _schema_matches(child, item, root, active_refs, depth + 1):
                return False
        if "items" in schema:
            for item in value[len(prefix):]:
                if not _schema_matches(schema["items"], item, root, active_refs, depth + 1):
                    return False
        if schema.get("uniqueItems"):
            for index, item in enumerate(value):
                if any(_json_equal(item, prior) for prior in value[:index]):
                    return False
        if "contains" in schema:
            matches = sum(_schema_matches(schema["contains"], item, root, active_refs, depth + 1)
                          for item in value)
            if matches < schema.get("minContains", 1):
                return False
            if "maxContains" in schema and matches > schema["maxContains"]:
                return False
    if type(value) is str:
        if len(value) < schema.get("minLength", 0):
            return False
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            return False
        if "pattern" in schema and _safe_schema_pattern(schema["pattern"]).search(value) is None:
            return False
    if type(value) in {int, float}:
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    return True


def _validate_phase_b_schema(value, schema):
    """Evaluate the bounded Phase B schema without coercion or external refs."""
    _bounded_schema_tree(schema, [0])
    _bounded_schema_tree(value, [0])
    _fail(len(json.dumps(schema, ensure_ascii=False, allow_nan=False).encode()) <= MAX_JSON,
          "schema byte bound")
    _fail(len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode()) <= MAX_JSON,
          "schema value byte bound")
    _fail(type(schema) is dict, "schema root")
    _check_schema(schema, schema, root_node=True)
    _reject_recursive_refs(schema)
    _fail(_schema_matches(schema, value, schema), "Phase B schema mismatch")
    return True


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
    _timestamp(value["CreatedAt"])
    _timestamp(value["UpdatedAt"])
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
        pid = int(fields[1])
        status = fields[2]
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
    device = _uint(row["executable_device"])
    inode = _uint(row["executable_inode"], 1)
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
    output = bytearray()
    index = 0
    while index < len(raw):
        if raw[index:index + 1] == b"\\":
            _fail(index + 4 <= len(raw) and raw[index + 1:index + 4] in {b"040", b"011", b"012", b"134"},
                  "mount escape")
            output.append(int(raw[index + 1:index + 4], 8))
            index += 4
        else:
            _fail(raw[index] not in {0, 10, 13}, "mount byte")
            output.append(raw[index])
            index += 1
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
        fields = line.split(b" ")
        _fail(fields.count(b"-") == 1)
        separator = fields.index(b"-")
        _fail(separator >= 6 and separator + 4 == len(fields), "mountinfo shape")
        _fail(fields[0].isdigit() and fields[1].isdigit() and b":" in fields[2])
        mount_id, parent_id = int(fields[0]), int(fields[1])
        major_minor = fields[2].split(b":")
        _fail(mount_id > 0 and parent_id > 0 and len(major_minor) == 2 and all(item.isdigit() for item in major_minor))
        root = _mount_unescape(fields[3])
        point = _mount_unescape(fields[4])
        _path(root)
        _path(point)
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


# ADR 0068's archive enumerator is deliberately pure.  It does not use tarfile,
# open a path, execute a decompressor, or retain regular-file payloads.
class FixedArchive(Enum):
    KATA_ZSTD = "kata"
    CONTAINERD_GZIP = "containerd"


@dataclass(frozen=True)
class RoleMember:
    role: str
    member: str
    kind: str


@dataclass(frozen=True)
class LinkFacts:
    counts: tuple[tuple[str, int], ...]
    sha256: str


@dataclass(frozen=True)
class ArchiveFacts:
    component: str
    compression: str
    stream_bytes: int
    member_count: int
    member_bytes: int
    type_counts: tuple[tuple[str, int], ...]
    rejected_type_count: int
    manifest_sha256: str
    links: LinkFacts
    roles: tuple[RoleMember, ...]
    blockers: tuple[str, ...]


_MAX_MEMBERS = 20_000
_MAX_NAME = 4096
_MAX_EXTENSION = 65_536
_MAX_PAX = 256
_MAX_MEMBER = 8 * 1024**3
_MAX_MEMBER_BYTES = 16 * 1024**3
_MAX_STREAM_BYTES = 16 * 1024**3
_LINK_CLASSES = (
    "symlink-relative-in-root", "symlink-absolute", "symlink-escape",
    "hardlink-member", "hardlink-missing", "hardlink-absolute", "hardlink-escape",
)
_KINDS = ((b"\0", "file"), (b"0", "file"), (b"5", "directory"),
          (b"1", "hardlink"), (b"2", "symlink"))
_ACCEPTED_EXTENSION_CODES = frozenset({b"x", b"L", b"K"})
_ROLE_RULES = {
    FixedArchive.KATA_ZSTD: (
        ("kata-runtime", "opt/kata/bin/kata-runtime", True),
        ("kata-shim", "opt/kata/bin/containerd-shim-kata-v2", True),
        ("qemu", "opt/kata/bin/qemu-system-x86_64", True),
        ("virtiofsd", "opt/kata/libexec/virtiofsd", True),
        ("kata-config", "opt/kata/share/defaults/kata-containers/configuration-qemu.toml", False),
    ),
    FixedArchive.CONTAINERD_GZIP: (
        ("containerd", "bin/containerd", True),
        ("ctr", "bin/ctr", True),
    ),
}
_PAX_KEYS = frozenset({"path", "linkpath", "size"})


@dataclass(frozen=True)
class _TarRow:
    name: str
    kind: str
    mode: int
    size: int
    target: str
    encoding: str


class _TarEnumerator:
    """Incremental 512-byte tar state machine for one fixed archive policy."""
    __slots__ = ("_asset", "_buffer", "_state", "_remaining", "_padding", "_payload",
                 "_extension", "_extension_hashes", "_pax", "_long_name", "_long_link",
                 "_rows", "_names", "_stream_bytes", "_member_bytes", "_zero_blocks", "_finished")

    def __init__(self, asset):
        _fail(type(asset) is FixedArchive, "fixed archive enum")
        self._asset = asset
        self._buffer = bytearray()
        self._state = "header"
        self._remaining = 0
        self._padding = 0
        self._payload = None
        self._extension = None
        self._extension_hashes = []
        self._pax = {}
        self._long_name = None
        self._long_link = None
        self._rows = []
        self._names = set()
        self._stream_bytes = 0
        self._member_bytes = 0
        self._zero_blocks = 0
        self._finished = False

    @staticmethod
    def _number(raw, maximum, field="number"):
        _fail(type(raw) is bytes and raw, field)
        if raw[0] & 0x80:
            # POSIX/GNU base-256, with the marker bit removed.  Negative values
            # retain the sign bit and are rejected.
            _fail(raw[0] & 0x40 == 0, field)
            value = int.from_bytes(bytes((raw[0] & 0x7f,)) + raw[1:], "big")
        else:
            value_raw = raw.rstrip(b"\0 ").lstrip(b" ")
            _fail(all(48 <= byte <= 55 for byte in value_raw), field)
            if value_raw:
                value = int(value_raw, 8)
            else:
                value = 0
        _fail(0 <= value <= maximum, field)
        return value

    @staticmethod
    def _text(raw, label):
        _fail(type(raw) is bytes and 0 < len(raw) <= _MAX_NAME, label)
        try:
            value = raw.decode("utf-8", "strict")
        except UnicodeError as error:
            raise KataRuntimeError(label) from error
        _fail(len(value.encode("utf-8")) <= _MAX_NAME and
              all(ord(char) >= 32 and ord(char) != 127 and char != "\\" for char in value), label)
        return value

    @classmethod
    def _name(cls, raw, directory=False):
        value = cls._text(raw, "member name")
        while value.startswith("./"):
            value = value[2:]
        if directory and value.endswith("/"):
            value = value[:-1]
        _fail(value and not value.startswith("/") and
              all(part not in {"", ".", ".."} for part in value.split("/")), "member path")
        return value

    @classmethod
    def _target(cls, raw):
        return cls._text(raw, "link target")

    @staticmethod
    def _field(block, start, size):
        raw = bytes(block[start:start + size])
        nul = raw.find(b"\0")
        if nul < 0:
            return raw
        _fail(not any(raw[nul + 1:]), "fixed field suffix")
        return raw[:nul]

    @classmethod
    def _pax_records(cls, raw):
        result = {}
        cursor = 0
        count = 0
        while cursor < len(raw):
            space = raw.find(b" ", cursor, min(len(raw), cursor + 32))
            _fail(space > cursor and raw[cursor:space].isdigit() and raw[cursor] != 48, "PAX length")
            length = int(raw[cursor:space])
            _fail(length >= space - cursor + 4 and cursor + length <= len(raw), "PAX span")
            record = raw[space + 1:cursor + length]
            _fail(record.endswith(b"\n") and record.count(b"=") >= 1, "PAX record")
            key_raw, value = record[:-1].split(b"=", 1)
            _fail(key_raw and all(33 <= byte <= 126 and byte != 61 for byte in key_raw), "PAX key")
            key = key_raw.decode("ascii")
            _fail(key in _PAX_KEYS, "unknown PAX key")
            _fail(key not in result, "duplicate PAX key")
            _fail(value and b"\0" not in value, "PAX value")
            try:
                decoded = value.decode("utf-8", "strict")
            except UnicodeError as error:
                raise KataRuntimeError("PAX encoding") from error
            _fail(all(ord(char) >= 32 and ord(char) != 127 for char in decoded), "PAX control")
            result[key] = value
            cursor += length
            count += 1
            _fail(count <= _MAX_PAX, "PAX count")
        _fail(cursor == len(raw), "PAX suffix")
        return result

    def _begin_header(self, block):
        if block == b"\0" * 512:
            self._zero_blocks += 1
            if self._zero_blocks == 2:
                self._state = "suffix"
            else:
                self._state = "header"
            return
        _fail(self._zero_blocks == 0, "single tar end block")
        stored = self._number(bytes(block[148:156]), 512 * 255, "checksum")
        checksum = sum(block[:148]) + 8 * 32 + sum(block[156:])
        _fail(stored == checksum, "tar checksum")
        magic, version = bytes(block[257:263]), bytes(block[263:265])
        _fail((magic, version) in {(b"ustar\0", b"00"), (b"ustar ", b" \0")}, "tar format")
        mode = self._number(bytes(block[100:108]), 0o7777, "mode")
        self._number(bytes(block[108:116]), (1 << 63) - 1, "uid")
        self._number(bytes(block[116:124]), (1 << 63) - 1, "gid")
        size = self._number(bytes(block[124:136]), _MAX_MEMBER, "size")
        self._number(bytes(block[136:148]), (1 << 63) - 1, "mtime")
        self._number(bytes(block[329:337]), (1 << 63) - 1, "device major")
        self._number(bytes(block[337:345]), (1 << 63) - 1, "device minor")
        self._field(block, 265, 32)
        self._field(block, 297, 32)
        typecode = bytes(block[156:157])
        extension_code = typecode.isalpha()
        _fail(not extension_code or typecode in _ACCEPTED_EXTENSION_CODES,
              "unsupported tar extension")
        if "size" in self._pax and typecode not in _ACCEPTED_EXTENSION_CODES:
            pax_size = self._pax["size"]
            _fail(pax_size.isdigit() and (pax_size == b"0" or not pax_size.startswith(b"0")), "PAX size")
            size = int(pax_size)
            _fail(size <= _MAX_MEMBER, "PAX size")
        name_raw = self._field(block, 0, 100)
        prefix = self._field(block, 345, 155)
        if prefix:
            name_raw = prefix + b"/" + name_raw
        extension = typecode in _ACCEPTED_EXTENSION_CODES
        if extension:
            _fail(size <= _MAX_EXTENSION and not self._pax.get("pending"), "extension bound")
        self._remaining = size
        self._padding = (-size) % 512
        if extension:
            self._payload = bytearray()
        else:
            self._payload = None
        header_sha256 = hashlib.sha256(block).hexdigest()
        self._extension = (typecode, name_raw, mode, size,
                           self._field(block, 157, 100), header_sha256)
        if size:
            self._state = "payload"
        else:
            self._state = "padding"
        if size == 0 and self._padding == 0:
            self._complete_payload()

    def _complete_payload(self):
        typecode, name_raw, mode, size, target_raw, header_sha256 = self._extension
        payload = bytes(self._payload or b"")
        if typecode in _ACCEPTED_EXTENSION_CODES:
            extension_digest = hashlib.sha256(header_sha256.encode() + payload).hexdigest()
            self._extension_hashes.append(extension_digest)
        if typecode == b"x":
            _fail(payload, "empty local PAX")
            _fail(not self._pax, "stacked PAX")
            self._pax = self._pax_records(payload)
        elif typecode in {b"L", b"K"}:
            _fail(payload.endswith(b"\0") and b"\0" not in payload[:-1], "GNU extension")
            value = payload[:-1]
            if typecode == b"L":
                _fail(self._long_name is None, "duplicate GNU name")
                self._long_name = value
            else:
                _fail(self._long_link is None, "duplicate GNU link")
                self._long_link = value
        else:
            _fail(not ("path" in self._pax and self._long_name is not None), "ambiguous name extension")
            _fail(not ("linkpath" in self._pax and self._long_link is not None), "ambiguous link extension")
            if "path" in self._pax:
                name_raw = self._pax["path"]
            elif self._long_name is not None:
                name_raw = self._long_name
            if "linkpath" in self._pax:
                target_raw = self._pax["linkpath"]
            elif self._long_link is not None:
                target_raw = self._long_link
            kind = dict(_KINDS).get(typecode, f"unsupported-{typecode.hex()}")
            _fail("linkpath" not in self._pax or kind in {"symlink", "hardlink"}, "inapplicable PAX linkpath")
            _fail(self._long_link is None or kind in {"symlink", "hardlink"}, "inapplicable GNU link")
            encoding_parts = []
            if self._pax:
                encoding_parts.append("pax:" + ",".join(sorted(self._pax)))
            if self._long_name is not None:
                encoding_parts.append("gnu-name")
            if self._long_link is not None:
                encoding_parts.append("gnu-link")
            if encoding_parts:
                encoding_name = "+".join(encoding_parts)
            else:
                encoding_name = "ustar"
            encoding_material = "".join((*self._extension_hashes, header_sha256)).encode()
            encoding = encoding_name + ":" + hashlib.sha256(encoding_material).hexdigest()
            _fail(kind == "file" or size == 0 or kind.startswith("unsupported-"), "non-file payload")
            name = self._name(name_raw, kind == "directory")
            if kind in {"symlink", "hardlink"}:
                target = self._target(target_raw)
            else:
                target = ""
            _fail(name not in self._names, "duplicate member")
            _fail(len(self._rows) < _MAX_MEMBERS, "member count")
            if kind == "file":
                _fail(self._member_bytes <= _MAX_MEMBER_BYTES - size, "member byte total")
                self._member_bytes += size
            self._names.add(name)
            self._rows.append(_TarRow(name, kind, mode, size, target, encoding))
            self._pax = {}
            self._extension_hashes = []
            self._long_name = None
            self._long_link = None
        self._payload = None
        self._extension = None
        self._state = "header"

    def feed(self, chunk: bytes) -> None:
        _fail(type(chunk) is bytes and not self._finished, "tar feed")
        _fail(self._stream_bytes <= _MAX_STREAM_BYTES - len(chunk), "decompressed stream bound")
        self._stream_bytes += len(chunk)
        pending = memoryview(chunk)
        while pending:
            if self._state == "suffix":
                raise KataRuntimeError("tar suffix bytes")
            count = min(len(pending), max(1, 1_048_576 - len(self._buffer)))
            self._buffer.extend(pending[:count])
            pending = pending[count:]
            _fail(len(self._buffer) <= 1_048_576, "tar buffer bound")
            while True:
                if self._state == "header":
                    if len(self._buffer) < 512:
                        break
                    block = bytes(self._buffer[:512])
                    del self._buffer[:512]
                    self._begin_header(block)
                elif self._state == "payload":
                    if not self._buffer:
                        break
                    consumed = min(len(self._buffer), self._remaining)
                    if self._payload is not None:
                        self._payload.extend(self._buffer[:consumed])
                    del self._buffer[:consumed]
                    self._remaining -= consumed
                    if self._remaining:
                        break
                    self._state = "padding"
                    if self._padding == 0:
                        self._complete_payload()
                elif self._state == "padding":
                    if len(self._buffer) < self._padding:
                        break
                    _fail(not any(self._buffer[:self._padding]), "tar padding")
                    del self._buffer[:self._padding]
                    self._padding = 0
                    self._complete_payload()
                else:
                    if not self._buffer:
                        break
                    raise KataRuntimeError("tar suffix bytes")

    @staticmethod
    def _lexical(name, target, symlink):
        if target.startswith("/"):
            return "absolute", posixpath.normpath(target)
        if symlink:
            base = posixpath.dirname(name)
        else:
            base = ""
        joined = posixpath.normpath(posixpath.join(base, target))
        if joined == ".." or joined.startswith("../"):
            return "escape", joined
        return "in-root", joined

    def _resolve(self, name, rows):
        current = name
        seen = set()
        for _unused in range(65):
            _fail(current not in seen, "link cycle")
            seen.add(current)
            parts = current.split("/")
            for index in range(1, len(parts) + 1):
                prefix = "/".join(parts[:index])
                row = rows.get(prefix)
                if row is not None and row.kind == "symlink":
                    disposition, target = self._lexical(prefix, row.target, True)
                    _fail(disposition == "in-root", "unsafe symlink")
                    current = "/".join(filter(None, (target, *parts[index:])))
                    break
            else:
                row = rows.get(current)
                _fail(row is not None, "missing link member")
                if row.kind == "hardlink":
                    disposition, target = self._lexical(current, row.target, False)
                    _fail(disposition == "in-root", "unsafe hardlink")
                    current = target
                    continue
                _fail(row.kind == "file", "role does not resolve to file")
                return row.kind
        raise KataRuntimeError("link depth")

    def finish(self) -> ArchiveFacts:
        _fail(not self._finished, "tar enumerator consumed")
        self._finished = True
        _fail(self._state == "suffix" and not self._buffer and not self._pax and
              not self._extension_hashes and self._long_name is None and
              self._long_link is None, "truncated tar")
        rows = {row.name: row for row in self._rows}
        link_rows = []
        counts = {name: 0 for name in _LINK_CLASSES}
        blockers = []
        for row in self._rows:
            if row.kind == "symlink":
                disposition, target = self._lexical(row.name, row.target, True)
                class_ = {"absolute": "symlink-absolute", "escape": "symlink-escape",
                          "in-root": "symlink-relative-in-root"}[disposition]
            elif row.kind == "hardlink":
                disposition, target = self._lexical(row.name, row.target, False)
                if disposition == "absolute":
                    class_ = "hardlink-absolute"
                elif disposition == "escape":
                    class_ = "hardlink-escape"
                elif target in rows:
                    class_ = "hardlink-member"
                else:
                    class_ = "hardlink-missing"
            else:
                continue
            counts[class_] += 1
            link_rows.append({"class": class_, "kind": row.kind, "name": row.name, "target": target})
        rejected = sum(row.kind.startswith("unsupported-") for row in self._rows)
        if rejected:
            blockers.append("archive-rejected-types")
        if any(counts[name] for name in ("symlink-absolute", "symlink-escape", "hardlink-missing",
                                         "hardlink-absolute", "hardlink-escape")):
            blockers.append("archive-unsafe-links")
        roles = []
        for role, member, executable in _ROLE_RULES[self._asset]:
            aliases = [row.name for row in self._rows
                       if row.name != member and row.name.endswith("/" + posixpath.basename(member))]
            if aliases:
                blockers.append("role-extra-" + role)
            row = rows.get(member)
            if row is None:
                blockers.append("role-missing-" + role)
                continue
            if row.kind != "file":
                blockers.append("role-type-" + role)
                continue
            if row.size == 0 or bool(row.mode & 0o111) is not executable:
                blockers.append("role-policy-" + role)
                continue
            roles.append(RoleMember(role, member, row.kind))
        canonical_rows = []
        ordered_rows = sorted(self._rows, key=lambda item: item.name.encode())
        for row in ordered_rows:
            target = ""
            if row.kind in {"symlink", "hardlink"}:
                target = self._lexical(row.name, row.target, row.kind == "symlink")[1]
            canonical_rows.append({
                "encoding": row.encoding,
                "kind": row.kind,
                "mode": row.mode,
                "name": row.name,
                "size": row.size,
                "target": target,
            })
        manifest_parts = []
        for row in canonical_rows:
            encoded = json.dumps(
                row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
            manifest_parts.append(encoded + b"\n")
        manifest = b"".join(manifest_parts)
        link_parts = []
        ordered_links = sorted(link_rows, key=lambda item: item["name"].encode())
        for row in ordered_links:
            encoded = json.dumps(
                row, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
            link_parts.append(encoded + b"\n")
        links = b"".join(link_parts)
        type_counts = tuple((kind, sum(row.kind == kind for row in self._rows))
                            for kind in ("directory", "file", "hardlink", "symlink"))
        compression = "zstd" if self._asset is FixedArchive.KATA_ZSTD else "gzip"
        return ArchiveFacts(self._asset.value, compression, self._stream_bytes, len(self._rows),
                            self._member_bytes, type_counts, rejected, hashlib.sha256(manifest).hexdigest(),
                            LinkFacts(tuple((name, counts[name]) for name in _LINK_CLASSES),
                                      hashlib.sha256(links).hexdigest()), tuple(roles),
                            tuple(sorted(set(blockers))))


def _new_fixed_tar_enumerator(asset: FixedArchive) -> _TarEnumerator:
    return _TarEnumerator(asset)


def _new_fixed_policy_tar_enumerator_for_tests(asset: FixedArchive) -> _TarEnumerator:
    """The test route changes no parser bound or policy."""
    return _TarEnumerator(asset)
