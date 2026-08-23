"""Cleanup-only custody for the fixed immutable prepared runtime."""
import hashlib
import os

import completion_kata_admission as admission
import completion_kata_operation as operation
import completion_rootfs_fs as fs

_RUNTIME = fs._name("kata-runtime-v1")
_BIN = fs._name("bin")
_ACTIVE_NAME = "configuration-qemu-observer.toml"
_ACTIVE = fs._name(_ACTIVE_NAME)
_PATH = ("deploy", "aws-feasibility", ".state", "completion-v1", "kata-runtime-v1")
_seal = object()
_states = {}


class PreparedRuntimeError(Exception):
    pass


class _PreparedCleanup:
    __slots__ = ()
    def __new__(cls, key=None):
        if key is not _seal: raise PreparedRuntimeError("sealed prepared cleanup custody required")
        return super().__new__(cls)


def _require(value, message="prepared runtime custody differs"):
    if not value: raise PreparedRuntimeError(message)


def _same_directory(current, expected):
    return all(current[name] == expected[name] for name in operation.GEN_KEYS[:7])


def _digest(descriptor, size):
    value = hashlib.sha256(); offset = 0
    while offset < size:
        raw = os.pread(descriptor, min(1_048_576, size - offset), offset)
        _require(raw); value.update(raw); offset += len(raw)
    _require(not os.pread(descriptor, 1, offset))
    return value.hexdigest()


def _host_generation(descriptor):
    from completion_kata_process import _host_generation
    return _host_generation(descriptor)


def _claim_exact(contracts, source_anchor, active_expected):
    """Open the sole fixed tree; the caller supplies reviewed contracts, not a path."""
    _require(set(contracts) >= {"containerd", "ctr"} and type(source_anchor) is int
             and type(active_expected) is dict
             and set(active_expected) == {"path", "size", "sha256", "base_path",
                                           "base_size", "base_sha256", "substitutions"}
             and active_expected["path"].endswith("/" + _ACTIVE_NAME)
             and active_expected["size"] == 32_220
             and type(active_expected["sha256"]) is str
             and len(active_expected["sha256"]) == 64)
    contracts = {name: value.value for name, value in contracts.items()}
    held = []
    try:
        current = os.dup(source_anchor); os.set_inheritable(current, False); held.append(current)
        for name in _PATH:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=current)
            seen = os.fstat(child)
            _require(seen.st_uid == seen.st_gid == 0 and not (seen.st_mode & 0o022))
            held.append(child); current = child
        runtime = current
        _require(set(os.listdir(runtime)) == {"bin", _ACTIVE_NAME})
        bin_fd = os.open("bin", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=runtime)
        held.append(bin_fd); _require(set(os.listdir(bin_fd)) == {"containerd", "ctr"})
        active_fd = os.open(_ACTIVE_NAME, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                            dir_fd=runtime)
        held.append(active_fd)
        generations = [_host_generation(runtime), _host_generation(bin_fd),
                       _host_generation(active_fd)]
        _require((generations[0]["mode"], generations[1]["mode"], generations[2]["mode"],
                  generations[0]["nlink"], generations[1]["nlink"],
                  generations[2]["nlink"]) == (0o700, 0o500, 0o400, 3, 2, 1)
                 and generations[2]["kind"] == "file"
                 and generations[2]["size"] == active_expected["size"]
                 and _digest(active_fd, generations[2]["size"]) == active_expected["sha256"]
                 and all(row["uid"] == row["gid"] == 0 for row in generations)
                 and not os.listxattr(runtime) and not os.listxattr(bin_fd)
                 and not os.listxattr(active_fd))
        facts = {"observer_configuration_size": generations[2]["size"],
                 "observer_configuration_sha256": active_expected["sha256"]}
        for index, name in enumerate(("containerd", "ctr")):
            contract = contracts[name]["objects"]
            expected_path = str(admission.FIXED_ROOT.joinpath(*_PATH, "bin", name))
            _require(len(contract) == 1 and contract[0]["path"] == expected_path)
            expected = contract[0]
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=bin_fd)
            held.append(descriptor); seen = _host_generation(descriptor)
            _require(seen["kind"] == "file" and seen["mode"] == 0o500
                     and seen["uid"] == seen["gid"] == 0 and seen["nlink"] == 1
                     and seen["size"] == expected["size"] and not os.listxattr(descriptor)
                     and _digest(descriptor, seen["size"]) == expected["sha256"])
            generations.append(seen); facts[name + "_size"] = seen["size"]
            facts[name + "_sha256"] = expected["sha256"]
        _require(set(os.listdir(runtime)) == {"bin", _ACTIVE_NAME}
                 and set(os.listdir(bin_fd)) == {"containerd", "ctr"}
                 and _host_generation(runtime) == generations[0]
                 and _host_generation(bin_fd) == generations[1]
                 and _host_generation(active_fd) == generations[2])
        facts.update(zip(("runtime_generation", "bin_generation",
                          "observer_configuration_generation", "containerd_generation",
                          "ctr_generation"), generations, strict=True))
        return facts, held
    except BaseException:
        for descriptor in reversed(held): os.close(descriptor)
        raise


def _snapshot(completion, body, control):
    snapshot = fs._enumerate_stable(completion, control)
    runtime_module = __import__("completion_kata_runtime")
    _require(not runtime_module._runtime_alias()
             and dict(snapshot.children).get(fs._name(".kata-runtime-v1.staging")) is None)
    child = dict(snapshot.children).get(_RUNTIME)
    if child is None: return {}
    runtime = fs._open_path_node(completion, _RUNTIME, "directory", control); nodes = {"runtime": runtime}
    try:
        _require(runtime.generation == child and not os.listxattr(runtime.operation_fd.number))
        _require(_same_directory(operation._generation_value(runtime.generation), body["runtime_generation"]))
        names = set(os.listdir(runtime.operation_fd.number)); _require(names <= {"bin", _ACTIVE_NAME})
        if _ACTIVE_NAME in names:
            active_node = fs._open_path_node(runtime, _ACTIVE, "file", control)
            nodes["observer_configuration"] = active_node
            current = operation._generation_value(active_node.generation)
            raw = fs._read_regular(active_node, body["observer_configuration_size"], control)
            _require(current == body["observer_configuration_generation"]
                     and len(raw) == body["observer_configuration_size"]
                     and hashlib.sha256(raw).hexdigest()
                         == body["observer_configuration_sha256"])
        if "bin" not in names: return nodes
        bin_node = fs._open_path_node(runtime, _BIN, "directory", control); nodes["bin"] = bin_node
        _require(not os.listxattr(bin_node.operation_fd.number)
                 and _same_directory(operation._generation_value(bin_node.generation), body["bin_generation"]))
        names = set(os.listdir(bin_node.operation_fd.number))
        _require(names in ({"containerd", "ctr"}, {"ctr"}, set()))
        for name in names:
            node = fs._open_path_node(bin_node, fs._name(name), "file", control); nodes[name] = node
            current = operation._generation_value(node.generation)
            raw = fs._read_regular(node, body[name + "_size"], control)
            _require(current == body[name + "_generation"] and len(raw) == body[name + "_size"]
                     and hashlib.sha256(raw).hexdigest() == body[name + "_sha256"])
        return nodes
    except BaseException as error:
        for node in reversed(tuple(nodes.values())): fs._close_node(node)
        raise error


def retain(journal, completion, grant, control):
    history = journal.runtime_recovery_history()
    if history["runtime_stage_intents"] or history["runtime_staged"]: return None
    prepared = history["runtime_prepared"]
    if not prepared:
        _require(grant is not None); operation._record_runtime_prepared(journal, grant)
        history = journal.runtime_recovery_history(); prepared = history["runtime_prepared"]
    _require(len(prepared) == 1 and not __import__("completion_kata_runtime")._runtime_alias())
    if grant is not None: admission._verify_prepared_runtime_custody(grant)
    nodes = _snapshot(completion, prepared[0], control)
    for node in reversed(tuple(nodes.values())): fs._close_node(node)
    custody = _PreparedCleanup(_seal); _states[custody] = (completion, prepared[0], control)
    return custody


def cleanup(custody):
    state = _states.get(custody); _require(type(custody) is _PreparedCleanup and state is not None)
    completion, body, control = state
    while True:
        nodes = _snapshot(completion, body, control)
        try:
            action = next((name for name in ("containerd", "ctr", "bin",
                                                "observer_configuration", "runtime")
                           if name in nodes), None)
            if action is None: break
            node = nodes[action]
            parent = (nodes["bin"] if action in {"containerd", "ctr"}
                      else nodes["runtime"] if action in {"bin", "observer_configuration"}
                      else completion)
            name = (_ACTIVE if action == "observer_configuration" else
                    fs._name(action if action != "runtime" else "kata-runtime-v1"))
            confirmation = _snapshot(completion, body, control)
            try: _require(action in confirmation and confirmation[action].generation == node.generation)
            finally:
                for held in reversed(tuple(confirmation.values())): fs._close_node(held)
            _require(fs._observe_child(parent, name, control) == node.generation)
            if action in {"containerd", "ctr", "observer_configuration"}:
                os.unlink(name.raw, dir_fd=parent.operation_fd.number)
            else:
                _require(not os.listdir(node.operation_fd.number))
                os.rmdir(name.raw, dir_fd=parent.operation_fd.number)
            os.fsync(parent.operation_fd.number)
        finally:
            for node in reversed(tuple(nodes.values())): fs._close_node(node)
    _states.pop(custody)
