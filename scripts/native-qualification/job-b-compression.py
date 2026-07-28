#!/usr/bin/env python3
"""Native B: qualify the production sealed gzip/zstd launcher."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
SOURCES = (
    "deploy/aws-feasibility/remote/completion_elf.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py",
    "schemas/trusted-runtime-closure-v1.json",
)
FIXED_INPUTS = (
    bytes.fromhex("1f8b08000000000002ff4bce4f2fd62d2acd2bc9cc4dd52d2c4dccc94ccb4c4e2cc9cccfd32d33e40200a9c9b5521e000000"),
    bytes.fromhex("28b52ffd201ef10000636f67732d72756e74696d652d7175616c696669636174696f6e2d76310a"),
)
FIXED_OUTPUT = b"cogs-runtime-qualification-v1\n"
FIXED_OUTPUT_SHA256 = hashlib.sha256(FIXED_OUTPUT).hexdigest()
CHECKS = (
    "gzip_source_exact", "gzip_sealed_exec", "zstd_source_exact",
    "zstd_sealed_exec", "decompression_deterministic", "network_denied",
    "children_exact", "cleanup_restored",
)
PREINPUT_FACTS = (
    "mapped_generations_exact", "exec_descriptor_consumed", "root_readonly_noexec",
    "root_has_no_proc", "host_paths_absent",
)
NETWORK_FACTS = ("network_namespace_exact", "seccomp_denials_exact", "no_acquisition_route")
CLEANUP_FACTS = (
    "descriptors_restored", "children_reaped", "descendants_reaped",
    "mounts_restored", "paths_restored", "namespaces_released",
    "namespace_handles_released",
)

QualificationError = RuntimeError
def _require(condition, message):
    if not condition:
        raise QualificationError(message)
def _fds():
    directory = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        return tuple(sorted(int(name) for name in os.listdir(directory) if int(name) != directory))
    finally:
        os.close(directory)
def _children():
    return tuple(int(value) for value in Path("/proc/self/task/self/children").read_text(encoding="ascii").split())

def _source_admission(revision):
    digest = hashlib.sha256()
    for path in SOURCES:
        data = (ROOT / path).read_bytes()
        encoded = path.encode()
        digest.update(struct.pack("!I", len(encoded)) + encoded)
        digest.update(struct.pack("!Q", len(data)) + hashlib.sha256(data).digest())
    value = {
        "bootstrap_sha256": hashlib.sha256((ROOT / SOURCES[2]).read_bytes()).hexdigest(),
        "revision": revision,
        "source_set_sha256": digest.hexdigest(),
        "version": "cogs.runtime-source-admission/v1",
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
def _close_all(values):
    failures = []
    for fd in values:
        try:
            os.close(fd)
        except OSError as error:
            failures.append(error)
    _require(not failures, "descriptor close failed")

def _fixed_bootstrap_descriptors(admission):
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    root_fd = -1
    try:
        _require(os.write(write_fd, admission) == len(admission), "admission short write")
        os.close(write_fd)
        write_fd = -1
        root_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        _require((read_fd, root_fd) == (3, 4), "nonempty descriptor baseline")
        return (read_fd, root_fd)
    except BaseException:
        for fd in (read_fd, write_fd, root_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        raise

class NativeAdapter:
    def launch(self, revision):
        fd_baseline = _fds()
        child_baseline = _children()
        _require(fd_baseline == (0, 1, 2), "descriptor baseline is not exact")
        _require(child_baseline == (), "child baseline is not empty")
        descriptors = _fixed_bootstrap_descriptors(_source_admission(revision))
        try:
            with subprocess.Popen(
                ("/usr/bin/python3", "-I", "-B", os.fspath(LAUNCHER)),
                cwd=ROOT, env={}, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=descriptors, close_fds=True,
            ) as process:
                owned, descriptors = descriptors, ()
                _close_all(owned)
                child_exact = _children() == (process.pid,)
                try:
                    stdout, stderr = process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=5)
                    raise
        finally:
            _close_all(descriptors)
        _require(process.returncode == 0 and stderr == b"", "production launcher failed")
        _require(len(stdout) <= 32768 and stdout.endswith(b"\n"), "launcher output framing")
        result = json.loads(stdout)
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        _require(canonical == stdout, "launcher output is not canonical")
        return {
            "result": result, "child_exact": child_exact,
            "fd_restored": _fds() == fd_baseline,
            "children_restored": _children() == child_baseline,
        }
def qualify(adapter, revision):
    _require(len(revision) == 40 and all(c in "0123456789abcdef" for c in revision), "revision")
    observation = adapter.launch(revision)
    _require(set(observation) == {"result", "child_exact", "fd_restored", "children_restored"} and type(observation["result"]) is dict, "adapter shape")
    result = observation["result"]
    _require(all(0 < len(value) <= 65536 for value in FIXED_INPUTS), "fixed input bound")
    identity = (result.get("version"), result.get("marker"), result.get("source_revision"))
    _require(identity == ("cogs.runtime-qualification/v1", "cogs-runtime-qualification-v1", revision), "result identity")
    _require((result.get("gzip_output_sha256"), result.get("zstd_output_sha256")) == (FIXED_OUTPUT_SHA256, FIXED_OUTPUT_SHA256), "deterministic outputs")
    _require(all(result.get(name) is True for name in PREINPUT_FACTS + NETWORK_FACTS + CLEANUP_FACTS), "production observation failed")
    _require(all(observation[name] is True for name in ("child_exact", "fd_restored", "children_restored")), "driver cleanup failed")
    closure = result.get("closure_sha256")
    _require(type(closure) is str and len(closure) == 64 and set(closure) <= set("0123456789abcdef"), "closure digest")
    metadata = [
        {"id": name, "role": "fixed-input", "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}
        for name, value in zip(("gzip-input", "zstd-input"), FIXED_INPUTS)
    ]
    metadata += [
        {"id": "gzip-output", "role": "deterministic-output", "sha256": FIXED_OUTPUT_SHA256, "size_bytes": len(FIXED_OUTPUT)},
        {"id": "zstd-output", "role": "deterministic-output", "sha256": FIXED_OUTPUT_SHA256, "size_bytes": len(FIXED_OUTPUT)},
        {"id": "runtime-closure", "role": "closure", "sha256": closure, "size_bytes": 0},
    ]
    return metadata
def _load_common():
    sys.path.insert(0, os.fspath(Path(__file__).resolve().parent))
    common = __import__("common")
    del sys.path[0]
    return common
def _native():
    common = _load_common()
    context = common.WorkflowContext.from_environ("B", __file__)
    try:
        metadata = qualify(NativeAdapter(), context.head_sha)
    except BaseException as error:
        diagnostic = f"{type(error).__name__}:{error}".encode()[:common.REPORT_LIMIT]
        common.finalize_report(context, "fail", dict.fromkeys(CHECKS, "fail"), [],
                               dict.fromkeys(common.CLEANUP_KEYS, False), "compression", diagnostic)
        return 1
    common.finalize_report(context, "pass", dict.fromkeys(CHECKS, "pass"), metadata,
                           dict.fromkeys(common.CLEANUP_KEYS, True))
    return 0
def main():
    if not __debug__ or sys.argv != [sys.argv[0], "--workflow-bound"]:
        raise SystemExit(2)
    try:
        status = _native()
    except BaseException:
        status = 1
    raise SystemExit(status)
if __name__ == "__main__":
    main()
