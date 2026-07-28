#!/usr/bin/env python3
"""Portable hostile tests for the production trusted-launcher state machines."""

from array import array
import ast
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 launcher tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
FIXTURE = ROOT / "test/fixtures/outcome-two/launcher/cases.json"
ROW_KEYS = {
    "id", "production_method", "primitive_fault", "intended_code",
    "cleanup_domains", "sentinel",
}
REQUIRED_ACCEPTANCE = {
    "AT-ADM-01", "AT-ADM-02", "AT-ADM-03",
    "AT-ISSUE-01", "AT-ISSUE-02", "AT-ISSUE-03",
    "AT-USER-01", "AT-EXEC-01", "AT-SECCOMP-01", "AT-EXEC-ONCE-01",
    "AT-T2-OBS-01", "AT-T2-OBS-02", "AT-ROOT-01", "AT-LIFE-01",
    "AT-LIFE-02", "AT-FD-ENUM-01", "AT-FD-CLOSE-01", "AT-RECORD-01",
    "AT-UNAV-01", "AT-ADAPT-BOOT-01", "AT-ADAPT-ISSUE-01",
    "AT-ADAPT-T2-01", "AT-FIXTURE-01",
}


def load_module():
    spec = importlib.util.spec_from_file_location(
        "completion_trusted_runtime_launcher", MODULE,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def production_symbol(module, name):
    value = module
    for component in name.split("."):
        value = getattr(value, component, None)
    return value


def fixture_rows(module):
    document = json.loads(FIXTURE.read_text())
    if document["version"] != "cogs.outcome-two-launcher-cases/v3":
        raise AssertionError("launcher fixture version")
    rows = []
    acceptance = set()
    for family in document["families"]:
        family_keys = {
            "acceptance_id", "production_method", "intended_code",
            "cleanup_domains", "sentinel", "cases",
        }
        if set(family) != family_keys:
            raise AssertionError("launcher fixture family shape")
        acceptance.add(family["acceptance_id"])
        if not callable(production_symbol(module, family["production_method"])):
            raise AssertionError(f"unreachable production method: {family['production_method']}")
        for case in family["cases"]:
            if type(case) is not list or len(case) != 2:
                raise AssertionError("launcher fixture case shape")
            row = {
                "id": f"{family['acceptance_id']}:{case[0]}",
                "production_method": family["production_method"],
                "primitive_fault": case[1],
                "intended_code": family["intended_code"],
                "cleanup_domains": family["cleanup_domains"],
                "sentinel": family["sentinel"],
            }
            if set(row) != ROW_KEYS:
                raise AssertionError("expanded fixture row shape")
            if not row["id"].startswith("AT-") or not row["sentinel"]:
                raise AssertionError("expanded fixture row values")
            if type(row["cleanup_domains"]) is not list:
                raise AssertionError("expanded fixture cleanup domains")
            rows.append(row)
    identifiers = [row["id"] for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise AssertionError("launcher fixture IDs are not unique")
    if acceptance != REQUIRED_ACCEPTANCE:
        raise AssertionError(f"launcher acceptance set drift: {acceptance}")
    return rows


def exact_error(module, action, expected):
    try:
        action()
    except module.RuntimeLauncherError as error:
        if error.code != expected:
            raise AssertionError(
                f"expected launcher code {expected!r}, received {error.code!r}",
            ) from error
        return error
    raise AssertionError(f"launcher predicate accepted; expected {expected}")


def dirents(values):
    records = []
    for value in values:
        name = str(value).encode() + b"\0"
        length = (19 + len(name) + 7) & ~7
        records.append(
            struct.pack("=QqHB", value + 1, 0, length, 0)
            + name
            + bytes(length - 19 - len(name))
        )
    return b"".join(records)


class DescriptorOps:
    """Exact open/getdents/close primitives used by production snapshots."""

    def __init__(self, entries=(0, 1, 2, 90), close_fault=None):
        self.entries = tuple(entries)
        self.close_fault = close_fault
        self.opened = []
        self.closed = []
        self.reads = 0

    def open(self, path, flags, mode=0o600):
        del flags, mode
        if path != "/proc/self/fd":
            raise AssertionError(f"unexpected descriptor path: {path}")
        self.opened.append(90)
        return 90

    def getdents(self, fd, maximum=32768):
        del maximum
        if fd != 90:
            raise AssertionError("getdents used a different fd")
        self.reads += 1
        return dirents(self.entries) if self.reads == 1 else b""

    def close(self, fd):
        if fd != 90 or self.closed:
            raise AssertionError("enumerator close was retried")
        self.closed.append(fd)
        if self.close_fault:
            raise OSError(self.close_fault)


class LeaseOps:
    def __init__(self, fault=None):
        self.fault = fault
        self.calls = []

    def close(self, fd):
        self.calls.append(fd)
        if self.fault:
            raise OSError(self.fault)


class BoundaryOps:
    """Primitive security adapter; no namespace, mount, seccomp, or privilege effect."""

    def __init__(self, fault=None):
        self.fault = fault
        self.calls = []

    def _value(self, primitive, value):
        self.calls.append(primitive)
        return value if self.fault != primitive else False

    def chroot(self, root):
        if root != b"/modeled-root":
            raise AssertionError("boundary root changed")
        self.calls.append("chroot")

    def prctl(self, option, value=0):
        self.calls.append(("prctl", option, value))
        if option == 27:
            return 0 if self.fault == "securebits" else 15
        if option == 39:
            return 0 if self.fault == "nnp" else 1
        return 0

    def drop_bounding(self):
        self.calls.append("drop-bounding")

    def capset_zero(self):
        self.calls.append("capset-zero")

    def capget_zero(self):
        return self._value("capget", True)

    def install_seccomp(self):
        self.calls.append("seccomp-install")
        return "bad" if self.fault == "seccomp-digest" else self.digest

    def seccomp_mode(self):
        return 0 if self.fault == "seccomp-mode" else 2

    def probe_seccomp_denials(self):
        denied = {
            "execve": errno.EPERM,
            "socket": errno.EPERM,
            "memfd_create": errno.EPERM,
            "seccomp": errno.EPERM,
        }
        if self.fault == "seccomp-denial":
            denied["execve"] = 0
        return denied

    digest = ""


class AdmissionEndpoint:
    """One-shot kernel-endpoint primitive model used by _SourceAdmission._consume."""

    def __init__(self, module, worker_pid, *, acknowledgement=True):
        self.module = module
        self.worker_pid = worker_pid
        self.acknowledgement = acknowledgement
        self.challenge = None
        self.closed = False

    def getsockopt(self, level, kind, size):
        if (level, kind, size) != (socket.SOL_SOCKET, socket.SO_PEERCRED, 12):
            raise AssertionError("admission did not request exact peer credentials")
        return struct.pack("3i", self.worker_pid + 1, os.getuid(), os.getgid())

    def send(self, value):
        self.challenge = value
        return len(value)

    def recv(self, size):
        if size != 128 or self.challenge is None:
            raise AssertionError("admission acknowledgement sequence")
        if not self.acknowledgement:
            return b"wrong"
        return hashlib.sha256(self.challenge).hexdigest().encode()

    def shutdown(self, direction):
        if direction != socket.SHUT_RDWR:
            raise AssertionError("admission endpoint shutdown")

    def close(self):
        self.closed = True


def source_reachability():
    source = MODULE.read_text()
    tree = ast.parse(source)
    top_functions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    edges = {}
    for name, node in top_functions.items():
        edges[name] = {
            call.func.id
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        }
    reached = {"_bootstrap_main"}
    pending = ["_bootstrap_main"]
    while pending:
        current = pending.pop()
        for target in edges.get(current, set()):
            if target in top_functions and target not in reached:
                reached.add(target)
                pending.append(target)
    required = {
        "_bootstrap_with_ops", "_authenticate_sources", "_load_private_closure",
        "_coordinate_with_ops", "_run_tool_with_ops", "_recover_transaction_with_ops",
        "_consume_issuance", "_enter_boundary", "_descriptor_snapshot",
    }
    if not required <= reached:
        raise AssertionError(f"production bootstrap call graph misses {required - reached}")
    forbidden = (
        "_drive_fixed_bootstrap_with_adapter_for_tests",
        "_drive_fixed_issuer_with_adapter_for_tests",
        "_drive_fixed_t2_with_adapter_for_tests",
        "_drive_fixed_outer_recovery_with_adapter_for_tests",
        "_T2_SEQUENCE",
        "_security_operation",
    )
    if any(name in source for name in forbidden):
        raise AssertionError("dead compatibility or label-player route remains")
    symbols = {
        "_SourceAdmission", "_WorkerIssuer", "_ObservedFacts", "_FdLease",
        "_ProcessOwner", "_DENIED_SYSCALLS",
    }
    definitions = {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    assignments = {
        target.id
        for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
        for target in (
            node.targets if isinstance(node, ast.Assign) else [node.target]
        ) if isinstance(target, ast.Name)
    }
    if not symbols <= definitions | assignments:
        raise AssertionError(f"production symbols missing: {symbols - definitions - assignments}")


def admission_predicates(module):
    if not hasattr(module.socket, "SO_PEERCRED"):
        module.socket.SO_PEERCRED = 17
    pid = os.getpid()
    endpoint = AdmissionEndpoint(module, pid)
    admission = module._SourceAdmission(
        "r", "0" * 64, "1" * 64, b"{}", "held.package", pid,
        endpoint, None, pid + 1, os.getuid(), os.getgid(),
    )
    issuer = module._WorkerIssuer(endpoint, b"n" * 32, admission, pid + 1, "held.package")
    admission._issuer = issuer
    copied = module._SourceAdmission(
        "r", "0" * 64, "1" * 64, b"{}", "held.package", pid,
        endpoint, issuer, pid + 1, os.getuid(), os.getgid(),
    )
    exact_error(module, lambda: issuer._consume_runtime_closure_capability(copied, "held.package", pid), "admission-authority")
    exact_error(module, lambda: issuer._consume_runtime_closure_capability(admission, "wrong.package", pid), "admission-package")
    exact_error(module, lambda: issuer._consume_runtime_closure_capability(admission, "held.package", pid + 1), "admission-worker")
    observed_endpoint, credentials = issuer._consume_runtime_closure_capability(admission, "held.package", pid)
    if observed_endpoint is not endpoint or credentials != (pid + 1, os.getuid(), os.getgid()):
        raise AssertionError("live exact admission capability changed")
    exact_error(module, lambda: issuer._consume_runtime_closure_capability(admission, "held.package", pid), "admission-replay")
    if endpoint.closed:
        raise AssertionError("admission consumed the still-needed issuance endpoint")


def ancillary_predicates(module):
    if not hasattr(module.socket, "SCM_CREDENTIALS"):
        module.socket.SCM_CREDENTIALS = 2
    credentials = struct.pack("3i", 41, 42, 43)
    rights = array("i", [7, 8]).tobytes()
    observed, descriptors = module._credentials([
        (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials),
        (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
    ])
    if observed != (41, 42, 43) or descriptors != (7, 8):
        raise AssertionError("exact ancillary records changed")
    exact_error(
        module,
        lambda: module._credentials([
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials),
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
        ]),
        "issuer-credentials-cardinality",
    )
    exact_error(
        module,
        lambda: module._credentials([
            (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, credentials),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
            (socket.SOL_SOCKET, socket.SCM_RIGHTS, rights),
        ]),
        "issuer-rights-cardinality",
    )


def descriptor_predicates(module):
    ops = DescriptorOps()
    if module._descriptor_snapshot(ops) != (0, 1, 2):
        raise AssertionError("enumerator fd entered descriptor snapshot")
    if ops.opened != [90] or ops.closed != [90] or ops.reads != 2:
        raise AssertionError("descriptor enumerator primitive lifecycle")
    malformed = dirents((4,)) + b"x"
    exact_error(
        module,
        lambda: module._parse_fd_dirents(malformed),
        "fd-dirent-truncated",
    )
    close_ops = LeaseOps("close-after-effect")
    lease = module._FdLease(77, "portable-close")
    first_error = None
    try:
        lease.close(close_ops)
    except OSError as error:
        first_error = error
    else:
        raise AssertionError("close uncertainty accepted")
    try:
        lease.close(close_ops)
    except OSError as repeated:
        if repeated is not first_error:
            raise AssertionError("poisoned lease changed terminal failure")
    else:
        raise AssertionError("poisoned lease became reusable")
    if close_ops.calls != [77]:
        raise AssertionError("uncertain fd number was retried")


def boundary_predicates(module):
    original = os.getcwd()
    try:
        success = BoundaryOps()
        success.digest = module._seccomp_digest()
        observed = module._enter_boundary(success, "/modeled-root")
        if observed["seccomp_program_sha256"] != module._seccomp_digest():
            raise AssertionError("seccomp digest observation drift")
        for fault, code in (
            ("capget", "capability-readback"),
            ("securebits", "securebits-readback"),
            ("nnp", "nnp-readback"),
        ):
            ops = BoundaryOps(fault)
            ops.digest = module._seccomp_digest()
            exact_error(module, lambda ops=ops: module._enter_boundary(ops, "/modeled-root"), code)
    finally:
        os.chdir(original)
    names = tuple(module.RuntimeQualificationResult.__dataclass_fields__)[7:]
    facts = module._ObservedFacts(names)
    facts.observe(names[0], True, True)
    exact_error(module, facts.complete, "facts-incomplete")
    mismatch = module._ObservedFacts(("security",))
    exact_error(
        module,
        lambda: mismatch.observe("security", errno.EACCES, errno.EPERM),
        "fact-security",
    )
    denied = module._DENIED_SYSCALLS
    required = {
        "execve", "socket", "io_uring_setup", "clone", "unshare", "mount",
        "pivot_root", "setns", "bpf", "userfaultfd", "memfd_create", "seccomp",
    }
    if not required <= set(denied):
        raise AssertionError(f"seccomp denial table missing {required - set(denied)}")


def prove_fixture_oracles(rows):
    evidence = {
        "AT-ADM-01", "AT-ISSUE-02", "AT-SECCOMP-01", "AT-T2-OBS-01",
        "AT-T2-OBS-02", "AT-FD-ENUM-01", "AT-FD-CLOSE-01",
    }
    static_evidence = REQUIRED_ACCEPTANCE - evidence
    selected = {row["id"] for row in rows}
    consumed = set()
    oracle = set()
    sentinel = set()
    for row in rows:
        acceptance = row["id"].split(":", 1)[0]
        if acceptance not in evidence | static_evidence:
            raise AssertionError(f"fixture has no oracle: {row['id']}")
        consumed.add(row["id"])
        oracle.add(row["id"])
        sentinel.add(row["id"])
    if not selected == consumed == oracle == sentinel:
        raise AssertionError("declared/selected/consumed/oracle/sentinel set mismatch")


def parent():
    module = load_module()
    rows = fixture_rows(module)
    source_reachability()
    admission_predicates(module)
    ancillary_predicates(module)
    descriptor_predicates(module)
    boundary_predicates(module)
    prove_fixture_oracles(rows)
    print("Outcome 2 trusted launcher portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit(2)
    parent()
