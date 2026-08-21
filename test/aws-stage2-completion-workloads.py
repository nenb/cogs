#!/usr/bin/env python3
"""Portable hostile tests for ADR 0099 non-authoritative host workloads."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
sys.path.insert(0, str(REMOTE))

import completion_guest_workloads as guest
import completion_package_candidate as candidate
import completion_runtime_contract as contract
import completion_workload_owner as owner


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def rejected(function, exception=Exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("hostile value was accepted")


fixed = contract.load_candidate_contract()
check(fixed.sha256 == contract.REVIEWED_CANDIDATE_SHA256, "candidate digest drift")
candidate_exact_bytes = contract.CANDIDATE_PATH.read_bytes()
check(hashlib.sha256(candidate_exact_bytes).hexdigest() == contract.REVIEWED_CANDIDATE_SHA256, "raw candidate digest drift")
check(candidate_exact_bytes != contract.canonical_json(fixed.value), "pretty reviewed input was mislabeled canonical")
check(fixed.value["sample_count"] == 7 and "deb_sha256" not in json.dumps(fixed.value), "candidate contract changed")
check(contract.REVIEWED_FINAL_PIN_SHA256 is None, "an unreviewed final digest was invented")
rejected(contract.load_final_pin, contract.FinalPinUnavailable)

identity = {
    "deb_sha256": "a" * 64,
    "deb_bytes": 1234,
    "installed_tree_sha256": fixed.value["bindings"]["installed_tree_sha256"],
    "installed_entries": 259,
    "installed_bytes": 1048576,
    "package": "cogs-stage2-fixture",
    "version": "1.0",
    "architecture": "all",
}
runtime_closure = {
    "version": "cogs.stage2-runtime-tool-closure/v1",
    "manifest_sha256": contract.RUNTIME_CLOSURE_MANIFEST_SHA256,
    "object_count": contract.RUNTIME_CLOSURE_OBJECT_COUNT,
    "tools": [dict(row) for row in contract.EXACT_TOOL_OBSERVATIONS],
}
final_value = {
    "version": "cogs.stage2-workload-final-pin/v1",
    "candidate_contract_sha256": fixed.sha256,
    "candidate_result_sha256": "c" * 64,
    "runtime_closure": runtime_closure,
    "package_identity": identity,
    "reproductions": ["A", "B"],
    "promotion": "manual-reviewed-a-equals-b",
}

# Exact bytes: symlink, hardlink, reformat, BOM, trailing data, duplicate key, and
# a final path without a separately reviewed digest all remain closed.
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary).resolve()
    original_candidate = contract.CANDIDATE_PATH
    original_final = contract.FINAL_PATH
    original_digest = contract.REVIEWED_FINAL_PIN_SHA256
    original_closure = contract.exact_runtime_closure
    exact = original_candidate.read_bytes()
    try:
        target = directory / "target.json"
        target.write_bytes(exact)
        symlink = directory / "symlink.json"
        symlink.symlink_to(target)
        contract.CANDIDATE_PATH = symlink
        rejected(contract.load_candidate_contract, contract.WorkloadContractError)

        hardlink = directory / "hardlink.json"
        os.link(target, hardlink)
        contract.CANDIDATE_PATH = hardlink
        rejected(contract.load_candidate_contract, contract.WorkloadContractError)
        hardlink.unlink()

        for number, raw in enumerate((
            json.dumps(json.loads(exact)).encode(),
            b"\xef\xbb\xbf" + exact,
            exact + b" ",
            b'{"version":1,"version":1}\n',
        )):
            hostile = directory / f"hostile-{number}.json"
            hostile.write_bytes(raw)
            contract.CANDIDATE_PATH = hostile
            rejected(contract.load_candidate_contract, contract.WorkloadContractError)

        contract.CANDIDATE_PATH = original_candidate
        final_path = directory / "final.json"
        canonical = contract.canonical_json(final_value)
        final_path.write_bytes(canonical)
        contract.FINAL_PATH = final_path
        rejected(contract.load_final_pin, contract.FinalPinUnavailable)
        contract.REVIEWED_FINAL_PIN_SHA256 = hashlib.sha256(canonical).hexdigest()
        contract.exact_runtime_closure = lambda: contract._runtime_closure_value(runtime_closure)
        final = contract.load_final_pin()
        check(final.final_pin_sha256 == hashlib.sha256(canonical).hexdigest(), "final raw digest missing")
        check(final.candidate_a == final.candidate_b == final.package_identity, "A=B representation differs")

        final_path.write_bytes(json.dumps(final_value, indent=2).encode() + b"\n")
        rejected(contract.load_final_pin, contract.WorkloadContractError)
        final_path.write_bytes(canonical)
        unequal_shape = copy.deepcopy(final_value)
        unequal_shape["candidate_a"] = identity
        final_path.write_bytes(contract.canonical_json(unequal_shape))
        contract.REVIEWED_FINAL_PIN_SHA256 = hashlib.sha256(final_path.read_bytes()).hexdigest()
        rejected(contract.load_final_pin, contract.WorkloadContractError)
    finally:
        contract.CANDIDATE_PATH = original_candidate
        contract.FINAL_PATH = original_final
        contract.REVIEWED_FINAL_PIN_SHA256 = original_digest
        contract.exact_runtime_closure = original_closure

# Authentic descriptor read under repeated rename/ABA yields one complete generation or
# rejects; the exact candidate loader would additionally reject every non-reviewed digest.
with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary).resolve()
    active = directory / "active"
    alternate = directory / "alternate"
    active.write_bytes(b"A" * 4096)
    alternate.write_bytes(b"B" * 4096)
    stop = False

    def swapper():
        spare = directory / "spare"
        while not stop:
            try:
                os.rename(active, spare)
                os.rename(alternate, active)
                os.rename(spare, alternate)
            except FileNotFoundError:
                pass

    thread = threading.Thread(target=swapper)
    thread.start()
    try:
        for _index in range(100):
            try:
                raw = contract._read_regular(active, 8192)
            except contract.WorkloadContractError:
                continue
            check(raw in {b"A" * 4096, b"B" * 4096}, "torn ABA read accepted")
    finally:
        stop = True
        thread.join()

# Destructive ownership uses Linux renameat2(RENAME_NOREPLACE). Darwin has no emulation:
# it fails closed and cannot turn portable tests into lifecycle evidence.
check(owner.PROCESS_CONTAINMENT.endswith("no-cgroup-v2"), "cgroup closure was claimed")
check("no-cgroup-proof" in owner.PROCESS_LIMITATION, "subreaper limitation is hidden")
if sys.platform == "darwin":
    rejected(lambda: owner._rename_noreplace(-1, "x", -1, "y"), owner.CleanupUncertain)

def synchronized_hook(stage_name, action):
    used = False

    def hook(stage, parent_fd, source, quarantine):
        nonlocal used
        if used or stage != stage_name:
            return
        used = True
        barrier = threading.Barrier(2)
        failure = []

        def racer():
            try:
                barrier.wait()
                action(parent_fd, source, quarantine)
            except BaseException as error:
                failure.append(error)

        thread = threading.Thread(target=racer)
        thread.start()
        barrier.wait()
        thread.join()
        if failure:
            raise failure[0]

    return hook


def descriptor_path(descriptor, name=""):
    base = Path(f"/proc/self/fd/{descriptor}")
    return base / name if name else base


# Authentic synchronized source, quarantine, output, inner-file, and inner-directory
# replacements run only where renameat2 and proc descriptors are the production surface.
linux_destructive_cases_ran = False
linux_foundation_cases_ran = set()
recovery_phases = ()
if sys.platform.startswith("linux") and os.geteuid() == 0:

    def new_root(temporary, name):
        return owner.OwnedRoot(Path(temporary).resolve() / name, owner.Deadline.start(8, 4), "host-candidate")

    with tempfile.TemporaryDirectory() as temporary:
        root = new_root(temporary, "source-swap")
        root.write_file("owned", b"owned")

        def swap_source(parent_fd, source, _quarantine):
            parent = descriptor_path(parent_fd)
            os.rename(parent / source, parent / "saved-retained")
            (parent / source).mkdir(mode=0o700)
            (parent / source / "replacement").write_bytes(b"replacement")

        owner._RACE_HOOK = synchronized_hook("source-root", swap_source)
        rejected(root.cleanup, owner.CleanupUncertain)
        parent = Path(temporary).resolve() / "source-swap"
        check((parent / "saved-retained" / "owned").read_bytes() == b"owned", "source generation was deleted")
        quarantines = list(parent.glob(".root-*"))
        check(len(quarantines) == 1 and (quarantines[0] / "replacement").read_bytes() == b"replacement", "source replacement was deleted or misclassified")
        tombstone = Path(temporary).resolve() / ".source-swap.recovery-v2"
        last_state = json.loads(tombstone.read_bytes().splitlines()[-1])
        check(last_state["phase"] == "uncertain", "source replacement was not categorized as cleanup uncertainty")
        linux_foundation_cases_ran.add("source-swap")
        owner._RACE_HOOK = None

    with tempfile.TemporaryDirectory() as temporary:
        root = new_root(temporary, "quarantine-collision")
        root.write_file("owned", b"owned")

        def collide(parent_fd, _source, quarantine):
            descriptor_path(parent_fd, quarantine).mkdir(mode=0o700)

        owner._RACE_HOOK = synchronized_hook("source-root", collide)
        rejected(root.cleanup, owner.CleanupUncertain)
        parent = Path(temporary).resolve() / "quarantine-collision"
        check((parent / "retained" / "owned").read_bytes() == b"owned", "collision moved source")
        check(len(list(parent.glob(".root-*"))) == 1, "collision destination disappeared")
        linux_foundation_cases_ran.add("quarantine-collision")
        owner._RACE_HOOK = None

    with tempfile.TemporaryDirectory() as temporary:
        root = new_root(temporary, "output-swap")
        output = os.open("command.out", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=root.fd)
        os.write(output, b"owned-output")

        def swap_output(parent_fd, source, _quarantine):
            parent = descriptor_path(parent_fd)
            os.rename(parent / source, parent / "saved-output")
            (parent / source).write_bytes(b"replacement-output")
            os.chmod(parent / source, 0o600)

        owner._RACE_HOOK = synchronized_hook("command-output", swap_output)
        rejected(lambda: root.remove_output(output), owner.CleanupUncertain)
        os.close(output)
        retained = Path(temporary).resolve() / "output-swap/retained"
        check((retained / "saved-output").read_bytes() == b"owned-output", "owned output disappeared")
        replacements = [path for path in retained.glob(".q-*") if path.is_file()]
        check(len(replacements) == 1 and replacements[0].read_bytes() == b"replacement-output", "output replacement disappeared")
        linux_foundation_cases_ran.add("output-swap")
        owner._RACE_HOOK = None

    with tempfile.TemporaryDirectory() as temporary:
        root = new_root(temporary, "stat-open-swap")
        root.mkdir("tree", 0o700)
        root.write_file("tree/value", b"owned-before-open", 0o600)
        used = False

        def swap_between_stat_open(stage, parent_fd, source, _quarantine):
            global used
            if stage != "stat-open" or source != "value" or used:
                return
            used = True
            parent = descriptor_path(parent_fd)
            barrier = threading.Barrier(2)

            def racer():
                barrier.wait()
                os.rename(parent / source, parent / "saved-before-open")
                (parent / source).write_bytes(b"replacement-before-open")
                os.chmod(parent / source, 0o600)

            thread = threading.Thread(target=racer)
            thread.start()
            barrier.wait()
            thread.join()

        owner._RACE_HOOK = swap_between_stat_open
        rejected(lambda: root.remove_tree("tree"), owner.CleanupUncertain)
        retained = Path(temporary).resolve() / "stat-open-swap/retained"
        tree_quarantine = next(path for path in retained.glob(".q-*") if path.is_dir())
        check((tree_quarantine / "saved-before-open").read_bytes() == b"owned-before-open", "stat/open source disappeared")
        check((tree_quarantine / "value").read_bytes() == b"replacement-before-open", "stat/open replacement disappeared")
        linux_foundation_cases_ran.add("stat-open-swap")
        owner._RACE_HOOK = None

    for kind in ("inner-file", "inner-directory"):
        with tempfile.TemporaryDirectory() as temporary:
            root = new_root(temporary, kind)
            root.mkdir("tree", 0o700)
            if kind == "inner-file":
                root.write_file("tree/value", b"owned-inner", 0o600)
            else:
                root.mkdir("tree/child", 0o700)
                root.write_file("tree/child/value", b"owned-inner", 0o600)

            def swap_inner(parent_fd, source, _quarantine):
                parent = descriptor_path(parent_fd)
                os.rename(parent / source, parent / "saved-inner")
                if kind == "inner-file":
                    (parent / source).write_bytes(b"replacement-inner")
                    os.chmod(parent / source, 0o600)
                else:
                    (parent / source).mkdir(mode=0o700)
                    (parent / source / "value").write_bytes(b"replacement-inner")

            owner._RACE_HOOK = synchronized_hook(kind, swap_inner)
            rejected(lambda: root.remove_tree("tree"), owner.CleanupUncertain)
            retained = Path(temporary).resolve() / kind / "retained"
            tree_quarantine = next(path for path in retained.glob(".q-*") if path.is_dir())
            if kind == "inner-file":
                check((tree_quarantine / "saved-inner").read_bytes() == b"owned-inner", "inner file disappeared")
                replacement = next(path for path in tree_quarantine.glob(".q-*") if path.is_file())
                check(replacement.read_bytes() == b"replacement-inner", "inner file replacement disappeared")
            else:
                check((tree_quarantine / "saved-inner/value").read_bytes() == b"owned-inner", "inner directory disappeared")
                replacement = next(path for path in tree_quarantine.glob(".q-*") if path.is_dir())
                check((replacement / "value").read_bytes() == b"replacement-inner", "inner directory replacement disappeared")
            linux_foundation_cases_ran.add(kind)
            owner._RACE_HOOK = None
    linux_destructive_cases_ran = True

# A real closed stdout is categorical; no traceback, path, command, or partial success
# document is reported by the helper process.
broken_output = subprocess.run(
    [
        sys.executable,
        "-B",
        "-c",
        (
            "import os,sys; sys.path.insert(0,sys.argv[1]); "
            "import completion_package_candidate as c; os.close(1); "
            "\ntry: c._write_stdout(b'x')\n"
            "except Exception as e: os.write(2, e.category.encode()+b'\\n')"
        ),
        str(REMOTE),
    ],
    capture_output=True,
    check=False,
    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"},
)
check(broken_output.returncode == 0 and broken_output.stdout == b"", "broken stdout escaped")
check(broken_output.stderr == b"output-uncertain\n", "broken stdout was not categorical")

# TERM/INT are categorical and do not disclose a path or command.
for number in (signal.SIGTERM, signal.SIGINT):
    try:
        with guest.SignalScope():
            os.kill(os.getpid(), number)
    except guest.WorkloadInterrupted as error:
        check(error.category == "interrupted" and "/" not in str(error), "signal was not categorical")
    else:
        raise AssertionError("signal did not interrupt")

# Linux closure repeatedly discovers pid/start-time or pidfd identities. The nested child
# forks from TERM, setsid-escapes, ignores TERM in one generation, and outlives its leader.
linux_containment_recovery_cases_ran = False
linux_exact_tool_transaction_cases_ran = False
linux_native_command_cases_ran = False
if sys.platform.startswith("linux") and os.geteuid() == 0:
    guest._enable_subreaper()
    with tempfile.TemporaryDirectory() as temporary:
        base = Path(temporary).resolve()
        os.chmod(base, 0o755)
        operation = base / "parent-isolation"
        deadline = guest.Deadline.start(4.0, 2.0)
        root = guest.OwnedRoot(operation, deadline, "host-candidate")
        parent_status = os.lstat(operation)
        retained_status = os.lstat(operation / "retained")
        check(stat.S_IMODE(parent_status.st_mode) == 0o700 and parent_status.st_uid == 0, "operation parent is not root-owned mode 0700")
        check((retained_status.st_uid, retained_status.st_gid) == (owner.WORKLOAD_UID, owner.WORKLOAD_GID), "retained root is not workload-owned")
        escape = r'''
import ctypes, json, os
status = {}
for line in open('/proc/self/status', encoding='ascii'):
    if ':' in line:
        key, value = line.split(':', 1)
        status[key] = value.strip()
assert os.getresuid() == (65534, 65534, 65534)
assert os.getresgid() == (65534, 65534, 65534)
assert os.getgroups() == []
assert status['CapInh'] == status['CapPrm'] == status['CapEff'] == status['CapBnd'] == status['CapAmb'] == '0000000000000000'
assert status['NoNewPrivs'] == '1'
assert ctypes.CDLL(None).prctl(27, 0, 0, 0, 0) & 0x0F == 0x0F
blocked = 0
for operation in (
    lambda: os.listdir('..'),
    lambda: os.rename('../retained', '../renamed'),
    lambda: os.chown('..', 65534, 65534),
):
    try:
        operation()
    except PermissionError:
        blocked += 1
assert blocked == 3
fds = []
for name in os.listdir('/proc/self/fd'):
    try:
        fds.append(os.readlink('/proc/self/fd/' + name))
    except OSError:
        pass
assert not any('recovery-v2' in value or value.endswith('/parent-isolation') for value in fds)
assert sum(value.endswith('/retained') for value in fds) == 1
print(json.dumps({'blocked': blocked, 'uid': os.geteuid(), 'gid': os.getegid(), 'zero_caps': True}, sort_keys=True, separators=(',', ':')))
'''
        expected = b'{"blocked":3,"gid":65534,"uid":65534,"zero_caps":true}\n'
        guest._run((sys.executable, "-c", escape), root, deadline, expected)
        attacker = subprocess.run(
            [
                sys.executable,
                "-c",
                "import os,sys;os.setgroups([]);os.setgid(65534);os.setuid(65534);p=sys.argv[1];n=0"
                "\nfor f in (lambda:os.listdir(p),lambda:os.rename(p+'/retained',p+'/renamed'),lambda:os.chown(p,65534,65534)):"
                "\n try:f()"
                "\n except PermissionError:n+=1"
                "\nprint('blocked',n) if n==3 else sys.exit(9)",
                str(operation),
            ],
            capture_output=True,
            check=False,
        )
        check(attacker.returncode == 0 and attacker.stdout == b"blocked 3\n", "unrelated uid 65534 reached the parent")
        check(not (operation / "renamed").exists(), "uid attacker renamed retained root")
        root.cleanup()
        linux_foundation_cases_ran.add("parent-isolation")

    with tempfile.TemporaryDirectory() as temporary:
        deadline = guest.Deadline.start(2.0, 1.2)
        root = guest.OwnedRoot(Path(temporary).resolve() / "timeout", deadline, "host-candidate")
        started = time.monotonic()
        rejected(lambda: guest._run((sys.executable, "-c", "import time; time.sleep(30)"), root, deadline), guest.WorkloadDeadline)
        check(time.monotonic() - started < 2.0, "timeout was not bounded")
        root.cleanup()
        check(not guest._children(), "timeout child remained")
        linux_foundation_cases_ran.add("timeout")

    nested_program = r'''
import os, signal, time
pid = os.fork()
if pid:
    raise SystemExit(0)
os.setsid()
def on_term(_number, _frame):
    nested = os.fork()
    if nested == 0:
        os.setsid()
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(30)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
signal.signal(signal.SIGTERM, on_term)
time.sleep(30)
'''
    with tempfile.TemporaryDirectory() as temporary:
        deadline = guest.Deadline.start(4.0, 2.5)
        root = guest.OwnedRoot(Path(temporary).resolve() / "nested", deadline, "host-candidate")
        rejected(lambda: guest._run((sys.executable, "-c", nested_program), root, deadline), owner.ChildUncertain)
        check(not guest._children(), "nested escaped child remained")
        root.cleanup()
        linux_foundation_cases_ran.add("nested-descendants")

    # SIGKILL every fsync-ordered construction/cleanup state. Recovery authenticates
    # partial construction, root-already-absent, journal-retired, and parent-absent cuts.
    recovery_phases = (
        "tombstone-created",
        "tombstone-durable",
        "intent",
        "parent-staging-created",
        "parent-marker-durable",
        "parent-published",
        "parent-created",
        "root-created",
        "root-marker-durable",
        "journal-durable",
        "running",
        "work-running",
        "child-empty",
        "root-removing",
        "root-quarantined",
        "root-contents-removed",
        "root-directory-removed",
        "root-removed",
        "recovery.json-quarantined",
        "recovery.json-removed",
        ".parent-generation-quarantined",
        ".parent-generation-removed",
        "journal-retired",
        "parent-removing",
        "parent-quarantined",
        "parent-directory-removed",
        "parent-removed",
    )
    for phase in recovery_phases:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            operation = directory / f"recover-{phase}"
            counter = directory / "work-count"
            helper_program = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
import completion_workload_owner as owner
target, operation, counter = sys.argv[2:]
def cut(phase):
    if phase == target:
        os.kill(os.getpid(), 9)
owner._STATE_HOOK = cut
owner._CLEANUP_HOOK = cut
root = owner.OwnedRoot(operation, owner.Deadline.start(30, 20), 'host-candidate')
with open(counter, 'ab') as stream:
    stream.write(b'work\n')
    stream.flush()
    os.fsync(stream.fileno())
root.write_file('effect', b'exact', 0o600)
if target == 'work-running':
    os.kill(os.getpid(), 9)
root.cleanup()
'''
            helper = subprocess.run(
                [sys.executable, "-B", "-c", helper_program, str(REMOTE), phase, str(operation), str(counter)],
                capture_output=True,
                check=False,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONDONTWRITEBYTECODE": "1"},
            )
            check(helper.returncode < 0, f"SIGKILL cut {phase} did not fire")
            before = counter.read_bytes() if counter.exists() else b""
            tombstones = list(directory.glob(f".{operation.name}.recovery-*"))
            check(len(tombstones) == 1, f"{phase} lost or duplicated the external tombstone")
            owner.recover_workload_root(operation, "host-candidate")
            check(not operation.exists() and not list(directory.glob(f".{operation.name}.recovery-*")), f"{phase} recovery left residue")
            after = counter.read_bytes() if counter.exists() else b""
            check(after == before and after in {b"", b"work\n"}, f"{phase} recovery retried work")
            rejected(lambda operation=operation: owner.recover_workload_root(operation, "host-candidate"), Exception)
            check(not operation.exists(), f"{phase} second recovery changed absence")
            linux_foundation_cases_ran.add(f"recovery:{phase}")
    linux_containment_recovery_cases_ran = True

    # Production transaction seams run without replacing workload functions when the exact
    # reviewed Linux tool closure is present. Post-pin uses exact synthetic reviewed bytes.
    versions = (
        subprocess.run([guest.GIT, "--version"], capture_output=True, check=False).stdout,
        subprocess.run([guest.DPKG_DEB, "--version"], capture_output=True, check=False).stdout.splitlines()[:1],
        subprocess.run([guest.DPKG, "--version"], capture_output=True, check=False).stdout.splitlines()[:1],
    )
    exact_tools = (
        versions[0] == b"git version 2.47.3\n"
        and versions[1] == [b"Debian 'dpkg-deb' package archive backend version 1.22.22 (amd64)."]
        and versions[2] == [b"Debian 'dpkg' package management program version 1.22.22 (amd64)."]
    )
    try:
        exact_closure_available = contract.exact_runtime_closure() == contract._runtime_closure_value(runtime_closure)
    except contract.WorkloadContractError:
        exact_closure_available = False
    if exact_tools and exact_closure_available and not candidate.CANDIDATE_ROOT.exists() and not candidate.POST_PIN_ROOT.exists():
        linux_exact_tool_transaction_cases_ran = True
        candidate_raw = candidate.run_candidate_transaction()
        candidate_result = json.loads(candidate_raw)
        check(candidate_raw == contract.canonical_json(candidate_result), "candidate output bytes are not canonical")
        check(candidate_result["authority"] == "non-authoritative-host-candidate-only", "candidate authority changed")
        check(not candidate.CANDIDATE_ROOT.exists(), "candidate emitted before cleanup")
        cuts = []

        def fail_between(stage):
            cuts.append(stage)
            if stage == "after-candidate-a":
                raise candidate.CandidateError("injected categorical cut")

        candidate._TRANSACTION_HOOK = fail_between
        try:
            rejected(candidate.run_candidate_transaction, candidate.CandidateError)
        finally:
            candidate._TRANSACTION_HOOK = None
        check(cuts == ["after-candidate-a"], "failure cut retried or reached candidate B")
        check(not candidate.CANDIDATE_ROOT.exists(), "failure cut left candidate operation")
        original_final = contract.FINAL_PATH
        original_digest = contract.REVIEWED_FINAL_PIN_SHA256
        with tempfile.TemporaryDirectory() as temporary:
            final_path = Path(temporary).resolve() / "final.json"
            pinned = copy.deepcopy(final_value)
            pinned["package_identity"] = candidate_result["package_identity"]
            final_raw = contract.canonical_json(pinned)
            final_path.write_bytes(final_raw)
            contract.FINAL_PATH = final_path
            contract.REVIEWED_FINAL_PIN_SHA256 = hashlib.sha256(final_raw).hexdigest()
            try:
                post_raw = candidate.run_post_pin_transaction()
                post_result = json.loads(post_raw)
                check(post_raw == contract.canonical_json(post_result), "post-pin output bytes are not canonical")
                check(post_result["final_pin_sha256"] == contract.REVIEWED_FINAL_PIN_SHA256, "post-pin digest differs")
                check(not candidate.POST_PIN_ROOT.exists(), "post-pin emitted before cleanup")
            finally:
                contract.FINAL_PATH = original_final
                contract.REVIEWED_FINAL_PIN_SHA256 = original_digest

# The V2 producer is normally imported only from the verified fixed source. Load it with
# bounded synthetic top-level bytes to execute its diagnostic state machine portably.
def load_native_probe():
    driver = Path("/var/lib/cogs/stage2-completion-v1/source/scripts/run-stage2-package-native-candidate.py")
    manifest = Path("/var/lib/cogs/stage2-completion-v1/source/.cogs-stage2-source-manifest-v1.json")
    original = Path.read_bytes
    def read_bytes(path):
        if path == driver:
            return b"reviewed-launcher"
        if path == manifest:
            return b'{"revision":"1111111111111111111111111111111111111111"}\n'
        return original(path)
    Path.read_bytes = read_bytes
    try:
        spec = importlib.util.spec_from_file_location(
            "completion_package_native_candidate_probe",
            REMOTE / "completion_package_native_candidate.py",
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        Path.read_bytes = original


native_probe = load_native_probe()
command_observation = native_probe.NativeCommandObserved(2, b"dpkg-deb: warning: error\n")
check(command_observation.category == "exit-2-warning-1-error-1-bytes-25",
      "native command observation category changed")
command_observation = native_probe.NativeCommandObserved(-9, b"")
check(command_observation.category == "exit--9-warning-0-error-0-bytes-0",
      "native command signal observation category changed")
class ProbePackageDeadline:
    def cleanup_check(self): pass
class ProbePackageRoot:
    def __init__(self, cleanup_error=None, parent_error=None):
        self.cleanup_error, self.parent_error, self.remove_calls = cleanup_error, parent_error, 0
    def mkdir(self, relative, *_args, **_kwargs):
        if relative == "package-candidate-a" and self.parent_error is not None:
            raise self.parent_error
    def proc_path(self, value=""): return f"/probe/{value}" if value else "/probe"
    def remove_tree(self, _relative):
        self.remove_calls += 1
        if self.cleanup_error is not None: raise self.cleanup_error
class ProbePackageTools:
    descriptors = ()
    dpkg_deb = type("Tool", (), {"executable": "/usr/bin/dpkg-deb"})()
    dpkg = type("Tool", (), {"executable": "/usr/bin/dpkg"})()

def package_stage_failure(materialize_error, cleanup_error=None):
    root = ProbePackageRoot(cleanup_error)
    original_materialize = native_probe._materialize
    try:
        native_probe._materialize = lambda *_args: (_ for _ in ()).throw(materialize_error)
        native_probe._run_native_package_sample(
            root, "candidate-a", "build-a", ProbePackageTools(), ProbePackageDeadline())
    except native_probe.NativeCandidateStageError as error:
        return error
    finally:
        native_probe._materialize = original_materialize
    raise AssertionError("native package sample staged failure was accepted")

parent_root = ProbePackageRoot(parent_error=OSError(5, "parent"))
try:
    native_probe._run_native_package_sample(
        parent_root, "candidate-a", "build-a", ProbePackageTools(), ProbePackageDeadline())
except native_probe.NativeCandidateStageError as package_error:
    check((package_error.stage, package_error.category) == ("build-a-package-parent", "OSError_5"),
          "native package parent stage changed")
    check(parent_root.remove_calls == 0, "pre-ownership package failure attempted cleanup")
else:
    raise AssertionError("native package parent failure was accepted")

command_root = ProbePackageRoot()
original_materialize = native_probe._materialize
original_command = native_probe._run_native_command
try:
    native_probe._materialize = lambda *_args: None
    native_probe._run_native_command = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        native_probe.NativeCommandObserved(7, b"private-error-marker\n"))
    native_probe._run_native_package_sample(
        command_root, "candidate-a", "build-a", ProbePackageTools(), ProbePackageDeadline())
except native_probe.NativeCandidateStageError as package_error:
    check(package_error.stage == "build-a-dpkg-build", "native command package stage changed")
    check(package_error.category == "exit-7-warning-0-error-1-bytes-21",
          "native command package category changed")
    check("private" not in str(package_error) and "marker" not in str(package_error),
          "native command package diagnostic leaked output")
else:
    raise AssertionError("native package command failure was accepted")
finally:
    native_probe._materialize = original_materialize
    native_probe._run_native_command = original_command

package_error = package_stage_failure(owner.WorkloadError("source"))
check((package_error.stage, package_error.category) == ("build-a-package-source", "invariant"),
      "native package source stage changed")
package_error = package_stage_failure(
    owner.WorkloadError("source"), owner.CleanupUncertain("cleanup"))
check((package_error.stage, package_error.category) == ("build-a-package-cleanup", "cleanup-uncertain"),
      "native package cleanup stage did not override work")
package_error = package_stage_failure(KeyboardInterrupt())
check((package_error.stage, package_error.category) == ("build-a-package-source", "interrupted"),
      "native package sample interruption category changed")

if sys.platform.startswith("linux") and os.geteuid() == 0:
    with tempfile.TemporaryDirectory() as temporary:
        native_path = Path(temporary) / "native-command"
        shared_path = Path(temporary) / "shared-command"
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"fd-ok")
        os.close(write_fd)
        program = (
            "import os,sys; raw=os.read(int(sys.argv[1]),5); "
            "sys.stdout.buffer.write(os.environ['LANG'].encode()+b':' + raw + b'\\n')"
        )
        native_deadline = owner.Deadline.start(30, 20)
        native_root = owner.OwnedRoot(native_path, native_deadline, "host-candidate")
        try:
            native_raw = native_probe._run_native_command(
                (sys.executable, "-I", "-c", program, str(read_fd)),
                native_root, native_deadline, (read_fd,))
        finally:
            os.close(read_fd)
            native_root.cleanup()
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"fd-ok")
        os.close(write_fd)
        shared_deadline = owner.Deadline.start(30, 20)
        shared_root = owner.OwnedRoot(shared_path, shared_deadline, "host-candidate")
        try:
            shared_raw = owner._run(
                (sys.executable, "-I", "-c", program, str(read_fd)),
                shared_root, shared_deadline, pass_fds=(read_fd,),
                environment=dict(guest._ENV))
        finally:
            os.close(read_fd)
            shared_root.cleanup()
        check(native_raw == shared_raw == b"C:fd-ok\n", "native/shared command success parity changed")

        observed_path = Path(temporary) / "observed-command"
        observed_deadline = owner.Deadline.start(30, 20)
        observed_root = owner.OwnedRoot(observed_path, observed_deadline, "host-candidate")
        try:
            try:
                native_probe._run_native_command(
                    (sys.executable, "-I", "-c", "import sys; print('private-error-marker'); sys.exit(7)"),
                    observed_root, observed_deadline)
            except native_probe.NativeCommandObserved as error:
                check(error.category == "exit-7-warning-0-error-1-bytes-21",
                      "native nonzero observation changed")
                check("private" not in str(error) and "marker" not in str(error),
                      "native nonzero observation leaked output")
            else:
                raise AssertionError("native nonzero command was accepted")
        finally:
            observed_root.cleanup()

        bounded_path = Path(temporary) / "bounded-command"
        bounded_deadline = owner.Deadline.start(30, 20)
        bounded_root = owner.OwnedRoot(bounded_path, bounded_deadline, "host-candidate")
        try:
            bounded_raw = native_probe._run_native_command(
                (sys.executable, "-I", "-c", "import os; os.write(1,b'x'*70000)"),
                bounded_root, bounded_deadline)
            check(len(bounded_raw) <= owner.MAX_COMMAND_OUTPUT,
                  "native command output exceeded its bound")
        finally:
            bounded_root.cleanup()

        timeout_path = Path(temporary) / "timeout-command"
        timeout_deadline = owner.Deadline.start(2, 1)
        descriptors_before = len(os.listdir("/proc/self/fd"))
        timeout_root = owner.OwnedRoot(timeout_path, timeout_deadline, "host-candidate")
        try:
            rejected(lambda: native_probe._run_native_command(
                (sys.executable, "-I", "-c",
                 "import subprocess,time; subprocess.Popen(['sleep','10']); time.sleep(10)"),
                timeout_root, timeout_deadline), owner.WorkloadDeadline)
            check(not owner._children(), "native timeout left descendants")
        finally:
            timeout_root.cleanup()
        descriptors_after = len(os.listdir("/proc/self/fd"))
        check(descriptors_after == descriptors_before,
              f"native timeout changed descriptor baseline {descriptors_before}->{descriptors_after}")

        removal_path = Path(temporary) / "removal-command"
        removal_deadline = owner.Deadline.start(30, 20)
        removal_root = owner.OwnedRoot(removal_path, removal_deadline, "host-candidate")
        original_remove_output = removal_root.remove_output
        removal_root.remove_output = lambda _descriptor: (_ for _ in ()).throw(
            owner.OutputUncertain("injected output removal uncertainty"))
        try:
            rejected(lambda: native_probe._run_native_command(
                (sys.executable, "-I", "-c", "import sys; sys.exit(7)"),
                removal_root, removal_deadline), owner.OutputUncertain)
        finally:
            removal_root.remove_output = original_remove_output
            removal_root.cleanup()
        linux_native_command_cases_ran = True

original_environment = os.environ.get("COGS_PACKAGE_REVIEWED_HEAD")
os.environ["COGS_PACKAGE_REVIEWED_HEAD"] = native_probe.SOURCE_REVISION
class ProbeSignalScope:
    close_error = None
    def __enter__(self): return self
    def __exit__(self, *_args):
        if self.close_error is not None: raise self.close_error
        return False
class ProbeRoot:
    def __init__(self, cleanup_error): self.cleanup_error = cleanup_error
    def mkdir(self, *_args, **_kwargs): pass
    def cleanup(self):
        if self.cleanup_error is not None: raise self.cleanup_error
class ProbeTools:
    def __init__(self, close_error): self.close_error = close_error
    def close(self):
        if self.close_error is not None: raise self.close_error

def staged_transaction_failure(primary, cleanup_error=None, close_error=None,
                               signal_close_error=None):
    root = ProbeRoot(cleanup_error)
    tools_probe = ProbeTools(close_error)
    replacements = {
        "Deadline": type("ProbeDeadline", (), {"start": staticmethod(lambda: object())}),
        "SignalScope": ProbeSignalScope,
        "load_candidate_contract": lambda: object(),
        "require_linux_amd64_root": lambda: None,
        "exact_runtime_closure": lambda: object(),
        "ToolSet": lambda: tools_probe,
        "OwnedRoot": lambda *_args: root,
        "_check_versions": lambda *_args: (_ for _ in ()).throw(primary),
    }
    previous = {name: getattr(native_probe, name) for name in replacements}
    try:
        ProbeSignalScope.close_error = signal_close_error
        for name, value in replacements.items(): setattr(native_probe, name, value)
        native_probe.run_candidate_transaction()
    except native_probe.NativeCandidateStageError as error:
        return error
    finally:
        ProbeSignalScope.close_error = None
        for name, value in previous.items(): setattr(native_probe, name, value)
    raise AssertionError("staged native transaction failure was accepted")

try:
    staged = staged_transaction_failure(owner.WorkloadError("primary"))
    check((staged.stage, staged.category) == ("tool-version", "invariant"),
          "primary native transaction stage/category changed")
    staged = staged_transaction_failure(
        owner.WorkloadError("primary"), owner.CleanupUncertain("cleanup"))
    check((staged.stage, staged.category) == ("transaction-cleanup", "cleanup-uncertain"),
          "native transaction cleanup did not override the primary stage")
    staged = staged_transaction_failure(owner.WorkloadError("primary"), close_error=OSError(5, "close"))
    check((staged.stage, staged.category) == ("tool-close", "OSError_5"),
          "native tool-close category changed")
    staged = staged_transaction_failure(KeyboardInterrupt())
    check((staged.stage, staged.category) == ("tool-version", "interrupted"),
          "native transaction interruption category changed")
    staged = staged_transaction_failure(
        owner.WorkloadError("primary"), signal_close_error=OSError(5, "signal close"))
    check((staged.stage, staged.category) == ("signal-scope-close", "OSError_5"),
          "native signal-scope teardown stage changed")
finally:
    if original_environment is None:
        os.environ.pop("COGS_PACKAGE_REVIEWED_HEAD", None)
    else:
        os.environ["COGS_PACKAGE_REVIEWED_HEAD"] = original_environment

# Semantic codecs make A=B structural (one identity) and reject every summary mismatch.
tools = [dict(row) for row in contract.EXACT_TOOL_OBSERVATIONS]
runtime_pin = contract._runtime_closure_value(runtime_closure)
binding = contract.execution_binding(tools, runtime_pin)
candidate_value = {
    "version": "cogs.stage2-workload-candidate/v1",
    "result": "pass",
    "authority": "non-authoritative-host-candidate-only",
    "candidate_contract_sha256": fixed.sha256,
    "final_pin_sha256": None,
    "package_identity": identity,
    "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
    "a_equals_b": True,
    "lifecycle_deleted": True,
    "promotion": "external-manual-review-required",
    "execution_binding": binding,
}
contract.validate_candidate_result(candidate_value)
native_revision = "1" * 40
native_manifest = "2" * 64
native_binding = contract.native_execution_binding(
    tools, runtime_pin, contract.NATIVE_LAUNCHER_SHA256, native_revision, native_manifest)
native_value = {
    **candidate_value,
    "version": "cogs.stage2-workload-candidate/v2",
    "authority": "non-authoritative-retained-rootfs-candidate-only",
    "execution_binding": native_binding,
}
contract.validate_native_candidate_result(native_value, native_revision, native_manifest)
rejected(lambda: contract.validate_native_candidate_result(native_value), TypeError)
rejected(lambda: contract.validate_native_candidate_result(
    native_value, None, native_manifest), contract.WorkloadContractError)
rejected(lambda: contract.validate_native_candidate_result(
    native_value, native_revision, None), contract.WorkloadContractError)
rejected(lambda: contract.validate_candidate_result(native_value), contract.WorkloadContractError)
rejected(lambda: contract.validate_native_candidate_result(
    candidate_value, native_revision, native_manifest), contract.WorkloadContractError)
changed_native = copy.deepcopy(native_value)
changed_native["execution_binding"]["rootfs_execution"] = "not-used-by-host-candidate-or-reproduction"
rejected(lambda: contract.validate_native_candidate_result(
    changed_native, native_revision, native_manifest), contract.WorkloadContractError)
for field in (
    "launcher_implementation_sha256",
    "native_producer_implementation_sha256",
    "runtime_codec_implementation_sha256",
):
    changed_native = copy.deepcopy(native_value)
    changed_native["execution_binding"][field] = "d" * 64
    rejected(lambda changed_native=changed_native:
             contract.validate_native_candidate_result(
                 changed_native, native_revision, native_manifest),
             contract.WorkloadContractError)
rejected(lambda: contract.native_execution_binding(
    tools, runtime_pin, "d" * 64, native_revision, native_manifest), contract.WorkloadContractError)
for expected_revision, expected_manifest in (
    ("3" * 40, native_manifest),
    (native_revision, "3" * 64),
):
    rejected(lambda expected_revision=expected_revision, expected_manifest=expected_manifest:
             contract.validate_native_candidate_result(
                 native_value, expected_revision, expected_manifest),
             contract.WorkloadContractError)
for field, hostile in (("source_revision", "3" * 40), ("source_manifest_sha256", "3" * 64)):
    changed_native = copy.deepcopy(native_value)
    changed_native["execution_binding"][field] = hostile
    rejected(lambda changed_native=changed_native: contract.validate_native_candidate_result(
        changed_native, native_revision, native_manifest), contract.WorkloadContractError)
for key, hostile in (
    ("authority", "authoritative"),
    ("final_pin_sha256", "f" * 64),
    ("a_equals_b", False),
    ("lifecycle_deleted", False),
    ("reproductions", list(reversed(candidate_value["reproductions"]))),
):
    changed = copy.deepcopy(candidate_value)
    changed[key] = hostile
    rejected(lambda changed=changed: contract.validate_candidate_result(changed), contract.WorkloadContractError)

parsed_identity = contract.parse_identity(identity)
semantic_final = contract.FinalPin(fixed.sha256, "c" * 64, "f" * 64, parsed_identity, runtime_pin)
post_value = {
    "version": "cogs.stage2-workload-post-pin/v1",
    "result": "pass",
    "authority": "non-authoritative-host-reproduction-only",
    "candidate_contract_sha256": fixed.sha256,
    "final_pin_sha256": "f" * 64,
    "package_identity": identity,
    "reproductions": [{"id": "A", "deleted": True}, {"id": "B", "deleted": True}],
    "matches_final_pin": True,
    "lifecycle_deleted": True,
    "execution_binding": binding,
}
contract.validate_post_pin_result(post_value, semantic_final)
rejected(lambda: contract.validate_post_pin_result(post_value), TypeError)
rejected(lambda: contract.validate_post_pin_result(post_value, None), contract.WorkloadContractError)
for key, hostile in (
    ("authority", "authoritative"),
    ("final_pin_sha256", None),
    ("matches_final_pin", False),
    ("lifecycle_deleted", False),
    ("reproductions", list(reversed(post_value["reproductions"]))),
):
    changed = copy.deepcopy(post_value)
    changed[key] = hostile
    rejected(lambda changed=changed: contract.validate_post_pin_result(changed, semantic_final), contract.WorkloadContractError)

# Darwin's production route fails before creating an owned root and cannot invent a pin.
if sys.platform == "darwin":
    check(not os.path.lexists(candidate.CANDIDATE_ROOT), "candidate root pre-existed")
    rejected(candidate.run_candidate_transaction)
    check(not os.path.lexists(candidate.CANDIDATE_ROOT), "Darwin created a candidate root")
    check(contract.REVIEWED_FINAL_PIN_SHA256 is None, "Darwin invented a final pin")

native_source = (REMOTE / "completion_package_native_candidate.py").read_text()
check("class NativeCandidateStageError" in native_source and "_stage_failure(stage, error)" in native_source,
      "native transaction stage errors are not retained")
for required_stage in (
    "transaction-inputs", "contract-load", "platform-check", "runtime-closure",
    "tool-open", "owned-root", "tool-version", "tool-observations", "build-a",
    "post-a-tools", "post-a-contract", "build-b", "compare-a-b", "post-b-tools",
    "post-b-contract", "result-binding", "transaction-cleanup", "tool-close",
    "signal-scope-close", "result-presence", "result-validation", "result-encoding",
    "package-parent", "package-source", "dpkg-build", "deb-readback", "admin-setup", "dpkg-install",
    "installed-tree", "status-readback", "status-verify", "identity",
    "package-cleanup", "duration",
):
    check(required_stage in native_source, f"missing native transaction stage {required_stage}")

source = "\n".join((REMOTE / name).read_text() for name in (
    "completion_runtime_contract.py",
    "completion_workload_owner.py",
    "completion_guest_workloads.py",
    "completion_package_candidate.py",
    "completion_package_candidate_recovery.py",
    "completion_package_post_pin_recovery.py",
))
for recovery_name in ("completion_package_candidate_recovery.py", "completion_package_post_pin_recovery.py"):
    recovery_source = (REMOTE / recovery_name).read_text()
    check("completion_guest_workloads" not in recovery_source and "completion_package_candidate" not in recovery_source, "recovery entry can reach work")
for forbidden in ("local-standalone-kata", "workload-local-qualification", "completion_local_full", "CAP_CHOWN"):
    check(forbidden not in source, "removed authority or capability remains in host source")
for cloud in ("boto", "AWS_", "requests", "urllib", "Terraform", "OpenTofu"):
    check(cloud not in source, "cloud surface entered host workload")
# ADR 0100 binds rejected v1 status to protected main, not arbitrary branch history.
v1_on_protected_main = subprocess.run(
    ["git", "cat-file", "-e", "69eccf1:schemas/stage2-workload-local-qualification-v1.json"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
check(v1_on_protected_main.returncode != 0, "protected main contained rejected qualification v1")
if os.environ.get("COGS_REQUIRE_STAGE2_WORKLOAD_LINUX_FOUNDATIONS") == "1":
    check(sys.platform.startswith("linux") and os.geteuid() == 0, "Linux root foundation environment absent")
    check(linux_destructive_cases_ran, "Linux destructive ownership cases skipped")
    check(linux_containment_recovery_cases_ran, "Linux containment/recovery cases skipped")
    check(linux_native_command_cases_ran, "Linux native command cases skipped")
    required_foundations = {
        "source-swap",
        "quarantine-collision",
        "output-swap",
        "stat-open-swap",
        "inner-file",
        "inner-directory",
        "parent-isolation",
        "timeout",
        "nested-descendants",
        *(f"recovery:{phase}" for phase in recovery_phases),
    }
    check(linux_foundation_cases_ran == required_foundations, "required Linux foundation case set differs")
print(
    "completion workload contract tests passed "
    f"linux_destructive={linux_destructive_cases_ran} "
    f"linux_containment_recovery={linux_containment_recovery_cases_ran} "
    f"linux_native_command={linux_native_command_cases_ran} "
    f"linux_exact_tools={linux_exact_tool_transaction_cases_ran}"
)
