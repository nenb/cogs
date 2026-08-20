#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy/aws-feasibility/remote"))

import completion_kata_fdmap as fdmap
import completion_kata_network_journal as journal_model
import completion_kata_nft_owner as owner
import completion_kata_operation as operation
import completion_kata_process as process


def rejected(call):
    try:
        call()
    except (owner.NftOwnerError, OSError, ValueError):
        return
    raise AssertionError("host-global NFT owner accepted hostile state")


# Portable record grammar: missing/torn/malformed and every non-FREE phase are
# never admission aliases. Historical and current deletion traces remain
# distinguishable without changing historical bytes.
fence = "a" * 64
initial = owner.initial_free_for_tests(
    fence,
    "12345678-1234-1234-1234-123456789abc",
    {"device": 1, "inode": 2},
)
parsed = owner._parse_state(initial)
assert parsed["phase"] == "FREE" and parsed["sequence"] == 0
source_text = (ROOT / "deploy/aws-feasibility/remote/completion_kata_nft_owner.py").read_text()
assert "os.O_RDWR | os.O_CREAT | os.O_EXCL" in source_text
assert "def provision_initial_free():" in source_text
assert "_global_legacy_census(provisioning=True)" in source_text
for hostile in (b"", initial[:-1], initial + b"x", initial.replace(b'"FREE"', b'"ACTIVE"')):
    rejected(lambda hostile=hostile: owner._parse_state(hostile))
assert journal_model.effect_command_trace(
    "NFT_REMOVE_ATOMIC", {"nft": {}}, journal_model.LEGACY_POLICY_VERSION
)[0] == "NFT_REMOVE_ATOMIC"
assert journal_model.effect_command_trace(
    "NFT_REMOVE_ATOMIC", {"nft": {}}, journal_model.POLICY_VERSION
)[:2] == ("NFT_TABLE", "NFT_REMOVE_ATOMIC")

# The production route derives a repeated global census itself. A paused old
# source owner is visible before it creates a child or command cgroup.
clean_processes = {"identities": [[1, 1]], "offenders": []}
clean_source = {"module_sha256": "1" * 64}
clean_journal = {"present": False}
clean_cgroup = {"present": False}
common = (
    patch.object(owner, "_boot_id", return_value="12345678-1234-1234-1234-123456789abc"),
    patch.object(owner, "_source_census", return_value=clean_source),
    patch.object(owner, "_journal_census", return_value=clean_journal),
    patch.object(owner, "_cgroup_census", return_value=clean_cgroup),
)
with common[0], common[1], common[2], common[3], \
     patch.object(owner, "_process_census", return_value=clean_processes):
    assert len(owner._global_legacy_census(provisioning=True)) == 64
paused = {"identities": [[1, 1], [77, 9]], "offenders": [{
    "pid": 77, "start_time": 9, "reasons": ["command"],
    "cmdline_sha256": "2" * 64, "cgroup_sha256": "3" * 64,
    "cwd": owner.SOURCE_ROOT, "executable": "/usr/bin/python3", "descriptors": [],
}]}
admission_context = SimpleNamespace(journal_key={"device": 1, "inode": 2})
common = (
    patch.object(owner, "_boot_id", return_value="12345678-1234-1234-1234-123456789abc"),
    patch.object(owner, "_source_census", return_value=clean_source),
    patch.object(owner, "_journal_census", return_value={"present": True}),
    patch.object(owner, "_cgroup_census", return_value=clean_cgroup),
)
with common[0], common[1], common[2], common[3], \
     patch.object(owner, "_process_census", return_value=paused):
    rejected(lambda: owner._global_legacy_census(admission_context))
with patch.object(owner.os, "close", side_effect=OSError(4, "uncertain")):
    rejected(lambda: owner._close_proven(123, "test lock"))


if sys.platform.startswith("linux") and os.geteuid() == 0:
    path = Path(f"/var/lib/cogs-stage2-nft-owner-test-{os.getpid()}")
    old_path = owner.OWNER_DIR
    context = SimpleNamespace(
        operation_token="b" * 64,
        journal_key={"kind": "file", "device": 1, "inode": 2},
        host_boot_id=owner._boot_id(),
        source_revision="c" * 40,
    )

    class Journal:
        def __init__(self):
            self.history = {
                "operation_token": context.operation_token,
                "phase": "BASELINES_CAPTURED", "terminal_sha256": "d" * 64,
                "tip": "NETWORK_SNAPSHOT_V2", "intents": (), "preexecs": (), "outcomes": (),
            }
        def runtime_recovery_history(self):
            return self.history

    original_context = operation._command_context

    def close_live(journal):
        live = owner._OWNERS.pop(context.operation_token, None)
        if live is None: return
        for descriptor in (live.lock_fd, *reversed(live.descriptors)):
            try: os.close(descriptor)
            except OSError: pass

    try:
        owner.OWNER_DIR = str(path)
        operation._command_context = lambda _journal: context
        original_census = owner._global_legacy_census
        owner._global_legacy_census = lambda context=None, provisioning=False: fence
        owner.provision_initial_free()
        rejected(owner.provision_initial_free)

        # Legacy empty-FD deletion evidence is fenced before FREE admission.
        legacy = Journal()
        legacy.history["intents"] = ({"command_id": "NFT_REMOVE_ATOMIC", "inherited_fds": []},)
        rejected(lambda: owner.acquire(legacy))
        assert owner._parse_state((path / owner.STATE_NAME).read_bytes())["phase"] == "FREE"

        # A deletion child holding the inherited exact OFD prevents an
        # independent contender after the owner dies. Child death releases the
        # lock, but ACTIVE still blocks recovery/retry and requires disposal.
        journal = Journal()
        live = owner.acquire(journal)
        claimed = owner.claim_child_binding(journal)
        bindings = fdmap._consume_nft_writer_lock((owner.LOCK_TARGET_FD,), claimed)
        ready_r, ready_w = os.pipe()
        stop_r, stop_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(ready_r); os.close(stop_w)
            fdmap.install(bindings)
            os.write(ready_w, b"R"); os.close(ready_w)
            os.read(stop_r, 1)
            os._exit(0)
        os.close(ready_w); os.close(stop_r)
        assert os.read(ready_r, 1) == b"R"; os.close(ready_r)
        process._prove_child_inherited_fds(pid, bindings)
        close_live(journal)
        opened, parent, _identity = owner._open_parent()
        try: rejected(lambda: owner._open_lock(parent))
        finally:
            for descriptor in reversed(opened): os.close(descriptor)
        os.close(stop_w); os.waitpid(pid, 0)
        opened, parent, _identity = owner._open_parent()
        try:
            descriptor, _identity = owner._open_lock(parent)
            os.close(descriptor)
        finally:
            for descriptor in reversed(opened): os.close(descriptor)
        rejected(lambda: owner.acquire(Journal()))
        assert owner._parse_state((path / owner.STATE_NAME).read_bytes())["phase"] == "ACTIVE"

        # Explicit test disposal restores the preprovisioned FREE fixture. An
        # uninterrupted unique command then performs ACTIVE->RELEASING->FREE.
        (path / owner.STATE_NAME).write_bytes(owner.initial_free_for_tests(fence))
        os.chmod(path / owner.STATE_NAME, 0o600)
        journal = Journal(); live = owner.acquire(journal)
        binding = {
            "role": owner.LOCK_ROLE, "target_fd": owner.LOCK_TARGET_FD,
            "generation": {}, "content_sha256": hashlib.sha256(b"").hexdigest(),
            "content_length": 0,
        }
        intent = {
            "command_id": "NFT_REMOVE_ATOMIC", "command_serial": 7,
            "binding_sha256": "e" * 64, "inherited_fds": [binding],
        }
        preexec = {
            "command_serial": 7, "cgroup_path": str(path / "absent-cgroup"),
            "pid": 2 ** 30, "proc_start_time": 1,
        }
        outcome = {
            "command_serial": 7, "outcome": "exited", "status": 0,
            "uncertain": False, "release_count": 1, "leader_reaped": True,
            "descendants_reaped": True, "cgroup_empty": True,
            "cgroup_removed": True, "pipes_eof": True, "errors": [],
            "stdout_length": 0, "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_length": 0, "stdout_truncated": False, "stderr_truncated": False,
        }
        journal.history.update({
            "phase": "FIREWALL_ABSENT", "tip": "FIREWALL_CLEANUP_SETTLED_V2",
            "terminal_sha256": "f" * 64, "intents": (intent,),
            "preexecs": (preexec,), "outcomes": (outcome,),
        })
        settled = owner.settle_free(journal, "firewall")
        assert settled["phase"] == "FREE" and settled["sequence"] == 3

        # A setup abort before NFT installation has no deletion child to reap,
        # but its durable network absence still releases the baseline owner.
        journal = Journal(); owner.acquire(journal)
        journal.history.update({
            "phase": "NETWORK_ABSENT", "tip": "NETWORK_CLEANUP_SETTLED_V2",
            "terminal_sha256": "8" * 64, "intents": (), "preexecs": (), "outcomes": (),
        })
        assert owner.settle_free(journal, "network")["phase"] == "FREE"

        # Close uncertainty is durable RELEASING, never completed FREE.
        journal = Journal(); owner.acquire(journal)
        journal.history.update({
            "phase": "FIREWALL_ABSENT", "tip": "FIREWALL_CLEANUP_SETTLED_V2",
            "terminal_sha256": "9" * 64, "intents": (intent,),
            "preexecs": (preexec,), "outcomes": (outcome,),
        })
        original_close_proven = owner._close_proven
        def uncertain_close(descriptor, label):
            os.close(descriptor)
            raise owner.NftOwnerError(label + " injected uncertainty")
        owner._close_proven = uncertain_close
        try: rejected(lambda: owner.settle_free(journal, "firewall"))
        finally: owner._close_proven = original_close_proven
        close_live(journal)
        assert owner._parse_state((path / owner.STATE_NAME).read_bytes())["phase"] == "RELEASING"
        (path / owner.STATE_NAME).write_bytes(owner.initial_free_for_tests(fence))
        os.chmod(path / owner.STATE_NAME, 0o600)

        # A cut after the first fsynced replacement remains RELEASING; closing
        # the local owner cannot make it admissible.
        journal = Journal(); live = owner.acquire(journal)
        journal.history.update({
            "phase": "FIREWALL_ABSENT", "tip": "FIREWALL_CLEANUP_SETTLED_V2",
            "terminal_sha256": "1" * 64, "intents": (intent,),
            "preexecs": (preexec,), "outcomes": (outcome,),
        })
        original_replace = owner._replace_state
        def cut(parent, value):
            original_replace(parent, value)
            if value["phase"] == "RELEASING":
                raise RuntimeError("cut after durable RELEASING")
        owner._replace_state = cut
        try:
            try:
                owner.settle_free(journal, "firewall")
            except RuntimeError:
                pass
            else:
                raise AssertionError("RELEASING cut did not stop transition")
        finally:
            owner._replace_state = original_replace
        close_live(journal)
        assert owner._parse_state((path / owner.STATE_NAME).read_bytes())["phase"] == "RELEASING"
        rejected(lambda: owner.acquire(Journal()))
    finally:
        operation._command_context = original_context
        if "original_census" in locals(): owner._global_legacy_census = original_census
        owner.OWNER_DIR = old_path
        for journal_id, live in tuple(owner._OWNERS.items()):
            for descriptor in (live.lock_fd, *reversed(live.descriptors)):
                try: os.close(descriptor)
                except OSError: pass
            owner._OWNERS.pop(journal_id, None)
        shutil.rmtree(path, ignore_errors=True)

print("completion Kata persistent NFT owner hostile-cut matrix passed")
