#!/usr/bin/env python3
"""Portable hostile tests and Linux syscall qualification for D-R2.2a."""

import ast
import dataclasses
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deploy/aws-feasibility/remote/completion_rootfs_fs.py"
spec = importlib.util.spec_from_file_location("completion_rootfs_fs_test", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def rejected(function):
    try:
        function()
    except module.RootfsFsError:
        return
    raise AssertionError("hostile input accepted")


def control(seconds=30):
    return module.OperationControl(time.monotonic_ns() + seconds * 1_000_000_000, lambda: False)


def generation(inode=1, ctime=1):
    key = module.HostKey(1, 1, inode, "directory")
    return module.HostGeneration(key, 0o700, 0, 0, 2, 0, 1, ctime)


def snapshot(names, value=None):
    value = value or generation()
    checked = tuple(module._name(name) for name in sorted(names))
    return module.DirectoryNamesSnapshot(value, checked)


def manifest_bytes(revision, entries):
    value = {"version": module.SOURCE_MANIFEST_VERSION, "revision": revision, "entries": entries}
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


def counter_snapshot(value=0, **changes):
    return {key: changes.get(key, value) for key in module.ROOTFS_STRUCTURAL_COUNTER_KEYS}


def counter_provider_tests():
    saved_values = dict(module._STRUCTURAL_COUNTERS._values)
    saved_snapshot = module.structural_counter_snapshot
    saved_delta = module.structural_counter_delta
    phases = ("work", "cleanup")
    try:
        module._STRUCTURAL_COUNTERS._values = counter_snapshot()
        start, read = module._phase_structural_counter_provider(phases)
        ticket = start("work")
        for index, key in enumerate(module.ROOTFS_STRUCTURAL_COUNTER_KEYS, 1):
            module._structural_increment(key, index)
        assert read("work", ticket) == {
            "record_reference_copies": 1, "byte_names_returned": 2, "parent_snapshots": 3,
            "complete_legal_record_folds": 4, "complete_filesystem_walks": 5,
            "incrementally_advanced_ledger_records": 6,
        }
        for malformed in ((), ["work"], ("work", "work"), ("",), (True,), ("work", 1)):
            rejected(lambda malformed=malformed: module._phase_structural_counter_provider(malformed))
        for phase in ("unknown", 1, True, None):
            rejected(lambda phase=phase: start(phase))
        for hostile_ticket in (True, False, 0, -1, "1", None):
            rejected(lambda hostile_ticket=hostile_ticket: read("work", hostile_ticket))

        other_start, other_read = module._phase_structural_counter_provider(phases)
        own = start("work")
        other = other_start("work")
        rejected(lambda: read("work", other))
        rejected(lambda: other_read("work", own))
        read("work", own); other_read("work", other)
        replaced = start("cleanup")
        rejected(lambda: read("work", replaced))
        rejected(lambda: read("cleanup", replaced))
        malformed_phase = start("work")
        rejected(lambda: read(True, malformed_phase))
        rejected(lambda: read("work", malformed_phase))
        duplicate = start("work")
        read("work", duplicate)
        rejected(lambda: read("work", duplicate))
        rejected(lambda: read("work", 999999999))

        outer = start("work")
        module._structural_increment("active_history_record_copies", 2)
        inner = start("cleanup")
        module._structural_increment("active_history_record_copies", 3)
        assert read("cleanup", inner)["record_reference_copies"] == 3
        module._structural_increment("active_history_record_copies", 5)
        assert read("work", outer)["record_reference_copies"] == 10

        captured_start, captured_read = module._phase_structural_counter_provider(("captured",))
        module.structural_counter_snapshot = lambda: (_ for _ in ()).throw(AssertionError("replaced snapshot"))
        module.structural_counter_delta = lambda *_args: (_ for _ in ()).throw(AssertionError("replaced delta"))
        captured = captured_start("captured")
        assert captured_read("captured", captured) == {
            "record_reference_copies": 0, "byte_names_returned": 0, "parent_snapshots": 0,
            "complete_legal_record_folds": 0, "complete_filesystem_walks": 0,
            "incrementally_advanced_ledger_records": 0,
        }
        module.structural_counter_snapshot, module.structural_counter_delta = saved_snapshot, saved_delta

        def provider_from_snapshots(*snapshots):
            values = iter(snapshots)
            module.structural_counter_snapshot = lambda: next(values)
            provider = module._phase_structural_counter_provider(("fault",))
            module.structural_counter_snapshot = saved_snapshot
            return provider

        overflowing_start, _unused = provider_from_snapshots(counter_snapshot(value=(1 << 63)))
        rejected(lambda: overflowing_start("fault"))
        faults = (
            (counter_snapshot(), counter_snapshot(value=(1 << 63))),
            (counter_snapshot(value=1), counter_snapshot()),
            (counter_snapshot(), counter_snapshot(active_history_record_copies=1_000_000_001)),
            (counter_snapshot(), counter_snapshot(group_node_copies=(1 << 63))),
            (counter_snapshot(), {**counter_snapshot(), "group_lookup_steps": True}),
        )
        for before, after in faults:
            fault_start, fault_read = provider_from_snapshots(before, after)
            fault_ticket = fault_start("fault")
            rejected(lambda fault_read=fault_read, fault_ticket=fault_ticket: fault_read("fault", fault_ticket))
            rejected(lambda fault_read=fault_read, fault_ticket=fault_ticket: fault_read("fault", fault_ticket))

        internal = module.StructuralCounterProvider()
        internal._values["group_lookup_steps"] = (1 << 63) - 1
        rejected(lambda: internal.add("group_lookup_steps"))

        ceiling_start, ceiling_read = module._phase_structural_counter_provider(("ceiling",))
        issued = [ceiling_start("ceiling") for _index in range(32)]
        assert len(set(issued)) == 32 and all(type(ticket) is int and ticket > 0 for ticket in issued)
        ceiling_read("ceiling", issued[0])
        rejected(lambda: ceiling_start("ceiling"))
    finally:
        module.structural_counter_snapshot, module.structural_counter_delta = saved_snapshot, saved_delta
        module._STRUCTURAL_COUNTERS._values = saved_values


def pure_tests():
    counter_provider_tests()
    raw = b"pos:\t0\nflags:\t" + module.FDINFO_FLAGS + b"\nmnt_id:\t42\nino:\t9\n"
    nofollow_raw = raw.replace(module.FDINFO_FLAGS, module.FDINFO_NOFOLLOW_FLAGS)
    assert module.FDINFO_FLAGS == b"012100000"
    assert module.FDINFO_NOFOLLOW_FLAGS == b"012400000"
    assert module.ANONYMOUS_FDINFO_FLAGS == (b"022440002", b"022300002")
    assert module._parse_fdinfo(raw, 9) == module._parse_fdinfo(nofollow_raw, 9) == 42
    assert module._parse_fdinfo(raw, 9, module.FDINFO_FLAGS) == 42
    rejected(lambda: module._parse_fdinfo(nofollow_raw, 9, module.FDINFO_FLAGS))
    custom_flags = (b"022440002", b"022300002")
    custom_raw = raw.replace(module.FDINFO_FLAGS, custom_flags[0])
    alternate_custom_raw = raw.replace(module.FDINFO_FLAGS, custom_flags[1])
    assert module._parse_fdinfo(custom_raw, 9, custom_flags[0]) == 42
    assert module._parse_fdinfo(custom_raw, 9, custom_flags) == module._parse_fdinfo(alternate_custom_raw, 9, custom_flags) == 42
    rejected(lambda: module._parse_fdinfo(raw.replace(module.FDINFO_FLAGS, b"022500002"), 9, custom_flags))
    for invalid_expected in ((), (b"a", b"a"), (b"a", b"b", b"c"), [b"a"], (b"a", "b")):
        rejected(lambda invalid_expected=invalid_expected: module._parse_fdinfo(raw, 9, invalid_expected))
    hostile_fdinfo = (
        raw.replace(module.FDINFO_FLAGS, b"0"),
        raw.replace(module.FDINFO_FLAGS, b"012500000"),
        raw.replace(b"mnt_id:\t42", b"mnt_id:\t042"),
        raw.replace(b"mnt_id:\t42", b"mnt_id:\t0"),
        raw.replace(b"ino:\t9", b"ino:\t8"),
        raw.replace(b"flags:\t", b"unknown:\t"),
        raw.replace(b"ino:\t9\n", b"ino:\t9\nlock:\t1\n"),
        raw.replace(b"pos:\t0", b"pos:\t1"),
        raw[:-1],
        raw + b"\x00",
        b"x" * (module.MAX_FDINFO_BYTES + 1),
    )
    for value in hostile_fdinfo:
        rejected(lambda value=value: module._parse_fdinfo(value, 9))

    assert module._name("é").raw == "é".encode()
    for value in (b"\xff", "e\u0301", ".", "..", "a/b", "a\x00b", "line\n", "x" * 256):
        rejected(lambda value=value: module._name(value))
    assert unicodedata.normalize("NFC", module._name("é").text) == "é"

    before = snapshot((b"a",))
    after_generation = generation(1, 2)
    after = snapshot((b"a", b"b"), after_generation)
    module.ParentDelta("create", module._name(b"b"), before, after)
    module.ParentDelta("metadata", module._name(b"a"), before, snapshot((b"a",), after_generation))
    module.ParentDelta("unlink", module._name(b"a"), before, snapshot((), after_generation))
    for changed in (
        dataclasses.replace(after_generation, nlink=3),
        dataclasses.replace(after_generation, size=4096),
        dataclasses.replace(after_generation, mtime_ns=3),
        dataclasses.replace(after_generation, ctime_ns=3),
    ):
        module.ParentDelta("create", module._name(b"b"), before, snapshot((b"a", b"b"), changed))
    rejected(lambda: module.ParentDelta("unlink", module._name(b"b"), before, after))
    rejected(lambda: module.ParentDelta("create", module._name(b"b"), before, snapshot((b"a", b"b", b"c"))))
    for changed in (
        dataclasses.replace(after_generation, key=module.HostKey(1, 1, 2, "directory")),
        dataclasses.replace(after_generation, mode=0o755),
        dataclasses.replace(after_generation, uid=1),
        dataclasses.replace(after_generation, gid=1),
    ):
        rejected(lambda changed=changed: module.ParentDelta(
            "create", module._name(b"b"), before, snapshot((b"a", b"b"), changed),
        ))

    fake_fd = module.CheckedFd(100, "fake")
    fake_node = module.HeldNode(fake_fd, fake_fd, generation())
    real_listdir = module.os.listdir
    real_observe = module._observe_node
    real_child = module._observe_child
    try:
        names = [f"name-{index:04d}" for index in range(526)]
        listings = iter((list(reversed(names)), list(names), list(reversed(names))))
        calls = {"lists": 0, "observes": 0, "children": 0}

        def listdir(_fd):
            calls["lists"] += 1
            return next(listings)

        def observe(*_args):
            calls["observes"] += 1
            return generation()

        def child(*_args):
            calls["children"] += 1
            raise AssertionError("name-only snapshot opened an unaffected sibling")

        module.os.listdir = listdir
        module._observe_node = observe
        module._observe_child = child
        counters_before = module.structural_counter_snapshot()
        names_only = module._enumerate_names_stable(fake_node, control())
        counters_after = module.structural_counter_snapshot()
        assert names_only.raw_names == tuple(name.encode() for name in names)
        assert calls == {"lists": 3, "observes": 4, "children": 0}
        counter_delta = module.structural_counter_delta(counters_before, counters_after)
        assert counter_delta["parent_snapshots"] == 1
        assert counter_delta["listed_names"] == 3 * 526
        assert all(counter_delta[key] == 0 for key in module.ROOTFS_STRUCTURAL_COUNTER_KEYS if key not in {
            "listed_names", "parent_snapshots",
        })
        assert tuple(counters_after) == module.ROOTFS_STRUCTURAL_COUNTER_KEYS
        assert all(type(value) is int and value >= 0 for value in counters_after.values())
        rejected(lambda: module.structural_counter_delta(counters_after, counters_before))

        for values in (
            (["a"], ["a", "b"], ["a"]),
            (["a"], ["a"], ["a", "b"]),
            (["a"], ["b"], ["a"]),
        ):
            listings = iter(values)
            rejected(lambda: module._enumerate_names_stable(fake_node, control()))

        stable = generation()
        for seam in range(4):
            generations = [stable] * 4
            generations[seam] = dataclasses.replace(stable, ctime_ns=2)
            observed = iter(generations)
            listings = iter((["a"], ["a"], ["a"]))
            module._observe_node = lambda *_args, observed=observed: next(observed)
            rejected(lambda: module._enumerate_names_stable(fake_node, control()))
        for drifted in (
            dataclasses.replace(stable, key=module.HostKey(2, 2, 2, "directory")),
            dataclasses.replace(stable, mode=0o755), dataclasses.replace(stable, uid=1),
            dataclasses.replace(stable, gid=1), dataclasses.replace(stable, nlink=3),
            dataclasses.replace(stable, size=4096), dataclasses.replace(stable, mtime_ns=2),
            dataclasses.replace(stable, ctime_ns=2),
        ):
            observed = iter((stable, drifted, stable, stable))
            listings = iter((["a"], ["a"], ["a"]))
            module._observe_node = lambda *_args, observed=observed: next(observed)
            rejected(lambda: module._enumerate_names_stable(fake_node, control()))

        listings = iter((["duplicate", "duplicate"],) * 3)
        module._observe_node = lambda *_args: stable
        rejected(lambda: module._enumerate_names_stable(fake_node, control()))
        for hostile_name in (".", "..", "a/b", "e\u0301", "line\n", "\udcff", "x" * 256):
            listings = iter(([hostile_name], [hostile_name], [hostile_name]))
            module._observe_node = lambda *_args: stable
            rejected(lambda: module._enumerate_names_stable(fake_node, control()))

        class FailAt:
            def __init__(self, seam):
                self.seam = seam
                self.calls = 0

            def check(self):
                self.calls += 1
                if self.calls == self.seam:
                    raise module.RootfsFsError()

        def checked_observe(_identity, _operation, checked):
            checked.check()
            return stable

        module._observe_node = checked_observe
        for seam in range(1, 11):
            listings = iter((["a"], ["a"], ["a"]))
            rejected(lambda seam=seam: module._enumerate_names_stable(fake_node, FailAt(seam)))

        listings = iter((["b", "a"], ["a", "b"], ["b", "a"]))
        module._observe_node = lambda *_args: stable
        module._observe_child = lambda _parent, _name, _control: generation(2)
        assert module._enumerate_stable(fake_node, control()).raw_names == (b"a", b"b")
        listings = iter((["a"], ["a", "b"]))
        rejected(lambda: module._enumerate_stable(fake_node, control()))
    finally:
        module.os.listdir = real_listdir
        module._observe_node = real_observe
        module._observe_child = real_child
    module._zero_xattrs(lambda *_args: 0, 1, control())
    rejected(lambda: module._zero_xattrs(lambda *_args: 1, 1, control()))
    rejected(lambda: module._zero_xattrs(lambda *_args: -1, 1, control()))

    revision = "a" * 40
    rows = [
        {"path": ".cogs-stage2-source-v1", "kind": "file", "mode": 0o400, "size": len(module.SOURCE_SENTINEL), "sha256": hashlib.sha256(module.SOURCE_SENTINEL).hexdigest()},
        {"path": "deploy", "kind": "directory", "mode": 0o700, "size": 0, "sha256": None},
    ]
    encoded = manifest_bytes(revision, rows)
    approval = module.SourceApproval(revision, hashlib.sha256(encoded).hexdigest())
    parsed = module._parse_source_manifest(encoded, approval)
    assert parsed.revision == revision and len(parsed.entries) == 2
    mutations = (
        encoded.replace(b'"version"', b'"unknown"', 1),
        encoded.replace(b'"revision":"', b'"revision": "', 1),
        encoded.replace(b'"mode":256', b'"mode":true', 1),
        encoded.replace(b'"path":"deploy"', b'"path":".git"', 1),
        encoded.replace(b'"path":"deploy"', b'"path":"deploy/aws-feasibility/.state"', 1),
        encoded.replace(b'"sha256":null', b'"sha256":"' + b"0" * 64 + b'"', 1),
    )
    for value in mutations:
        hostile = module.SourceApproval(revision, hashlib.sha256(value).hexdigest())
        rejected(lambda value=value, hostile=hostile: module._parse_source_manifest(value, hostile))
    rejected(lambda: module._parse_source_manifest(encoded, module.SourceApproval(revision, "0" * 64)))

    cancelled = module.OperationControl(time.monotonic_ns() + 1_000_000_000, lambda: True)
    expired = module.OperationControl(1, lambda: False)
    rejected(cancelled.check)
    rejected(expired.check)
    rejected(lambda: module.OperationControl(time.monotonic_ns() + 1_000_000, lambda: 0).check())

    descriptor = os.open(os.devnull, os.O_RDONLY)
    owned = module.CheckedFd(descriptor, "test")
    calls = []
    real_close = module.os.close
    try:
        def interrupted(number):
            calls.append(number)
            raise InterruptedError()
        module.os.close = interrupted
        rejected(owned.close)
        assert calls == [descriptor] and owned.disposition == "uncertain"
    finally:
        module.os.close = real_close
        real_close(descriptor)
    rejected(owned.close)

    source = MODULE_PATH.read_text()
    tree = ast.parse(source)
    banned = {"mkdir", "makedirs", "unlink", "remove", "rmdir", "rename", "replace", "link", "symlink", "write", "pwrite", "fsync", "fdatasync", "flock", "chmod", "chown"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            assert not (node.func.value.id == "os" and node.func.attr in banned), node.func.attr
    anonymous_open = source.split("def _open_anonymous(", 1)[1].split("\ndef ", 1)[0]
    assert "flags = os.O_TMPFILE | os.O_RDWR | _O_CLOEXEC" in anonymous_open
    assert "flags == 0o22200002" in anonymous_open
    assert "os.open(b\".\", flags, mode, dir_fd=directory.operation_fd.number)" in anonymous_open
    assert source.count("O_TMPFILE") == 2 and source.count("O_RDWR") == 1
    assert "if __name__" not in source and "argparse" not in source and "subprocess" not in source
    assert "O_CREAT" not in source and "O_TRUNC" not in source and "O_WRONLY" not in source
    assert module.PRIVILEGED_MUTATOR_EXCLUSION.startswith("Concurrent EUID-0")


def write_source_fixture(source):
    (source / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache").mkdir(parents=True, mode=0o700)
    (source / ".cogs-stage2-source-v1").write_bytes(module.SOURCE_SENTINEL)
    (source / "module.py").write_bytes(b"value = 1\n")
    for path in (source, source / "deploy", source / "deploy/aws-feasibility", source / "deploy/aws-feasibility/.state", source / "deploy/aws-feasibility/.state/completion-v1", source / "deploy/aws-feasibility/.state/completion-v1/artifacts", source / "deploy/aws-feasibility/.state/completion-v1/artifacts/cache"):
        path.chmod(0o700)
    for path in (source / ".cogs-stage2-source-v1", source / "module.py"):
        path.chmod(0o400)
    entries = []
    for relative, kind, mode, content in (
        (".cogs-stage2-source-v1", "file", 0o400, module.SOURCE_SENTINEL),
        ("deploy", "directory", 0o700, None),
        ("deploy/aws-feasibility", "directory", 0o700, None),
        ("module.py", "file", 0o400, b"value = 1\n"),
    ):
        entries.append({"path": relative, "kind": kind, "mode": mode, "size": 0 if content is None else len(content), "sha256": None if content is None else hashlib.sha256(content).hexdigest()})
    revision = "b" * 40
    raw = manifest_bytes(revision, entries)
    manifest = source / ".cogs-stage2-source-manifest-v1.json"
    manifest.write_bytes(raw)
    manifest.chmod(0o400)
    return module.SourceApproval(revision, hashlib.sha256(raw).hexdigest())


def linux_tests():
    if sys.platform != "linux":
        return False
    if os.geteuid() != 0:
        rejected(lambda: module._open_workspace_anchor(control()))
        return False
    active = control()
    with tempfile.TemporaryDirectory(prefix="cogs-fs-linux-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        source = root / "source"
        source.mkdir(mode=0o700)
        approval = write_source_fixture(source)
        (root / "regular").write_bytes(b"content")
        (root / "regular").chmod(0o400)
        (root / "link").symlink_to("regular")

        anchor = module._open_root_node(active)
        components = []
        parent = anchor
        for part in Path(temporary).parts[1:]:
            node = module._open_path_node(parent, part, "directory", active)
            components.append(module.ChainComponent(module._name(part), node))
            parent = node
        chain = module.HeldChain(anchor, tuple(components))
        directory = chain.components[-1].node
        try:
            names_snapshot = module._enumerate_names_stable(directory, active)
            snapshot_value = module._enumerate_stable(directory, active)
            assert (names_snapshot.generation, names_snapshot.raw_names) == (
                snapshot_value.generation, snapshot_value.raw_names,
            )
            assert snapshot_value.raw_names == tuple(sorted(snapshot_value.raw_names))
            assert b"regular" in snapshot_value.raw_names and b"link" in snapshot_value.raw_names

            detached = Path(temporary + "-detached")
            os.rename(temporary, detached)
            Path(temporary).mkdir(mode=0o700)
            try:
                assert module._enumerate_names_stable(directory, active).raw_names == names_snapshot.raw_names
                rejected(lambda: module._revalidate_chain(chain, active))
            finally:
                Path(temporary).rmdir()
                os.rename(detached, temporary)
            module._revalidate_chain(chain, active)

            regular = module._open_path_node(directory, b"regular", "file", active)
            try:
                module._require_empty_fd_xattrs(regular, active)
            finally:
                module._close_node(regular)

            child = module._open_path_node(directory, b"link", "symlink", active)
            try:
                module._require_empty_symlink_xattrs(chain, directory, b"link", child, active)
            finally:
                module._close_node(child)

            source_node = module._open_path_node(directory, b"source", "directory", active)
            try:
                verified = module._verify_source_bundle(source_node, approval, active)
                assert verified.digest == approval.manifest_sha256
            finally:
                module._close_node(source_node)
        finally:
            module._close_chain(chain)
    return True


pure_tests()
linux_qualified = linux_tests()
qualification = "EUID-0 LINUX QUALIFIED" if linux_qualified else "EUID-0 Linux matrix SKIPPED"
print(f"completion rootfs filesystem tests passed; {qualification}")
