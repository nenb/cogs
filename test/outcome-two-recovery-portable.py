#!/usr/bin/env python3
"""Portable owner state, crash-cut, publication, handoff, and recovery tests."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from unittest.mock import patch

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 recovery tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REMOTE = ROOT / "deploy/aws-feasibility/remote"
MODULE = REMOTE / "completion_trusted_runtime_closure.py"
CASES = ROOT / "test/fixtures/outcome-two/recovery/cases.json"
sys.path.insert(0, str(REMOTE))


def load_module():
    spec = importlib.util.spec_from_file_location("completion_trusted_runtime_closure", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_ops(module, cut=None, crash=False):
    class Ops(module._Ops):
        def __init__(self):
            self.cut = cut
            self.crash = crash
            self.cut_fired = False
            self.events = []
            self.live = set()
            self.close_fault = False
            self.close_fault_fired = False
            self.corrupt_report = False

        def checkpoint(self, name):
            self.events.append(name)
            if name == self.cut and not self.cut_fired:
                self.cut_fired = True
                if self.crash:
                    os._exit(73)
                raise RuntimeError(f"scripted cut: {name}")

        def list_fds(self):
            return frozenset({0, 1, 2} | self.live)

        def child_baseline(self):
            return b""

        def close(self, fd):
            if fd not in self.live:
                raise OSError("double or foreign close")
            self.live.remove(fd)
            if self.close_fault and not self.close_fault_fired:
                self.close_fault_fired = True
                raise OSError("scripted uncertain close")

        def fcntl(self, fd, command, argument=0):
            del command, argument
            if fd in (300, 301): return module._EXEC_SEALS
            if fd == 302: return module._DATA_SEALS
            raise OSError("foreign descriptor")

        def pread(self, fd, size, offset):
            if fd != 302 or current[0] is None:
                raise OSError("foreign descriptor")
            return current[0].canonical_report[offset:offset + size]

        def report_candidate(self, data):
            if self.corrupt_report:
                return data.replace(b"{", b'{"version":"duplicate",', 1)
            return data

    return Ops()


def object_(module, role, fd, tool):
    generation = module.SourceGeneration(8, fd, 10 + fd, 1, 1, stat.S_IFREG | 0o755, 0, 0)
    soname = f"ld-{tool}.so.1" if role == "loader" else None
    elf = module.ElfMetadata(module._INTERPRETER if role == "executable" else None, soname, ())
    return module.AuthenticatedObject(role, f"/fixed/{tool}/{role}", fd, generation,
                                      generation.size, f"{fd:064x}"[-64:], elf)


def harness(module, ops):
    next_source = iter(range(100, 106))
    next_output = iter((300, 301))

    def resolve(_ops, tool, _path):
        executable = object_(module, "executable", next(next_source), tool)
        loader = object_(module, "loader", next(next_source), tool)
        ops.live.update((executable.held_fd, loader.held_fd))
        return module.ResolvedToolClosure(tool, executable, loader, ())

    def spawn(_ops, closure):
        child = module._Child(40, 41, 42, 40, 40, closure.executable.identity)
        return child, 43

    def stop(_ops, child, gate):
        assert gate == 43
        child.reaped = True

    def mapped(_ops, child, closure):
        assert not child.reaped
        values = tuple((item.role, item.sha256) for item in closure.objects)
        digest = hashlib.sha256(module._canonical([list(item) for item in values])).hexdigest()
        return module.MappedToolClosure(closure.tool, values, digest)

    def seal(_ops, source, tool):
        fd = next(next_output)
        ops.live.add(fd)
        return module.SealedExecutable(tool, fd, source.generation, source.size,
                                       source.sha256, module._EXEC_SEALS)

    def seal_report(_ops, raw):
        assert module._validate_report_bytes(raw) == raw
        ops.live.add(302)
        return 302

    return (
        patch.object(module, "_resolve_tool", side_effect=resolve),
        patch.object(module, "_spawn_helper", side_effect=spawn),
        patch.object(module, "_mapped_closure", side_effect=mapped),
        patch.object(module, "_stop_helper", side_effect=stop),
        patch.object(module, "_seal_source", side_effect=seal),
        patch.object(module, "_seal_report", side_effect=seal_report),
    )


current = [None]


def prepared(module, ops):
    contexts = harness(module, ops)
    for context in contexts: context.start()
    try:
        owner = module._prepare_with_adapter_for_tests(ops)
        current[0] = owner
        return owner
    finally:
        for context in reversed(contexts): context.stop()


def child(case):
    module = load_module()
    cut = case.split(":", 1)[1] if ":" in case else None
    ops = make_ops(module, cut, case.startswith("crash:"))
    if case == "success":
        owner = prepared(module, ops)
        report = owner.canonical_report
        handoff = owner.settle_fixed_handoff()
        try: owner.settle_fixed_handoff()
        except module.RuntimeClosureError: pass
        else: raise AssertionError("second handoff accepted")
        owner.close(); owner.close()
        assert owner._state is module._State.CLOSED
        assert set((handoff.gzip_executable_fd, handoff.zstd_executable_fd, handoff.report_fd)) == ops.live
        for fd in tuple(ops.live): ops.close(fd)
        assert module._validate_report_bytes(report) == report
    elif case.startswith("fault:"):
        if cut.startswith("handoff.") or cut.startswith("cleanup."):
            ops.cut = None
            owner = prepared(module, ops)
            ops.cut = cut
            action = owner.settle_fixed_handoff if cut.startswith("handoff.") else owner.close
            try: action()
            except RuntimeError: pass
            else: raise AssertionError(f"fault cut accepted: {cut}")
            owner.close()
            assert owner._state is module._State.CLOSED and ops.live == set()
        else:
            try: prepared(module, ops)
            except BaseException: pass
            else: raise AssertionError(f"preparation cut accepted: {cut}")
            assert ops.live == set()
    elif case.startswith("crash:"):
        if cut.startswith("handoff.") or cut.startswith("cleanup."):
            ops.cut = None
            owner = prepared(module, ops)
            ops.cut = cut
            (owner.settle_fixed_handoff if cut.startswith("handoff.") else owner.close)()
        else:
            prepared(module, ops)
        raise AssertionError("crash cut did not terminate")
    elif case == "poison-repeat":
        owner = prepared(module, ops); ops.close_fault = True
        first = second = None
        try: owner.close()
        except module.RuntimeClosureCleanupError as error: first = error
        else: raise AssertionError("uncertain close accepted")
        try: owner.close()
        except module.RuntimeClosureCleanupError as error: second = error
        else: raise AssertionError("poisoned repeat became success")
        assert first is second and owner._state is module._State.POISONED and ops.live == set()
    elif case == "publication-corrupt":
        ops.corrupt_report = True
        try: prepared(module, ops)
        except module.RuntimeClosureCleanupError: pass
        else: raise AssertionError("corrupt publication accepted")
        assert ops.live == set()
    else:
        raise AssertionError(case)
    print(json.dumps({"case": case, "events": ops.events}, sort_keys=True, separators=(",", ":")))


def fresh(case, crash=False):
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child", case],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}, timeout=5, check=False,
    )
    if crash:
        assert result.returncode == 73 and result.stdout == b"", (case, result.returncode, result.stderr)
        return None
    assert result.returncode == 0, (case, result.stdout, result.stderr)
    return json.loads(result.stdout)


def parent():
    fixture = json.loads(CASES.read_text())
    cuts = fixture["state_cuts"] + fixture["preparation_cuts"] + fixture["publication_cuts"] + fixture["handoff_cuts"]
    success = fresh("success")
    assert set(cuts).issubset(success["events"])
    for cut in cuts:
        fresh(f"fault:{cut}")
        fresh(f"crash:{cut}", crash=True)
        fresh("success")  # fresh recovery has no inherited process/module state
    fresh("publication-corrupt")
    fresh("poison-repeat")
    module = load_module()
    assert tuple(state.value for state in module._State) == (
        "NEW", "PREPARING", "READY", "HANDED_OFF", "CLOSED", "POISONED",
    )
    assert len(cuts) == len(set(cuts))
    print("Outcome 2 recovery portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child": child(sys.argv[2])
    elif len(sys.argv) == 1: parent()
    else: raise SystemExit(2)
