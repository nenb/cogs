#!/usr/bin/env python3
"""Portable fixed-launcher source, handoff, and cleanup qualification."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

if sys.flags.optimize:
    raise RuntimeError("Outcome 2 launcher tests refuse optimized Python")
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py"
FIXTURES = ROOT / "test/fixtures/outcome-two/launcher/cases.json"
GOLDEN = ROOT / "test/fixtures/outcome-two/reports/runtime-closure-v1.canonical.json"


def load_module():
    spec = importlib.util.spec_from_file_location("completion_trusted_runtime_launcher", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def values(module):
    payload = b"cogs-runtime-qualification-v1\n"
    return {
        "baseline": object(),
        "authenticate_tracked_source": "a" * 40,
        "inspect_descriptor:gzip": None,
        "inspect_descriptor:zstd": None,
        "inspect_descriptor:report": None,
        "read_report": GOLDEN.read_bytes(),
        "run_tool:gzip": module._ToolOutcome(payload, True),
        "run_tool:zstd": module._ToolOutcome(payload, True),
        "close_descriptor": None,
        "prove_restored": None,
    }


def success_script(module):
    names = json.loads(FIXTURES.read_text())["success_steps"]
    available = values(module)
    return tuple((name, available[name]) for name in names)


def fault_script(module, selected):
    order = json.loads(FIXTURES.read_text())["fault_steps"]
    base = values(module)
    logical = selected.split(":", 1)[0] if selected.startswith("close_descriptor:") else selected
    script = []
    baseline_ok = logical != "baseline"
    for name in order:
        name_logical = name.split(":", 1)[0] if name.startswith("close_descriptor:") else name
        if name_logical == logical and (name == selected or name == logical):
            script.append((name_logical, OSError("fixed scripted cut")))
            break
        script.append((name_logical, base[name_logical]))
    completed = [name for name, _value in script]
    close_count = completed.count("close_descriptor")
    script.extend(("close_descriptor", None) for _ in range(3 - close_count))
    if baseline_ok and "prove_restored" not in completed:
        script.append(("prove_restored", None))
    return tuple(script)


def child(case):
    module = load_module()
    handoff = SimpleNamespace(gzip_executable_fd=31, zstd_executable_fd=32, report_fd=33)
    if case == "success":
        adapter = module._ScriptedLauncherAdapter(success_script(module))
        result = module._launch_fixed_runtime_qualification_with_adapter(handoff, adapter)
        assert result.marker == "cogs-runtime-qualification-v1"
        assert result.children_reaped and result.descriptors_restored and result.report_read_only
    elif case.startswith("fault:"):
        selected = case.removeprefix("fault:")
        adapter = module._ScriptedLauncherAdapter(fault_script(module, selected))
        try:
            module._launch_fixed_runtime_qualification_with_adapter(handoff, adapter)
        except BaseException:
            pass
        else:
            raise AssertionError(f"launcher accepted cut {selected}")
        assert adapter._script == []
    elif case == "sandbox-success":
        outcome = module.SandboxQualificationResult(
            module._VERSION, module._MARKER, True, True, True, True, True, True, True,
        )
        adapter = module._ScriptedLauncherAdapter((
            ("baseline", object()), ("run_sandbox", outcome), ("prove_restored", None),
        ))
        assert module._launch_fixed_sandbox_probe_with_adapter(adapter) == outcome
    elif case == "sandbox-primary-cleanup":
        adapter = module._ScriptedLauncherAdapter((
            ("baseline", object()), ("run_sandbox", ValueError("primary")),
            ("prove_restored", OSError("cleanup")),
        ))
        try:
            module._launch_fixed_sandbox_probe_with_adapter(adapter)
        except module.RuntimeLauncherError as error:
            assert "cleanup uncertain" in str(error)
        else:
            raise AssertionError("sandbox cleanup uncertainty accepted")
    else:
        raise AssertionError(f"unknown child case {case}")
    print(json.dumps({"case": case, "events": adapter.events}, sort_keys=True, separators=(",", ":")))


def fresh(case):
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child", case],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"},
        timeout=5, check=False,
    )
    assert result.returncode == 0, (case, result.stdout, result.stderr)
    return json.loads(result.stdout)


def parent():
    cases = json.loads(FIXTURES.read_text())
    assert cases["fixed_fd_map"] == [["gzip", 198], ["zstd", 199], ["report", 200]]
    success = fresh("success")
    assert success["events"] == cases["success_steps"]
    assert success["events"].index("authenticate_tracked_source") < success["events"].index("inspect_descriptor:gzip")
    assert success["events"].count("authenticate_tracked_source") == 1
    for step in cases["fault_steps"]:
        observed = fresh(f"fault:{step}")
        assert observed["events"][-1] in {"close_descriptor", "prove_restored"}
    fresh("sandbox-success")
    fresh("sandbox-primary-cleanup")
    module = load_module()
    assert tuple(module._FIXED_FD_MAP) == (("gzip", 198), ("zstd", 199), ("report", 200))
    source = MODULE.read_text()
    public = source[source.index("def launch_fixed_runtime_qualification"):]
    assert "PATH" not in public and "listdir" not in public and "resolve(" not in public
    print("Outcome 2 trusted launcher portable tests passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        child(sys.argv[2])
    elif len(sys.argv) == 1:
        parent()
    else:
        raise SystemExit(2)
