import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();

test("final control accounting requires an absent or safe canonical complete member set", () => {
  const program = String.raw`
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile

spec = importlib.util.spec_from_file_location("budget", sys.argv[1])
budget = importlib.util.module_from_spec(spec)
spec.loader.exec_module(budget)
root = Path(tempfile.mkdtemp(prefix="cogs-budget-v5-"))
budget.ROOT = root
budget.FINAL_CONTROL_DATA_ROOT = "v5"
budget.FINAL_CONTROL_DATA_MEMBERS = ("v5/a.json", "v5/b.json")
state = {"tracked": set(), "ordinary": set(), "ignored": set()}

def fake_git(args):
    if "--ignored" in args:
        values = state["ignored"]
    elif "--others" in args:
        values = state["ordinary"]
    else:
        values = state["tracked"]
    return "".join(f"{value}\n" for value in sorted(values))

budget._git = fake_git

def expect_failure(operation):
    try:
        operation()
    except budget.LineBudgetError:
        return
    raise AssertionError("expected fail-closed accounting")

def reset():
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(mode=0o700)
    state["tracked"].clear()
    state["ordinary"].clear()
    state["ignored"].clear()

def write_members():
    (root / "v5").mkdir(mode=0o700)
    for name in budget.FINAL_CONTROL_DATA_MEMBERS:
        (root / name).write_bytes(b"{}\n")

try:
    assert budget._final_control_data_state()[0] == "absent"

    reset(); write_members(); state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    assert budget._final_control_data_state()[0] == "member-set-complete"

    reset(); write_members(); state["tracked"].add("v5/a.json"); state["ordinary"].add("v5/b.json")
    assert budget._final_control_data_state()[0] == "member-set-complete"

    reset(); state["tracked"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v5/b.json").unlink(); state["tracked"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); state["ordinary"].add("v5/a.json")
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); state["ordinary"].update((*budget.FINAL_CONTROL_DATA_MEMBERS, "v5/extra.json"))
    expect_failure(budget._final_control_data_state)

    reset(); state["ignored"].add("v5/a.json")
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v5/b.json").write_bytes(b"\x00" * 100000)
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v5/b.json").write_bytes(b"not-json\n")
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v5/b.json").write_bytes(b'{"value":NaN}\n')
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v5/b.json").unlink(); os.link(root / "v5/a.json", root / "v5/b.json")
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); outside = root / "outside"; outside.mkdir(); (outside / "a.json").write_bytes(b"{}\n"); (outside / "b.json").write_bytes(b"{}\n")
    (root / "v5").symlink_to(outside, target_is_directory=True)
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); binary = root / "binary.ts"; binary.write_bytes(b"\x00" * 100000)
    expect_failure(lambda: budget._lines(binary))

    allocations = {"old.ts": "route", "new.ts": "completion"}
    highs = {"route": 10, "completion": 10}
    new_highs = {"route": 1, "completion": 1}
    forecasts = {owner: {"total": 1} for owner in highs}
    budget_data = {"global_gross_line_high": 20}
    budget._remediation_budget = lambda: (budget_data, highs, allocations, new_highs, forecasts)
    diff_raw = "0\t3\told.ts\x003\t0\tnew.ts\x00"
    ordinary_raw = ""
    def accounting_git(args):
        if args[0] == "ls-tree": return "old.ts\x00"
        if "diff" in args: return diff_raw
        if "--ignored" in args: return ""
        if "--others" in args: return ordinary_raw
        raise AssertionError(args)
    budget._git = accounting_git
    gross, new_files, _, _ = budget._remediation_gross()
    assert gross == {"route": 0, "completion": 3}
    assert new_files == {"route": 0, "completion": 1}

    diff_raw = "1\t0\tunknown.ts\x00"
    expect_failure(budget._remediation_gross)

    reset(); allocations = {"new.ts": "route"}; highs = {"route": 10}; new_highs = {"route": 1}
    forecasts = {"route": {"total": 1}}; diff_raw = ""; ordinary_raw = "new.ts\x00"
    (root / "new.ts").write_bytes(b"\x00" * 100000)
    expect_failure(budget._remediation_gross)

    reset(); allocations = {"a.ts": "route", "b.ts": "route"}; highs = {"route": 10}; new_highs = {"route": 1}
    forecasts = {"route": {"total": 1}}; ordinary_raw = ""; diff_raw = "1\t0\ta.ts\x001\t0\tb.ts\x00"
    expect_failure(budget._remediation_gross)
finally:
    shutil.rmtree(root, ignore_errors=True)
print("ok")
`;
  const result = spawnSync("python3", ["-B", "-c", program, join(root, "scripts/check-stage2-retained-lines.py")], {
    cwd: root,
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "ok\n");
});
