import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const policy = JSON.parse(readFileSync("config/stage2-retired-revisions-v1.json", "utf8")) as {
  revisions: Record<string, string>;
  runs: Record<string, string>;
  artifacts: Record<string, string>;
};
const tombstones = Object.keys({ ...policy.revisions, ...policy.runs, ...policy.artifacts }).sort();

test("every pre-checkout and second-job retirement mirror equals policy and refuses before effects", () => {
  const lanes: [string, number, string[]][] = [
    ["stage2-prebuilt-rootfs-producer", 2, ["EXACT_H"]],
    ["stage2-prebuilt-rootfs-diagnostic-producer", 2, ["EXACT_H"]],
    ["stage2-prebuilt-rootfs-publisher", 2, ["EXACT_H", "PRODUCER_RUN_ID", "PRODUCER_ARTIFACT_ID"]],
    ["stage2-prebuilt-rootfs-diagnostic-publisher", 2, ["EXACT_H", "PRODUCER_RUN_ID", "PRODUCER_ARTIFACT_ID"]],
    [
      "stage2-local-static-control-prebuilt-candidate",
      1,
      ["EXACT_IMPLEMENTATION_HEAD", "CONTROL_RUN_ID", "CONTROL_ARTIFACT_ID"],
    ],
    [
      "stage2-prebuilt-mixed-hg-preflight",
      1,
      ["EXACT_IMPLEMENTATION_HEAD", "EXACT_CONTROL_HEAD", "EXACT_QUALIFICATION_HEAD"],
    ],
    [
      "stage2-prebuilt-local-kata-qualification",
      3,
      ["EXACT_IMPLEMENTATION_HEAD", "EXACT_CONTROL_HEAD", "EXACT_QUALIFICATION_HEAD"],
    ],
    ["stage2-prebuilt-kvm-rehearsal", 1, ["EXACT_H", "PUBLISHER_RUN_ID", "PUBLISHER_ARTIFACT_ID"]],
    ["stage2-prebuilt-kvm-integration-diagnostic", 2, []],
  ];
  const equalMirror = (block: string) => {
    const values = block.match(/([0-9a-f]{40}(?:\|[0-9a-f]+)+)\) exit 2/u)?.[1]?.split("|");
    assert.deepEqual(values?.sort(), tombstones);
  };
  for (const [lane, count, required] of lanes) {
    const source = readFileSync(`.github/workflows/${lane}.yml`, "utf8");
    const blocks = [...source.matchAll(/ {10}# ADR0309 exact retirement mirror[^\n]*\n[\s\S]*? {10}done\n/gu)];
    assert.equal(blocks.length, count, lane);
    for (const match of blocks) {
      const block = match[0].replace(/^ {10}/gmu, "");
      equalMirror(block);
      assert.throws(() => equalMirror(block.replace(`${tombstones[0]}|`, "")), "omission must fail equality");
      const selectors = [...block.matchAll(/"\$([A-Z_]+)"/gu)].map((item) => item[1] as string);
      for (const name of ["GITHUB_SHA", "GITHUB_RUN_ID", ...required])
        assert.ok(selectors.includes(name), `${lane}:${name}`);
      const job = [...source.slice(0, match.index).matchAll(/^ {2}([a-z][a-z0-9_-]*):\n/gmu)].at(-1);
      assert.ok(job);
      const preceding = source.slice(job.index, match.index);
      assert.doesNotMatch(preceding, /gh api|git (?:fetch|init)|sudo|uses:|download|install /u);
      const env = Object.fromEntries(selectors.map((name) => [name, name.endsWith("_ID") ? "123" : "a".repeat(40)]));
      // Execute ONLY the extracted literal predicate, never an effect command.
      const program = `set -euo pipefail\n${block}\nprintf EFFECT`;
      for (const name of selectors) {
        for (const retired of tombstones) {
          const result = spawnSync("bash", ["-c", program], {
            encoding: "utf8",
            env: { ...env, [name]: retired },
            timeout: 2000,
          });
          assert.equal(result.status, 2, `${lane}:${name}:${retired}`);
          assert.equal(result.stdout, "", "retired selection reached effect sentinel");
        }
      }
      assert.equal(
        spawnSync("bash", ["-c", program], { encoding: "utf8", env }).stdout,
        "EFFECT",
        "not retired is only a veto result, never authorization",
      );
    }
  }
});

test("ADR0309 exact allocations preserve hard limits and reserve every bounded future closure", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import runpy,subprocess
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py')
b,highs,paths,new,forecasts=m['_remediation_budget']()
assert highs==dict(route=1500,revocation=3500,relay=1400,lifecycle=4100,completion=1900,integration=3600)
assert b['global_gross_line_high']==16000 and b['base_revision']=='242bbefeae5444118d9e97b46597130b509ca253'
assert m['FINAL_H_REVISION']=='8907eba3191d07573cd84573cb0b2adddff17bd6'
assert (m['HARD_LIMIT'],m['DEPLOY_CORRECTION_HIGH'],m['RETAINED_CORRECTION_HIGH'],m['WORKFLOW_CORRECTION_HIGH'],m['GLOBAL_CORRECTION_HIGH'],m['MUTABLE_OWNER_LINE_LIMIT'])==(95900,22300,13100,5500,40500,2000)
assert new==dict(route=1,revocation=5,relay=0,lifecycle=4,completion=5,integration=25)
assert sum(new.values())==40 and sum(x['total'] for x in forecasts.values())==2570000
for p in ('config/stage2-retired-revisions-v1.json','scripts/stage2-revision-retirement.py'):
 assert paths[p]=='integration' and p in m['RETAINED_FILES'] and m['_counted'](p)
for owner,names in {
 'lifecycle':['dev/launcher/deterministic-stream.ts','dev/launcher/fixtures.ts','dev/launcher/otlp-fixture.ts','test/dev-launcher-envoy-egress.test.ts','test/dev-launcher-deterministic-stream.test.ts','test/stage3-s309-exit-evidence.test.ts'],
 'revocation':['dev/launcher/openbao.ts','test/egress-openbao-pki.test.ts','test/dev-launcher-trusted-fixtures.test.ts'],
 'relay':['dev/linux-kvm/driver.sh','dev/linux-kvm/README.md','test/linux-kvm-git-tools.test.ts','test/stage3-real-runtime-report.test.ts'],
 'integration':['deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py','test/outcome-two-runtime-report-portable.py','test/outcome-two-trusted-launcher-portable.py','scripts/native-qualification/common.py','scripts/validate-schemas.ts','schemas/native-qualification-report-v1alpha1.json','test/native-qualification-common.test.ts']}.items():
 for p in names: assert paths[p]==owner,p
for owner,names in {
 'revocation':['config/openbao-local-build-v1.json','images/openbao-local/Dockerfile','images/openbao-local/dependencies.patch','scripts/openbao-local-artifact.py','test/openbao-local-artifact.test.ts'],
 'integration':['.github/workflows/build-openbao-local.yml','.github/workflows/release-openbao-local.yml','docs/security-evidence/openbao-local-artifact-candidate.md','docs/operations/openbao-local-artifact.md']}.items():
 for p in names: assert paths[p]==owner and not Path(p).exists(),p
baseline=set(subprocess.check_output(['git','ls-tree','-r','--name-only',b['base_revision']],text=True).splitlines())
assert len(set(paths)-baseline)==40
for number,name in ((310,'freeze-remediated-H-and-authorize-control'),(311,'establish-remediated-Q-and-authorize-qualification')):
 p=f'docs/adr/{number:04d}-{name}.md'; assert paths[p]=='integration' and not Path(p).exists()
assert len(m['FINAL_CONTROL_DATA_MEMBERS'])==13 and m['_final_control_data_state']()[0]=='absent'
assert not any('*' in p for p in paths)
r=runpy.run_path('scripts/stage2-revision-retirement.py')
head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
for retired in r['REVISIONS']:
 assert subprocess.run(['git','merge-base','--is-ancestor',retired,head]).returncode==0
r['select']((head,))  # A real repaired descendant remains eligible for separate review.
`,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

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
    ordinary_raw = ignored_raw = ""
    def accounting_git(args):
        if args[0] == "ls-tree": return "old.ts\x00"
        if "diff" in args: return diff_raw
        if "--ignored" in args: return ignored_raw
        if "--others" in args: return ordinary_raw
        raise AssertionError(args)
    budget._git = accounting_git
    gross, new_files, _, _ = budget._remediation_gross()
    assert gross == {"route": 0, "completion": 3}
    assert new_files == {"route": 0, "completion": 1}

    for diff_raw in ("1\t0\tunknown.ts\x00", "1\t0\told.ts.lookalike\x00", "-\t-\told.ts\x00"):
        expect_failure(budget._remediation_gross)
    diff_raw = ""; ignored_raw = "old.ts\x00"
    expect_failure(budget._remediation_gross)
    ignored_raw = ""

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
