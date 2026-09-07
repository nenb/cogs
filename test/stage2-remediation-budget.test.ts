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
assert highs==dict(route=1800,revocation=3000,relay=1900,lifecycle=7000,completion=2600,integration=3000)
assert b['global_gross_line_high']==18500 and b['base_revision']=='242bbefeae5444118d9e97b46597130b509ca253'
assert m['FINAL_H_REVISION']=='8907eba3191d07573cd84573cb0b2adddff17bd6'
assert (m['HARD_LIMIT'],m['DEPLOY_CORRECTION_HIGH'],m['RETAINED_CORRECTION_HIGH'],m['WORKFLOW_CORRECTION_HIGH'],m['GLOBAL_CORRECTION_HIGH'],m['MUTABLE_OWNER_LINE_LIMIT'])==(95900,22300,13100,5500,40500,2000)
assert new==dict(route=1,revocation=0,relay=0,lifecycle=4,completion=3,integration=31)
assert sum(new.values())==39 and sum(x['total'] for x in forecasts.values())==2570000
for p in ('config/stage2-retired-revisions-v1.json','scripts/stage2-revision-retirement.py'):
 assert paths[p]=='integration' and p in m['RETAINED_FILES'] and m['_counted'](p)
for owner,names in {
 'lifecycle':['dev/launcher/deterministic-stream.ts','dev/launcher/fixtures.ts','dev/launcher/otlp-fixture.ts','dev/launcher/trusted-controls.ts','test/dev-launcher-envoy-egress.test.ts','test/dev-launcher-deterministic-stream.test.ts','test/dev-launcher-operations.test.ts','test/stage3-s309-exit-evidence.test.ts'],
 'revocation':['dev/launcher/openbao.ts','src/auth/openbao-workload-identity.ts','test/egress-openbao-pki.test.ts','test/dev-launcher-trusted-fixtures.test.ts','test/openbao-workload-identity.test.ts'],
 'relay':['dev/linux-kvm/driver.sh','dev/linux-kvm/README.md','test/linux-kvm-git-tools.test.ts','test/stage3-real-runtime-report.test.ts'],
 'integration':['deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py','test/outcome-two-runtime-report-portable.py','test/outcome-two-trusted-launcher-portable.py','scripts/native-qualification/common.py','scripts/validate-schemas.ts','schemas/native-qualification-report-v1alpha1.json','test/native-qualification-common.test.ts','docs/test-reports/stage-3-s3-09-linux-kvm-exit.md']}.items():
 for p in names: assert paths[p]==owner,p
for retired_path in ('config/openbao-local-build-v1.json','images/openbao-local/Dockerfile','images/openbao-local/dependencies.patch','scripts/openbao-local-artifact.py','test/openbao-local-artifact.test.ts','docs/security-evidence/openbao-local-artifact-candidate.md','docs/operations/openbao-local-artifact.md'):
 assert retired_path not in paths and not Path(retired_path).exists(),retired_path
baseline=set(subprocess.check_output(['git','ls-tree','-r','--name-only',b['base_revision']],text=True).splitlines())
assert len(set(paths)-baseline)==39
for current in ('docs/adr/0310-authorize-openbao-recognition-correction.md','docs/adr/0311-reallocate-integrated-post-H-closure.md','docs/adr/0312-reallocate-final-observer-closure.md','docs/adr/0313-authorize-final-hostile-corrections-and-stage2-scope.md','docs/adr/0314-raise-final-hostile-integration-ceilings.md','docs/adr/0315-authorize-final-async-transport-ownership.md','docs/adr/0316-authorize-worker-transport-and-response-custody.md','docs/adr/0317-reallocate-worker-transport-integration.md','docs/adr/0318-authorize-s3-live-control-response-custody.md','docs/adr/0321-authorize-causal-npm-compatibility-correction.md'):
 assert paths[current]=='integration' and Path(current).is_file()
for number,name in ((319,'freeze-remediated-H-and-authorize-control'),(320,'establish-remediated-Q-and-authorize-qualification')):
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

test("historical H3/G3/Q3 variables fail current exact selectors, not the bounded retirement registry", () => {
  // ADR0309 snapshot only: no remote-variable audit or mutation. This deliberately
  // does not map all historical package/rootfs/producer selectors or old workflows.
  const historical = {
    IMPLEMENTATION: "229ea62bce964086726181974a6fec1c6dfd1f86",
    CONTROL: "821149ba4c3dbccef48694efcdb1eb29fa9fd2b9",
    QUALIFICATION: "06188f67a9a699924d645ce8aa0e91950b6341c7",
  };
  const source = readFileSync("scripts/stage2-prebuilt-mixed-hg-preflight.sh", "utf8");
  const h = source.match(/^H=([a-f0-9]{40})$/mu)?.[1];
  const g = source.match(/^G=([a-f0-9]{40})$/mu)?.[1];
  assert.ok(h && g);
  const env: Record<string, string> = {
    H: h,
    G: g,
    GITHUB_SHA: "a".repeat(40),
    EXACT_IMPLEMENTATION_HEAD: h,
    EXACT_CONTROL_HEAD: g,
    EXACT_QUALIFICATION_HEAD: "a".repeat(40),
  };
  const predicates = [
    ...source.matchAll(
      /^ {2}test "\$EXACT_(?:IMPLEMENTATION|CONTROL|QUALIFICATION)_HEAD" = "\$(?:H|G|GITHUB_SHA)" \|\| return$/gmu,
    ),
  ];
  assert.equal(predicates.length, 3);
  const program = `admit_exact() {\n${predicates.map((m) => m[0]).join("\n")}\n}\nadmit_exact && printf EFFECT`;
  assert.equal(spawnSync("bash", ["-c", program], { env, encoding: "utf8" }).stdout, "EFFECT");
  for (const [role, revision] of Object.entries(historical)) {
    assert.ok(!tombstones.includes(revision), "not a registry veto claim");
    assert.ok(
      readFileSync("docs/adr/0309-retire-post-review-H-and-authorize-bounded-corrections.md", "utf8").includes(
        revision,
      ),
    );
    const result = spawnSync("bash", ["-c", program], {
      env: { ...env, [`EXACT_${role}_HEAD`]: revision },
      encoding: "utf8",
      timeout: 2000,
    });
    assert.equal(result.status, 1, role);
    assert.equal(result.stdout, "", role);
  }
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import runpy
r=runpy.run_path('scripts/stage2-revision-retirement.py')
g=runpy.run_path('scripts/stage2-prebuilt-local-qualification-guard.py')
e=${JSON.stringify(Object.fromEntries(Object.entries(historical).map(([role, rev]) => [`EXACT_${role}_HEAD`, rev])))}
e['GITHUB_SHA']='a'*40
r['select'](tuple(e.values())) # The three-entry registry deliberately does not reject these.
try: g['guard'](e)
except g['GuardError'] as error: assert str(error)=='review constants remain blocked',str(error)
else: raise AssertionError('unfilled exact guard admitted historical selectors')
`,
    ],
    { encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("ADR0309 post-H gross reserves reject overruns even below the legacy correction highs", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py')
assert m['POST_H_REVISION']=='6bd12dcd25d877ffac03752fa0f71beeeb86a99e'
assert m['POST_H_HIGHS']=={'deploy':150,'retained':500,'workflow':350,'global':1000}
f=m['measure']; ns=f.__globals__; original=ns['_gross_slice']; observed=[]
def gross(paths,allowed,revision=m['CORRECTION_BASE_REVISION']):
 if revision!=m['POST_H_REVISION']: return original(paths,allowed,revision)
 assert revision!=m['FINAL_H_REVISION']
 key='deploy' if paths==(m['DEPLOY_ROOT'],) else 'workflow' if paths==(m['WORKFLOW_ROOT'],) else 'retained'
 observed.append(key)
 if key=='deploy':
  assert all(allowed(p) for p in (*m['CONTROL_DATA_MEMBERS'],*m['FINAL_CONTROL_DATA_MEMBERS']))
 if key=='retained':
  assert all(p in paths and allowed(p) for p in ('scripts/stage2-revision-retirement.py','config/stage2-retired-revisions-v1.json'))
 return values[key]
ns['_gross_slice']=gross
values=dict(deploy=150,retained=500,workflow=350)
report=f()
assert sorted(observed)==['deploy','retained','workflow']
assert report['post_h_gross_added_lines']==dict(values,**{'global':1000})
assert report['post_h_reserve_limits_satisfied'] is True
for key in values:
 values=dict(deploy=0,retained=0,workflow=0); values[key]=m['POST_H_HIGHS'][key]+1
 try: f()
 except m['LineBudgetError']: pass
 else: raise AssertionError(key+' reserve not enforced by central measure')
# Exercise combined enforcement independently of the (currently summing-to-1000) slices.
ns['POST_H_HIGHS']=dict(m['POST_H_HIGHS'],deploy=151)
values=dict(deploy=151,retained=500,workflow=350)
try: f()
except m['LineBudgetError']: pass
else: raise AssertionError('combined reserve not enforced')
# Gross diff never subtracts deletions, and must disable rename/copy/textconv credit.
ns['_gross_slice']=original
calls=[]
def git(args):
 calls.append(args)
 if 'diff' in args:
  assert '--no-renames' in args and '--no-textconv' in args and '--no-ext-diff' in args
  assert m['POST_H_REVISION'] in args
  return '151\\t9999\\tdeploy/aws-feasibility/old.py\\n'
 return ''
ns['_git']=git
assert original((m['DEPLOY_ROOT'],),lambda p: p.endswith('.py'),m['POST_H_REVISION'])==151
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
