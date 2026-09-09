import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const policy = JSON.parse(readFileSync("config/stage2-retired-revisions-v1.json", "utf8")) as {
  revisions: Record<string, string>;
  runs: Record<string, string>;
  artifacts: Record<string, string>;
};
const tombstones = Object.keys({ ...policy.revisions, ...policy.runs, ...policy.artifacts }).sort();
assert.equal(policy.revisions["0296252721fad0502dd4f41dacb1674e71b42bd6"], "ADR0323");
assert.equal(policy.revisions["9b9966afffe0ea8de4d0c99147886a95094470a9"], "ADR0319");
assert.equal(policy.revisions["97bc8eb8520a2116914c65a9ec5929e82c34ebf3"], "ADR0324");
assert.equal(policy.revisions["942e84cd8f977ee23a97dc47ce4a5d2d7510b346"], "ADR0324");
assert.equal(policy.runs["34192787285"], "ADR0324");
assert.equal(policy.artifacts["10042564354"], "ADR0324");
assert.equal(policy.revisions["6276eae08e29ee577f3d9b2c739ceadfe467a769"], "ADR0326");
assert.equal(policy.runs["34257525184"], "ADR0326");
assert.equal(policy.artifacts["10069446931"], "ADR0326");

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
    [
      "stage2-production-plan",
      1,
      ["IMPLEMENTATION_HEAD", "CONTROL_HEAD", "QUALIFICATION_HEAD", "QUALIFICATION_RUN_ID", "PACKAGE_ARTIFACT_ID"],
    ],
    ["stage2-production-approval", 1, ["COGS_STAGE2_CONTROL_REVISION", "PLAN_RUN_ID", "PLAN_ARTIFACT_ID"]],
    ["stage2-production-campaign", 1, ["CONTROL_HEAD", "APPROVAL_RUN_ID", "APPROVAL_ARTIFACT_ID"]],
  ];
  const equalMirror = (block: string) => {
    const values = block.match(/([0-9a-f]{40}(?:\|[0-9a-f]+)+)\) exit 2/u)?.[1]?.split("|");
    assert.deepEqual(values?.sort(), tombstones);
  };
  for (const [lane, count, required] of lanes) {
    const source = readFileSync(`.github/workflows/${lane}.yml`, "utf8");
    const blocks = [...source.matchAll(/ {10}# ADR0326 complete retirement mirror[^\n]*\n[\s\S]*? {10}done\n/gu)];
    assert.equal(blocks.length, count, lane);
    for (const match of blocks) {
      const block = match[0].replace(/^ {10}/gmu, "");
      equalMirror(block);
      assert.throws(() => equalMirror(block.replace(`${tombstones[0]}|`, "")), "omission must fail equality");
      const selectors = [...block.matchAll(/"\$([A-Z0-9_]+)"/gu)].map((item) => item[1] as string);
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

test("every next-chain first-created query paginates all refs without caller partitions", () => {
  for (const [file, workflowName] of [
    ["stage2-prebuilt-rootfs-producer.yml", "stage2-prebuilt-rootfs-producer.yml"],
    ["stage2-prebuilt-rootfs-publisher.yml", "stage2-prebuilt-rootfs-publisher.yml"],
    ["stage2-local-static-control-prebuilt-candidate.yml", "stage2-local-static-control-prebuilt-candidate.yml"],
    ["stage2-prebuilt-mixed-hg-preflight.yml", "stage2-prebuilt-mixed-hg-preflight.yml"],
    ["stage2-prebuilt-local-kata-qualification.yml", "stage2-prebuilt-local-kata-qualification.yml"],
  ]) {
    const source = readFileSync(`.github/workflows/${file}`, "utf8");
    const endpoint = `actions/workflows/${workflowName}/runs?event=workflow_dispatch&per_page=100`;
    const endpointAt = source.indexOf(endpoint);
    assert.ok(endpointAt > 0, file);
    const queryStart = source.lastIndexOf("gh api", endpointAt);
    const predicateEnd = source.indexOf("map(.id) == [$current]", endpointAt);
    assert.ok(queryStart >= 0 && predicateEnd > endpointAt, file);
    const admission = source.slice(queryStart, predicateEnd + 25);
    assert.match(admission, /gh api --paginate --slurp/u, file);
    assert.doesNotMatch(admission, /branch=|display_title|--arg title/u, file);
    assert.match(admission, /\.head_sha == \$(?:h|g|q)/u, file);
    assert.match(admission, /\.path == "\.github\/workflows\//u, file);
  }
});

test("every Stage2 workflow is guarded, hard-disabled, or the non-authorizing foundations check", () => {
  const guarded = new Set([
    "stage2-local-static-control-prebuilt-candidate",
    "stage2-prebuilt-kvm-integration-diagnostic",
    "stage2-prebuilt-kvm-rehearsal",
    "stage2-prebuilt-local-kata-qualification",
    "stage2-prebuilt-mixed-hg-preflight",
    "stage2-prebuilt-rootfs-diagnostic-producer",
    "stage2-prebuilt-rootfs-diagnostic-publisher",
    "stage2-prebuilt-rootfs-producer",
    "stage2-prebuilt-rootfs-publisher",
    "stage2-production-approval",
    "stage2-production-campaign",
    "stage2-production-plan",
  ]);
  const disabled = new Set([
    "stage2-local-kata-qualification",
    "stage2-local-static-admission-diagnostic",
    "stage2-local-static-control-candidate",
    "stage2-mixed-hg-preflight",
    "stage2-package-native-candidate",
    "stage2-phase-a-candidate",
    "stage2-rootfs-full-build-qualification",
  ]);
  const workflowFiles = readdirSync(".github/workflows").filter((name) => /\.ya?ml$/u.test(name));
  const selector =
    /reviewed_implementation_head|implementation_head:|EXACT_IMPLEMENTATION_HEAD|EXACT_H|CONTROL_HEAD|COGS_STAGE2_CONTROL_REVISION/u;
  for (const file of workflowFiles) {
    if (selector.test(readFileSync(`.github/workflows/${file}`, "utf8"))) assert.match(file, /^stage2-/u);
  }
  const names = workflowFiles
    .filter((name) => /^stage2-.*\.ya?ml$/u.test(name))
    .map((name) => name.replace(/\.ya?ml$/u, ""))
    .sort();
  assert.deepEqual(names, [...guarded, ...disabled, "stage2-workload-linux-foundations"].sort());
  for (const name of disabled) {
    const source = readFileSync(`.github/workflows/${name}.yml`, "utf8");
    const starts = [...source.matchAll(/^ {2}([a-z][a-z0-9_-]*):\n/gmu)].filter(
      (item) => (item.index ?? 0) > source.indexOf("\njobs:\n"),
    );
    assert.ok(starts.length > 0, name);
    for (let index = 0; index < starts.length; index += 1) {
      const start = starts[index];
      const next = starts[index + 1];
      assert.ok(start);
      assert.match(
        source.slice(start.index, next?.index),
        /^ {4}if:[\s\S]{0,160}github\.sha == ''/mu,
        `${name}:${start[1]}`,
      );
    }
  }
});

test("ADR0319 preserves original finding numbers and grants no chain or AWS authority", () => {
  const adr = readFileSync("docs/adr/0319-retire-frozen-H-and-authorize-bounded-review-corrections.md", "utf8");
  assert.match(adr, /1\. route-level[\s\S]*2\. model credentials[\s\S]*3\. the launch schema[\s\S]*4\. atomic SFTP/u);
  assert.match(adr, /Finding 2 remains open/u);
  assert.match(adr, /findings 1, 3, and 4 only/u);
  assert.match(adr, /grants no producer[\s\S]*AWS authority/u);
});

test("ADR0326 allocates retirement reconciliation and the complete fresh H-G-Q closure", () => {
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
assert highs==dict(route=2200,revocation=3000,relay=1975,lifecycle=7500,completion=3100,integration=4550)
assert b['global_gross_line_high']==21800 and b['base_revision']=='242bbefeae5444118d9e97b46597130b509ca253'
assert m['FINAL_H_REVISION']=='8907eba3191d07573cd84573cb0b2adddff17bd6'
assert (m['HARD_LIMIT'],m['DEPLOY_CORRECTION_HIGH'],m['RETAINED_CORRECTION_HIGH'],m['WORKFLOW_CORRECTION_HIGH'],m['GLOBAL_CORRECTION_HIGH'],m['MUTABLE_OWNER_LINE_LIMIT'])==(98000,22300,13100,5500,43000,2000)
assert new==dict(route=1,revocation=0,relay=0,lifecycle=4,completion=3,integration=37)
assert sum(new.values())==45 and sum(x['total'] for x in forecasts.values())==2570000
for p in ('config/stage2-retired-revisions-v1.json','scripts/stage2-revision-retirement.py'):
 assert paths[p]=='integration' and p in m['RETAINED_FILES'] and m['_counted'](p)
for owner,names in {
 'lifecycle':['dev/launcher/deterministic-stream.ts','dev/launcher/fixtures.ts','dev/launcher/otlp-fixture.ts','dev/launcher/trusted-controls.ts','test/dev-launcher-envoy-egress.test.ts','test/dev-launcher-deterministic-stream.test.ts','test/dev-launcher-operations.test.ts','test/stage3-s309-exit-evidence.test.ts'],
 'revocation':['dev/launcher/openbao.ts','src/auth/openbao-workload-identity.ts','test/egress-openbao-pki.test.ts','test/dev-launcher-trusted-fixtures.test.ts','test/openbao-workload-identity.test.ts'],
 'relay':['dev/linux-kvm/driver.sh','dev/linux-kvm/README.md','test/linux-kvm-git-tools.test.ts','test/stage3-real-runtime-report.test.ts'],
 'integration':['deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py','test/outcome-two-runtime-report-portable.py','test/outcome-two-trusted-launcher-portable.py','scripts/native-qualification/common.py','scripts/validate-schemas.ts','schemas/native-qualification-report-v1alpha1.json','test/native-qualification-common.test.ts','docs/test-reports/stage-3-s3-09-linux-kvm-exit.md','.github/workflows/stage2-production-plan.yml','.github/workflows/stage2-production-approval.yml','.github/workflows/stage2-production-campaign.yml','scripts/stage2-production-planner.py','scripts/stage2-production-approval.py','scripts/stage2-stage-production-approval.py','test/stage2-production-workflows.test.ts','test/stage2-production-planner.py','test/stage2-production-planner.test.ts','test/stage2-production-approval.py','test/stage2-production-approval.test.ts']}.items():
 for p in names: assert paths[p]==owner,p
for retired_path in ('config/openbao-local-build-v1.json','images/openbao-local/Dockerfile','images/openbao-local/dependencies.patch','scripts/openbao-local-artifact.py','test/openbao-local-artifact.test.ts','docs/security-evidence/openbao-local-artifact-candidate.md','docs/operations/openbao-local-artifact.md'):
 assert retired_path not in paths and not Path(retired_path).exists(),retired_path
baseline=set(subprocess.check_output(['git','ls-tree','-r','--name-only',b['base_revision']],text=True).splitlines())
assert len(set(paths)-baseline)==45
for current in ('docs/adr/0310-authorize-openbao-recognition-correction.md','docs/adr/0311-reallocate-integrated-post-H-closure.md','docs/adr/0312-reallocate-final-observer-closure.md','docs/adr/0313-authorize-final-hostile-corrections-and-stage2-scope.md','docs/adr/0314-raise-final-hostile-integration-ceilings.md','docs/adr/0315-authorize-final-async-transport-ownership.md','docs/adr/0316-authorize-worker-transport-and-response-custody.md','docs/adr/0317-reallocate-worker-transport-integration.md','docs/adr/0318-authorize-s3-live-control-response-custody.md','docs/adr/0319-retire-frozen-H-and-authorize-bounded-review-corrections.md','docs/adr/0320-freeze-corrected-H-and-authorize-control.md','docs/adr/0321-authorize-causal-npm-compatibility-correction.md','docs/adr/0322-establish-corrected-Q-and-authorize-qualification.md','docs/adr/0323-retire-timeout-H-and-authorize-turn-deadline-correction.md','docs/adr/0324-retire-failed-static-generation-and-correct-authority.md','docs/adr/0325-freeze-static-corrected-H-and-authorize-control.md','docs/adr/0326-reconcile-historical-stage2-retirement-policy.md'):
 assert paths[current]=='integration' and Path(current).is_file()
control=Path('docs/adr/0320-freeze-corrected-H-and-authorize-control.md').read_text()
assert '97bc8eb8520a2116914c65a9ec5929e82c34ebf3' in control
assert '34183885618' in control and '10040293103' in control
assert 'grants no AWS operation' in control
assert len(m['FINAL_CONTROL_DATA_MEMBERS'])==13 and m['_final_control_data_state']()[0]=='member-set-complete'
assert not any('*' in p for p in paths)
r=runpy.run_path('scripts/stage2-revision-retirement.py')
history_head=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
assert subprocess.run(['git','merge-base','--is-ancestor','6276eae08e29ee577f3d9b2c739ceadfe467a769',history_head]).returncode==0
r['select'](('f'*40,))  # A distinct replacement remains outside the exact-selection veto.
`,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("ADR0326 independently enumerates and rejects every reconciled generation identity", () => {
  const reconciled = {
    revisions: [
      "6276eae08e29ee577f3d9b2c739ceadfe467a769",
      "5601edf196a1bd4127afed6adf12ad8525fdb5b3",
      "9f6e79140e4df284588182c96b5044bb52f50ef9",
      "0e5b7012fabae3412ce8e3110bb181af1ffe608b",
      "f93748b253c1429cce9149defde623f40c9cc0ab",
      "d2fe08553d25d73fa276794c96b0f311e5406186",
      "a108f981dacad6978e2a37d16a143da5c3b51cf4",
      "728a77a87328e9cccd57547a930e84764964061f",
      "8e2af4398519ab8d64b7f9e7194f9c116c6f51d9",
      "229ea62bce964086726181974a6fec1c6dfd1f86",
      "821149ba4c3dbccef48694efcdb1eb29fa9fd2b9",
      "06188f67a9a699924d645ce8aa0e91950b6341c7",
      "8a1b56cfdaf013b27d8ef7a7e2753d3bb2582271",
      "69987e08cf9454fecf540a4de097f0877155b043",
    ],
    runs: [
      "34257525184",
      "33626103650",
      "33630868892",
      "33837299968",
      "33850962596",
      "33851159217",
      "33908498241",
      "33931002300",
      "33931091412",
      "33965298642",
      "33972129993",
      "33980034976",
      "33987181596",
      "33987659305",
      "33995592875",
      "33995910136",
      "34007531193",
      "34013328638",
      "34013774850",
    ],
    artifacts: [
      "10069446931",
      "9845676644",
      "9924034454",
      "9928325265",
      "9951239210",
      "9958532006",
      "9958574502",
      "9971564905",
      "9973726406",
      "9975524471",
      "9975667979",
      "9981717931",
      "9983143614",
      "9983282050",
    ],
  };
  assert.deepEqual(
    [Object.keys(policy.revisions).length, Object.keys(policy.runs).length, Object.keys(policy.artifacts).length],
    [21, 24, 17],
  );
  for (const [kind, values] of Object.entries(reconciled)) {
    for (const value of values) assert.equal(policy[kind as keyof typeof policy][value], "ADR0326", `${kind}:${value}`);
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
values=${JSON.stringify(reconciled)}
for value in values['revisions']:
 try: r['select']((value,))
 except r['RetirementError']: pass
 else: raise AssertionError(('revision',value))
for kind in ('runs','artifacts'):
 for value in values[kind]:
  kwargs={kind:(value,)}
  try: r['select'](('f'*40,),**kwargs)
  except r['RetirementError']: pass
  else: raise AssertionError((kind,value))
r['select'](('f'*40,))
`,
    ],
    { encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("ADR0323 post-H gross reserves reject overruns even below the legacy correction highs", () => {
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
assert m['POST_H_HIGHS']=={'deploy':150,'retained':2000,'workflow':600,'global':2500}
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
values=dict(deploy=100,retained=1800,workflow=500)
report=f()
assert sorted(observed)==['deploy','retained','workflow']
assert report['post_h_gross_added_lines']==dict(values,**{'global':2400})
assert report['post_h_reserve_limits_satisfied'] is True
for key in values:
 values=dict(deploy=0,retained=0,workflow=0); values[key]=m['POST_H_HIGHS'][key]+1
 try: f()
 except m['LineBudgetError']: pass
 else: raise AssertionError(key+' reserve not enforced by central measure')
# Exercise a binding combined limit while every individual slice remains within its own high.
values=dict(deploy=150,retained=2000,workflow=351)
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
