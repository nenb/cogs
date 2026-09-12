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
const runnerRolloverGeneration = {
  revisions: [
    "c30e0d69ec374cd812ff361e670e974d51b661c4", // H
    "15d99b55f4910df94decdd7edcc80bf95aee492d", // G
    "d0e29eb359f0c1678c18f676e312276eff3aa3f8", // Q
  ],
  runs: ["34375934829", "34402409489", "34403562378", "34411847798"],
  artifacts: ["10114901253", "10123988189", "10124443866"],
};
const failedGeneration = {
  revisions: [
    "c10fc103532f3e3a8b746727bd0f48c6d8498148", // H
    "eb59cae18e0f041a243f35f253d46713f7e87142", // G
    "b11adc47c454bde0dc0e2930012e418b90917555", // Q
  ],
  runs: ["34282898803", "34292774279", "34293986674", "34301325559", "34302034014"],
  artifacts: ["10079099187", "10081986019", "10082440691"],
};
assert.deepEqual(
  [Object.keys(policy.revisions).length, Object.keys(policy.runs).length, Object.keys(policy.artifacts).length],
  [27, 33, 23],
);
for (const [kind, values] of Object.entries(runnerRolloverGeneration)) {
  const group = policy[kind as keyof typeof policy];
  assert.deepEqual(
    Object.keys(group)
      .filter((value) => group[value] === "ADR0330")
      .sort(),
    [...values].sort(),
  );
}
for (const [kind, values] of Object.entries(failedGeneration)) {
  const group = policy[kind as keyof typeof policy];
  assert.deepEqual(
    Object.keys(group)
      .filter((value) => group[value] === "ADR0327")
      .sort(),
    [...values].sort(),
  );
}

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
  assert.equal(
    lanes.reduce((total, [, count]) => total + count, 0),
    19,
  );
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
      if (lane === "stage2-prebuilt-local-kata-qualification" && job[1] === "admission")
        assert.ok(selectors.includes("MIXED_PREFLIGHT_RUN_ID"));
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

test("every next-chain first-created query server-filters its head and proves complete singleton history", () => {
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
    assert.match(admission, /&head_sha=\$(?:EXACT_H|GITHUB_SHA|EXACT_QUALIFICATION_HEAD)/u, file);
    assert.match(admission, /\(\[\.\[\]\.total_count\] \| unique\) == \[1\]/u, file);
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

test("ADR0335 allocates measured correction while preserving historical chain accounting", () => {
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
assert highs==dict(route=2200,revocation=3000,relay=4650,lifecycle=11800,completion=6080,integration=18182)
assert b['global_gross_line_high']==45200 and b['base_revision']=='242bbefeae5444118d9e97b46597130b509ca253'
assert m['FINAL_H_REVISION']=='8907eba3191d07573cd84573cb0b2adddff17bd6'
assert (m['HARD_LIMIT'],m['DEPLOY_CORRECTION_HIGH'],m['RETAINED_CORRECTION_HIGH'],m['WORKFLOW_CORRECTION_HIGH'],m['GLOBAL_CORRECTION_HIGH'],m['MUTABLE_OWNER_LINE_LIMIT'])==(115000,24500,31000,6000,60000,2000)
assert new==dict(route=1,revocation=0,relay=1,lifecycle=5,completion=3,integration=87)
assert sum(new.values())==97 and sum(x['total'] for x in forecasts.values())==8470000
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
assert len(set(paths)-baseline)==97
for current in ('docs/adr/0310-authorize-openbao-recognition-correction.md','docs/adr/0311-reallocate-integrated-post-H-closure.md','docs/adr/0312-reallocate-final-observer-closure.md','docs/adr/0313-authorize-final-hostile-corrections-and-stage2-scope.md','docs/adr/0314-raise-final-hostile-integration-ceilings.md','docs/adr/0315-authorize-final-async-transport-ownership.md','docs/adr/0316-authorize-worker-transport-and-response-custody.md','docs/adr/0317-reallocate-worker-transport-integration.md','docs/adr/0318-authorize-s3-live-control-response-custody.md','docs/adr/0319-retire-frozen-H-and-authorize-bounded-review-corrections.md','docs/adr/0320-freeze-corrected-H-and-authorize-control.md','docs/adr/0321-authorize-causal-npm-compatibility-correction.md','docs/adr/0322-establish-corrected-Q-and-authorize-qualification.md','docs/adr/0323-retire-timeout-H-and-authorize-turn-deadline-correction.md','docs/adr/0324-retire-failed-static-generation-and-correct-authority.md','docs/adr/0325-freeze-static-corrected-H-and-authorize-control.md','docs/adr/0326-reconcile-historical-stage2-retirement-policy.md','docs/adr/0327-retire-failed-formal-generation-and-separate-runtime-contracts.md','docs/adr/0328-freeze-runtime-corrected-H-and-authorize-control.md','docs/adr/0329-establish-runtime-corrected-Q-and-authorize-qualification.md','docs/adr/0330-retire-runner-rollover-generation-and-correct-admission.md','docs/adr/0331-freeze-image-bound-H-and-authorize-control.md','docs/adr/0332-establish-image-bound-Q-and-authorize-qualification.md'):
 assert paths[current]=='integration' and Path(current).is_file()
image_qualification=Path('docs/adr/0332-establish-image-bound-Q-and-authorize-qualification.md').read_text()
assert '34486733842' in image_qualification and '10155984475' in image_qualification
assert 'stop immediately on such a failure' in image_qualification and 'stop immediately before AWS' in image_qualification
image_control=Path('docs/adr/0331-freeze-image-bound-H-and-authorize-control.md').read_text()
assert '11c03441468d4c3130667321018e1cb6f626a303' in image_control
assert '34452651886' in image_control and '10143009714' in image_control
assert 'grants no AWS operation' in image_control
qualification=Path('docs/adr/0329-establish-runtime-corrected-Q-and-authorize-qualification.md').read_text()
assert '34403562378' in qualification and '10124443866' in qualification
assert 'stop immediately before AWS' in qualification
runtime_control=Path('docs/adr/0328-freeze-runtime-corrected-H-and-authorize-control.md').read_text()
assert 'c30e0d69ec374cd812ff361e670e974d51b661c4' in runtime_control
assert '34375934829' in runtime_control and '10114901253' in runtime_control
assert 'grants no AWS operation' in runtime_control
control=Path('docs/adr/0320-freeze-corrected-H-and-authorize-control.md').read_text()
assert '97bc8eb8520a2116914c65a9ec5929e82c34ebf3' in control
assert '34183885618' in control and '10040293103' in control
assert 'grants no AWS operation' in control
assert b['source_limits']==dict(tracked_files=1517,source_inventory_bytes=26000000,serialized_source_inventory_bytes=262144)
# The authorized integration tranche synchronizes implementation, not serialized or per-file bounds.
source_inventory=Path('scripts/stage4-offline-source-inventory.ts').read_text()
for constant in ('MAXIMUM_TRACKED_FILES = 1517;', 'MAXIMUM_AGGREGATE_BYTES = 26_000_000;',
                 'MAXIMUM_FILE_BYTES = 4 * 1024 * 1024;', 'MAXIMUM_GIT_OUTPUT_BYTES = 4 * 1024 * 1024;'):
 assert constant in source_inventory,constant
assert m['FINAL_CONTROL_DATA_ROOT'].endswith('-v7') and len(m['FINAL_CONTROL_DATA_MEMBERS'])==13
assert m['_final_control_data_state']()[0] in ('absent','member-set-complete')
assert 'deploy/aws-feasibility/remote/stage2-completion-local-control-v7/**/*.json' in Path('biome.json').read_text()
assert sum('/stage2-completion-local-control-v5/' in p for p in m['CONTROL_DATA_MEMBERS'])==13
assert sum('/stage2-completion-local-control-v6/' in p for p in m['CONTROL_DATA_MEMBERS'])==13
for p in (*m['FINAL_CONTROL_DATA_MEMBERS'],*m['ADR0327_RETAINED_FILES'],
 'docs/adr/0327-retire-failed-formal-generation-and-separate-runtime-contracts.md',
 'docs/adr/0328-freeze-runtime-corrected-H-and-authorize-control.md',
 'docs/adr/0329-establish-runtime-corrected-Q-and-authorize-qualification.md',
 'docs/adr/0330-retire-runner-rollover-generation-and-correct-admission.md',
 'docs/adr/0331-freeze-image-bound-H-and-authorize-control.md',
 'docs/adr/0332-establish-image-bound-Q-and-authorize-qualification.md',
 'scripts/stage2-hosted-opt-mode.py',
 'test/aws-stage2-completion-evidence-v3.test.ts',
 'test/fixtures/stage2-completion/approval-v5-test-only.json',
 'test/fixtures/stage2-completion/production-v3-test-only.json',
 'test/fixtures/stage2-completion/production-v3-test-only.md'):
 assert paths[p]=='integration',p
for p in (*m['ADR0327_RETAINED_FILES'],*m['ADR0330_RETAINED_FILES']):
 assert p in m['RETAINED_FILES'] and m['_counted'](p) and Path(p).is_file(),p
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
    [27, 33, 23],
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

test("ADR0327 independently rejects every failed formal-generation identity and policy drift", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import copy,json,runpy,tempfile
from pathlib import Path
r=runpy.run_path('scripts/stage2-revision-retirement.py')
p=r['load_policy']()
assert p==dict(version='cogs.stage2-retired-revisions/v1',revisions=r['REVISIONS'],runs=r['RUNS'],artifacts=r['ARTIFACTS'])
values=${JSON.stringify(failedGeneration)}
def veto(call):
 try: call()
 except r['RetirementError']: pass
 else: raise AssertionError('retirement veto missing')
with tempfile.TemporaryDirectory() as directory:
 path=Path(directory)/'policy.json'
 for kind,identities in values.items():
  for value in identities:
   if kind=='revisions':
    for position in range(3):
     selected=['f'*40]*3; selected[position]=value
     veto(lambda: r['select'](selected))
   else: veto(lambda: r['select'](('f'*40,),**{kind:(value,)}))
   for mutation in ('omission','decision-drift'):
    changed=copy.deepcopy(p)
    if mutation=='omission': del changed[kind][value]
    else: changed[kind][value]='ADR0326'
    path.write_text(json.dumps(changed))
    veto(lambda: r['select'](('f'*40,),policy=path))
r['select'](('f'*40,))  # Exact selection, not a global content or ancestry veto.
`,
    ],
    { encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("ADR0330 independently rejects every runner-rollover identity and policy drift", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import copy,json,runpy,tempfile
from pathlib import Path
r=runpy.run_path('scripts/stage2-revision-retirement.py'); p=r['load_policy']()
assert p==dict(version='cogs.stage2-retired-revisions/v1',revisions=r['REVISIONS'],runs=r['RUNS'],artifacts=r['ARTIFACTS'])
values=${JSON.stringify(runnerRolloverGeneration)}
def veto(call):
 try: call()
 except r['RetirementError']: return
 raise AssertionError('ADR0330 veto missing')
with tempfile.TemporaryDirectory() as directory:
 path=Path(directory)/'policy.json'
 for kind,identities in values.items():
  for value in identities:
   if kind=='revisions':
    for position in range(3):
     selected=['f'*40]*3; selected[position]=value
     veto(lambda selected=selected: r['select'](selected))
   else:
    veto(lambda kind=kind,value=value: r['select'](('f'*40,),**{kind:(value,)}))
   for decision in (None,'ADR0327'):
    changed=copy.deepcopy(p)
    if decision is None: del changed[kind][value]
    else: changed[kind][value]=decision
    path.write_text(json.dumps(changed)); veto(lambda: r['select'](('f'*40,),policy=path))
r['select'](('f'*40,),runs=('123',),artifacts=('124',))
`,
    ],
    { encoding: "utf8", timeout: 5000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("ADR0335 post-H gross reserves remain independent of cumulative correction highs", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      `
import json,runpy
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py')
assert m['POST_H_REVISION']=='6bd12dcd25d877ffac03752fa0f71beeeb86a99e'
assert m['POST_H_HIGHS']=={'deploy':1500,'retained':19000,'workflow':1200,'global':21000}
f=m['measure']; ns=f.__globals__; original=ns['_gross_slice']; observed=[]
# Isolate reserve enforcement from the separate whole-file planning gate.
budget=json.loads(Path('config/external-review-remediation-budget-v1.json').read_text())
zero={owner['name']:0 for owner in budget['owners']}
forecasts={owner['name']:owner['gross_byte_forecast'] for owner in budget['owners']}
ns['_remediation_gross']=lambda:(zero,zero,budget,forecasts)
ns['_product_test_gross']=lambda budget:zero
ns['_gross_added_line_bytes']=lambda paths,revision:0
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
values=dict(deploy=1200,retained=2000,workflow=800)
report=f()
assert sorted(observed)==['deploy','retained','workflow']
assert report['post_h_gross_added_lines']==dict(values,**{'global':4000})
assert report['post_h_reserve_limits_satisfied'] is True
for key in values:
 values=dict(deploy=0,retained=0,workflow=0); values[key]=m['POST_H_HIGHS'][key]+1
 try: f()
 except m['LineBudgetError']: pass
 else: raise AssertionError(key+' reserve not enforced by central measure')
# Each slice fits independently; the actual global boundary passes then rejects +1.
values=dict(deploy=1500,retained=19000,workflow=500)
assert f()['post_h_gross_added_lines']['global']==21000
values['workflow']+=1
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
  return '1501\\t9999\\tdeploy/aws-feasibility/old.py\\n'
 return ''
ns['_git']=git
assert original((m['DEPLOY_ROOT'],),lambda p: p.endswith('.py'),m['POST_H_REVISION'])==1501
`,
    ],
    { encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

function assertBudgetProgram(program: string) {
  const result = spawnSync("python3", ["-I", "-B", "-c", program], { encoding: "utf8", timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
}
test("ADR0335 exact ownership matrix, eight files, forecasts and ceilings are closed without transfers", () => {
  assertBudgetProgram(String.raw`
import copy,json,runpy,tempfile
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['_remediation_budget']; ns=f.__globals__; original_git=ns['_git']; cache={}
def git(args): cache[tuple(args)]=original_git(args); return cache[tuple(args)]
ns['_git']=git; b,highs,paths,new,forecasts=f()
assert (m['BASE_REVISION'],m['GROSS_CHECKPOINT_REVISION'])==('746568773798d72f5a79ad639d96cb227597f3b7',)*2; assert m['CORRECTION_BASE_REVISION']=='6f7d5c4dfdbf9f5ee4b4be0dc7d54839eac07f57'; assert m['FINAL_H_REVISION']=='8907eba3191d07573cd84573cb0b2adddff17bd6'
assert (m['FINAL_H_DEPLOY_GROSS'],m['FINAL_H_RETAINED_GROSS'],m['FINAL_H_WORKFLOW_GROSS'])==(21948,11844,4836); assert m['CORRECTION_BASE_CONSERVATIVE_LINES']==55354
assert (m['HARD_LIMIT'],m['DEPLOY_CORRECTION_HIGH'],m['RETAINED_CORRECTION_HIGH'],m['WORKFLOW_CORRECTION_HIGH'],m['GLOBAL_CORRECTION_HIGH'])==(115000,24500,31000,6000,60000); assert m['PREFERRED_LIMIT']==90000 and m['MUTABLE_OWNER_LINE_LIMIT']==2000
assert b['global_gross_line_high']==45200; assert b['source_limits']==dict(tracked_files=1517,source_inventory_bytes=26000000,serialized_source_inventory_bytes=262144)
assert highs==dict(route=2200,revocation=3000,relay=4650,lifecycle=11800,completion=6080,integration=18182); assert new==dict(route=1,revocation=0,relay=1,lifecycle=5,completion=3,integration=87) and sum(new.values())==97
expected_bytes=dict(route=350000,revocation=220000,relay=700000,lifecycle=1200000,completion=800000,integration=5200000)
assert m['REMEDIATION_BYTE_HIGHS']==expected_bytes; assert forecasts=={o:dict(total=n) for o,n in expected_bytes.items()}; assert sum(expected_bytes.values())==8470000 and b['global_gross_byte_high']==m['REMEDIATION_GLOBAL_BYTE_HIGH']==6550000 and 18763891+b['global_gross_byte_high']==25313891<26000000
plan=b['product_test_correction']; assert plan['base_revision']==m['PRODUCT_TEST_Q']=='8ddd4c3164bae32dbe02c67d2ee9b82eb8315a38'; assert plan['base_tree']==m['PRODUCT_TEST_Q_TREE']=='181128aae8617eb58c5dce743416f4f69266c02c'
assert plan['global_gross_line_forecast']==15537 and plan['global_gross_byte_forecast']==4500000; assert plan['integration_regeneration_gross_line_forecast']==400
expected_forecasts=dict(route=0,revocation=0,relay=2650,lifecycle=4450,completion=2580,integration=5857)
assert m['PRODUCT_TEST_FORECASTS']==expected_forecasts; assert {e['name']:e['gross_line_forecast'] for e in plan['owners']}==expected_forecasts; assert sum(expected_forecasts.values())==15537
q_bytes=dict(route=0,revocation=0,relay=400000,lifecycle=450000,completion=300000,integration=3900000)
assert m['PRODUCT_TEST_BYTE_FORECASTS']==q_bytes and sum(q_bytes.values())==5050000; assert {e['name']:e['gross_byte_forecast'] for e in plan['owners']}==q_bytes
existing={
 'route':'docs/operations/runbooks/index.json',
 'revocation':'',
 'relay':'''dev/linux-kvm/ci-smoke.sh dev/linux-kvm/driver.sh dev/linux-kvm/qualify.sh
 test/egress-conformance/guest-probes/run-kvm-black-box-case.sh
 test/egress-conformance/stage3-real-runtime/harness.ts test/linux-kvm-git-tools.test.ts''',
 'lifecycle':'''dev/insecure-sandbox/ci-smoke.sh dev/insecure-sandbox/driver.sh dev/insecure-sandbox/ssh-adapter-smoke.ts
 dev/launcher/cli.ts dev/launcher/contract.ts dev/launcher/control.ts dev/launcher/core.ts dev/launcher/main.ts dev/launcher/operations.ts dev/launcher/profiles.ts
 dev/launcher/runner.ts dev/launcher/state.ts dev/launcher/supervisor.ts dev/launcher/trusted-compose.ts dev/launcher/trusted-controls.ts
 dev/launcher/worker-entry.ts dev/launcher/worker-process.ts
 schemas/runtime-v1alpha1.json src/runtime/compose.ts src/runtime/config.ts src/skills/session-preparer.ts
 test/dev-launcher-control-otlp.test.ts test/dev-launcher-core.test.ts test/dev-launcher-operations.test.ts test/dev-launcher-profiles.test.ts
 test/dev-launcher-state.test.ts test/dev-launcher-supervisor.test.ts test/dev-launcher-trusted-compose.test.ts test/dev-launcher-trusted-controls.test.ts
 test/dev-launcher-worker-process.test.ts test/production-compose.test.ts test/runtime-config.test.ts''',
 'completion':'''dev/launcher/api-client.ts src/api/server.ts src/pi/session.ts src/telemetry/worker-telemetry.ts
 test/api-server.test.ts test/dev-launcher-cli-api.test.ts test/pi-session.test.ts
 test/skills-session-preparer.test.ts test/worker-telemetry.test.ts''',
 'integration':'''.github/workflows/insecure-container.yml config/external-review-remediation-budget-v1.json docs/adr/README.md
 docs/operations/production-runtime-foundation.md
 docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json
 docs/security-evidence/stage4-offline-readiness-artifacts/local-validation.json
 docs/security-evidence/stage4-offline-readiness-artifacts/render-preparation-receipt.json
 docs/security-evidence/stage4-offline-readiness-artifacts/schema-inventory.json
 docs/security-evidence/stage4-offline-readiness-artifacts/source-inventory.json
 docs/security-evidence/stage4-offline-readiness-package.json package.json
 scripts/check-stage2-retained-lines.py scripts/run-launcher-smoke-evidence.ts scripts/stage4-offline-readiness-regenerate.ts
 scripts/stage4-offline-readiness.ts scripts/stage4-offline-source-inventory.ts
 scripts/stage4-runtime-artifact-closure-regenerate.ts scripts/stage4-runtime-artifact-closure.ts
 test/aws-stage2-completion-kata-runtime.py test/aws-stage2-completion-kata-s5.py test/aws-stage2-completion-local-result.test.ts
 test/ci-infrastructure-boundary.test.ts test/launcher-smoke-evidence.test.ts test/stage2-remediation-budget.test.ts
 test/stage4-offline-readiness.test.ts test/stage4-runtime-artifact-closure.test.ts test/stage4-schema-registry.test.ts'''}
expected_new={
 'dev/linux-kvm/bounded-command.py':'relay',
 'src/skills/snapshot-session-preparer.ts':'lifecycle',
 'dev/product-test/host-custody.py':'integration',
 'dev/product-test/runner.ts':'integration',
 'dev/product-test/snapshot-owner.ts':'integration',
 'docs/adr/0333-authorize-controlled-product-test-corrections.md':'integration',
 'docs/adr/0334-reallocate-measured-product-test-correction.md':'integration',
 'docs/adr/0335-replan-measured-kvm-custody-and-final-corrections.md':'integration'}
assert m['PRODUCT_TEST_NEW_FILES']==expected_new; assert {e['name']:e['existing_paths'] for e in plan['owners']}=={o:sorted(s.split()) for o,s in existing.items()}
assert {e['name']:e['new_files'] for e in plan['owners']}=={o:sorted(p for p,owner in expected_new.items() if owner==o) for o in existing}; assert {e['name']:len(e['new_files']) for e in plan['owners']}==dict(route=0,revocation=0,relay=1,lifecycle=1,completion=0,integration=6)
planned={p:o for o,s in existing.items() for p in s.split()} | expected_new; assert len(planned)==83 and sum(len(e['existing_paths'])+len(e['new_files']) for e in plan['owners'])==83
for p,owner in planned.items(): assert paths[p]==owner,p
q=plan['base_revision']; q_names=set(git(['ls-tree','-r','--name-only','-z',q]).split('\0')[:-1]); q_budget=json.loads(git(['show',q+':config/external-review-remediation-budget-v1.json'])); old={p:o['name'] for o in q_budget['owners'] for p in o['paths']}
assert all(paths[p]==o for p,o in old.items())  # includes every historical path, not only this matrix
historical_tests={'test/aws-stage2-completion-kata-runtime.py','test/aws-stage2-completion-local-result.test.ts'}
assert {p for p in planned if p.startswith('test/aws-')}==historical_tests|{'test/aws-stage2-completion-kata-s5.py'}
for p in historical_tests: assert p in q_names and old[p]==paths[p]==planned[p]=='integration'
assert set(paths)==set(old)|set(planned); assert set(paths)-q_names==set(expected_new) and len(expected_new)==8
# Newly allocated EXISTING paths carry no historical gross; otherwise a transfer ledger would be required.
added_existing=(set(paths)-set(old))-set(expected_new); assert git(['diff','--no-renames','--numstat',b['base_revision'],q,'--',*sorted(added_existing)])==''
assert paths['test/production-compose.test.ts']=='lifecycle'; assert paths['test/skills-session-preparer.test.ts']=='completion'; assert paths['docs/operations/runbooks/limitations.md']=='route'
assert 'docs/operations/runbooks/limitations.md' not in planned and 'dev/launcher/openbao.ts' not in planned; assert 'schemas/launch-v1alpha1.json' not in planned
assert {p for p in planned if p.startswith(('.github/','deploy/','images/'))}=={'.github/workflows/insecure-container.yml'}
for p in ('package.json','.github/workflows/insecure-container.yml'): assert old[p]==paths[p]==planned[p]=='integration'
for p in ('test/ci-infrastructure-boundary.test.ts','test/launcher-smoke-evidence.test.ts'): assert paths[p]==planned[p]=='integration'
assert planned['test/dev-launcher-profiles.test.ts']=='lifecycle' and 'scripts/prepare-launcher-images.ts' not in planned
adr=Path('docs/adr/0333-authorize-controlled-product-test-corrections.md').read_text(); replan_path='docs/adr/0335-replan-measured-kvm-custody-and-final-corrections.md'
replan=Path(replan_path).read_text(); prior=Path('docs/adr/0334-reallocate-measured-product-test-correction.md').read_text()
assert len(replan.splitlines())<=130
for text in ('Supported-entrypoint denial revision from \x60c2439e42\x60', 'persist-credentials: false', '/usr/bin/python3 -I -B',
 'controlled Docker orchestration is exclusively', 'It does NOT use', 'no root ledger claim',
 'Closed supported external ingress inventory', 'Current exact key is \x60launcher\x60', 'no insecure execution alias exists',
 'fixed denial command', 'appended npm arguments are unused shell positional arguments', 'Package denial does not launch Node or tsx',
 'no pre/post execution hooks', 'unconditional job-level \x60if: \x24{{ false }}\x60', 'skip the whole effectful job',
 'step-only guards', 'extra effectful jobs', 'future exact \x60.github/workflows/insecure-container.yml\x60 execution gate',
 'Direct and sourced entry denies before report unlink/write', '\x60create\x60, \x60verify\x60, \x60reset\x60, \x60destroy\x60',
 'including root callers', 'Both embedded Python cleanup paths', 'before application argument resolution',
 'loader cache/IPC is not target resource authority', 'Imports and module initialization on that CLI path',
 'direct TypeScript exports are trusted internal implementation/model surfaces, not package exports or supported ingress',
 'exported \x60cleanupSensitiveExport\x60 need no independent denial', 'Manual imports', 'operational guardrail',
 'No resistance to arbitrary code imports or same-UID trusted-code compromise is claimed',
 'explicitly image preparation, not product/launcher execution, and unchanged', 'Finding11 closure boundary',
 'closure is limited to supported entrypoints plus controlled product host custody', 'This plan does not close finding11',
 'existing generation-bound root host custodian', 'exact full product execution closure/root helper',
 'same sealed verified context', 'Never consume a later checkout reopen/copy',
 'Required pre-target-effect tests, future source tranche', 'exactly zero application target-effect calls',
 'Preserve non-authorizing models; convert complete-driver assertions', 'retain existing direct-export fake/model success tests',
 'no new internal denial or migration of direct-export successes is required',
 'insecure driver isolates docker tool state outside launcher controls', 'insecure driver never adopts or removes pre-existing docker competitors',
 'including their create/destroy assertions', 'fixed denial, zero-tool calls and byte/mode/device/inode-exact state preservation with no new target paths',
 'Docker HOME/DOCKER_CONFIG/BUILDX_CONFIG isolation', 'no keys before build', 'cleanup-required intent and uncertain lock retention',
 'hostile-state/key preservation and competitor non-adoption/non-removal', 'retain the static Docker context exclusion assertion',
 'never extract or execute a complete-driver body past denial', 'add a root/EUID/env/flag bypass',
 'No runtime guard tests are implemented in this plan-only commit', '83 paths', '12,804/15,100', '988,774/1,850,000'):
 assert text in replan,text
for superseded in ('HOLD 1','durably writes BEGIN before any main/state mkdir','Direct exported boundaries','production-private unforgeable capability','Audit every exported/CLI legacy entry'): assert superseded not in replan,superseded
for p in planned: assert p in adr or p in replan,p
for p in expected_new: assert p in replan,p
for text in ('/tmp/cogs42-kvm-budget-replan.md','e3c1e938f3237df468ebf266f2b1cc096ae4ba05','044e127a',
 '8,604/12,000 lines and 416,404/1,300,000 bytes','completion 2,047; lifecycle 2,446; relay 732; integration 3,379',
 '24,733,891','44,705','45,200','6,496 remaining gross lines','No historical gross transfers: zero lines and zero files transferred',
 'Do not commit pending two independent reviews','No reserve release before that owner\'s named tasks complete',
 'task consumption, reserve use and the exact changed-since-review diff','not task purpose inferred from line diffs',
 'Finding12 remains open','final implementation review remains pending','source-only','convert every admitted driver/smoke/conformance guest invocation',
 'bound QMP, reject truncation','portable subprocess/fault tests','no finding-closure or host-containment claim',
 'Docker-only and mechanically rejects a KVM profile','Actual KVM execution remains prohibited until focused/full source reviews pass',
 'existing-file, independently reviewed local-execution gate','complete fresh protected-runner envelope',
 'stop-before-exec placement for every driver/smoke/helper process and cgroup escape prevention',
 'all writable paths and logs, fixed storage/quota, and exact lifetime/settlement deadlines',
 'existing non-initial network namespace and root-owned \x60/run/cogs-kvm-network-domain/<device>-<inode>\x60 lease',
 'preloaded image/cache identity and receipt-bound retirement','no ninth file is implied','Missing prerequisites fail before effects',
 'tool errors bind evidence','snapshot discovery uses journaled publication with no external temp','Buildx inventoried retirement','FIFO nonblocking validation','cross-invocation fixtures',
 'No AWS/provider/model/credential operation or authoritative H/G/Q workflow is authorized',
 'Existing commits gain no retrospective authority if this gate fails','Stop immediately before every AWS-facing command'):
 assert text in replan,text
assert replan_path.removeprefix('docs/adr/') in prior and replan_path.removeprefix('docs/adr/') in Path('docs/adr/README.md').read_text()
assert '5,870/6,000' in prior and '24,133,891' in prior  # history is not rewritten
q_lines=dict(route=2023,revocation=2984,relay=1953,lifecycle=7348,completion=2972,integration=12325)
for owner in q_lines:
 assert f'| {owner} | {q_lines[owner]:,} | {expected_forecasts[owner]:,} | {highs[owner]:,} |' in replan
 assert f'| {owner} | {q_bytes[owner]:,} | {expected_bytes[owner]:,} |' in replan
for row in (
 '| relay | 2,068 | bounded helper/call-site/QMP/tests 1,400; review reserve 668 |',
 '| lifecycle | 1,854 | mounted-snapshot/compose corrections 400; launcher/insecure acquisition corrections 450; production HTTPS/capability/live-mount tests 350; profile truncation 50; runtime schema/docs 50; review reserve 554 |',
 '| integration | 1,121 | ADR0335/budget tests 500; source-inventory constant synchronization/readiness regeneration 100; later in-file ADR0335 execution-contract amendment and existing tests 200; product execution docs/tests 100; reserve 221 |',
 '| completion | 1,453 | event review corrections/tests 700; telemetry/HTTPS integration 300; reserve 453 |'):
 assert row in replan,row
previous=json.loads(git(['show','086b2c2cda3fa09f4455baa8c5c4dedcb212bb44:config/external-review-remediation-budget-v1.json'])); expected=copy.deepcopy(previous)
expected['product_test_correction']['integration_synchronization_gross_byte_forecast']=60000
next(e for e in expected['product_test_correction']['owners'] if e['name']=='integration')['gross_byte_forecast']=1200000
expected['global_gross_byte_high']=6550000; expected['product_test_correction']['global_gross_byte_forecast']=4500000
next(e for e in expected['product_test_correction']['owners'] if e['name']=='integration')['gross_byte_forecast']=3900000
next(e for e in expected['owners'] if e['name']=='integration')['gross_byte_forecast']['total']=5200000
expected['product_test_correction']['integration_regeneration_gross_line_forecast']=400
for name,delta in (('completion',-420),('relay',-150),('integration',570)):
 next(e for e in expected['product_test_correction']['owners'] if e['name']==name)['gross_line_forecast']+=delta; next(e for e in expected['owners'] if e['name']==name)['gross_line_high']+=delta
assert b==expected  # historical completion 420 plus prospective relay 150; no anchor/path/accounting changes
for parent,head,charged in (('086b2c2cda3fa09f4455baa8c5c4dedcb212bb44','fdf7726b768e45e808e16bdfaf048d03d50102ac',11740),('fdf7726b768e45e808e16bdfaf048d03d50102ac','9ef95d2946c88dfcf594e4d026877badbc4e914e',290399),('9ef95d2946c88dfcf594e4d026877badbc4e914e','3e9969282fef305aca3c526e4bd36a9c46ee40e0',281692),('3e9969282fef305aca3c526e4bd36a9c46ee40e0','5fad3419d794b9cae9c5e6f20d7b4fe75640a7a7',12478),('5fad3419d794b9cae9c5e6f20d7b4fe75640a7a7','e4b7835c6f35eac2f97a7bcc3cb9880ce640c39a',280750)):
 raw=m['_git_raw'](['diff','--no-renames','--no-ext-diff','--no-textconv','--diff-algorithm=myers','--indent-heuristic','--unified=3',parent,head,'--',*sorted(p for p,o in paths.items() if o=='integration')]); assert sum(len(line)-1 for line in raw.splitlines(keepends=True) if line.startswith(b'+') and not line.startswith(b'+++'))==charged
assert 728683+11740+290399+281692==1312514 and 2095805+11740+290399+281692==2679636
assert 1312514+20000+280750==1613264 and 2679636+20000+280750==2980386 and 12478+7522==20000
future=2*300000+20000+4517+20000+8000; assert future==652517 and 1613264+300000+future==2565781 and 2980386+300000+future==3932903
assert 5083+44+7+5==5139 and 101+5+64+20+10==200 and 5139+64+20+10+150+4==5387 and 2552+348==2900
rounded=lambda n:((n+49999)//50000)*50000
assert rounded(2565781)==2600000 and rounded(3231576)==3250000 and rounded(3932903)==3950000  # consumed historical funding, no credit
for text in ('exact empty-tags plan','\x60.git/refs/tags/\x60','inventory value \x60None\x60','real local Git fixture','nonempty tags, nested descendants, file/symlink substitution','No implementation/readiness here','300,000 bytes and five lines','99,463+15,537=115,000 is NOT'): assert text in replan,text
for parent,head,charge in (('e4b7835c6f35eac2f97a7bcc3cb9880ce640c39a','6efd79649530af46ea7440c0b43dbdba9af0c6d8',19091),('6efd79649530af46ea7440c0b43dbdba9af0c6d8','741dfb738fd951e4628d6f5286c15b80aa55ccc8',283844)):
 raw=m['_git_raw'](['diff','--no-renames','--no-ext-diff','--no-textconv','--diff-algorithm=myers','--indent-heuristic','--unified=3',parent,head,'--',*sorted(p for p,o in paths.items() if o=='integration')]); assert sum(len(l)-1 for l in raw.splitlines(keepends=True) if l.startswith(b'+') and not l.startswith(b'+++'))==charge
assert 19091+909==20000 and 3164+280680==283844 and 3164+2*280680==564524  # identical second bundle remains charged
assert 1613264+300000+20000+564524==2497788 and 2980386+300000+20000+564524==3864910
assert (8000-3164)+(600000-2*280680)+20000+4517==67993 and 2497788+67993==2565781 and 3864910+67993==3932903
assert 2*300000+24000+10000==634000 and 2565781+634000==3199781 and 3932903+634000==4566903
assert 348+42+10==plan['integration_regeneration_gross_line_forecast'] and 5549+4+4+150+64+76+10==expected_forecasts['integration']==5857
assert 2552+28==expected_forecasts['completion']==2580 and 12325+5857==highs['integration']==18182 and 1771+879==expected_forecasts['relay'] and 148-120==28
assert planned['test/production-compose.test.ts']==paths['test/production-compose.test.ts']=='lifecycle'
assert 4195+100+155==expected_forecasts['lifecycle'] and 11503+100+197==highs['lifecycle']
assert 194972+6000<=267175<=q_bytes['lifecycle'] and 478274+6000<=558274<=expected_bytes['lifecycle']
assert 12+88==100 and 5000+5000==10000 and (160-88)+48==120  # retain full prior closure charge; fresh helper 160/12000
for text in ('P2 fixture plan closure at \x6011c95edeab1b330a33c22a35feecddc11339521d\x60','real temporary generation/control directory','si_pid','si_code=CLD_STOPPED','si_status=SIGSTOP','100 gross lines/6,000 raw added-line bytes','155/197 lines','inside existing lifecycle 80,000-byte task funding','withheld 24 lines/771 bytes','No owner/global cap raise, transfer','process-group SIGKILL then helper cgroup.kill before reap'): assert text in replan,text
for text in ('Before subprocess fork','helper-pending','<=1,024 bytes','integer 1','parent_pid','fsync file and control directory before fork','Record no command secrets','PR_SET_PDEATHSIG=SIGKILL','getppid()','captured BEFORE fork','CLD_STOPPED','SIGSTOP','read back exact','only then unlink the exact pending inode and fsync control durably','then SIGCONT','lost removal','pending on recovery vetoes retirement','sticky crash-safe refusal, no adoption','no recovery clearing/retrying pending','before the cgroup-retire-intent shortcut','after durable pending removal cgroup custody governs','fork->prctl->stop->placement->pending removal','post-unlink/pre-fsync','parent kill before/after arming','spawn failure before/after child creation','stale/malformed/foreign/oversize/extra-field','Keep existing cgroup settlement exact','exact saved cgroup device/inode','helpers rmdir then generation rmdir','recovery after either rmdir without further commands','bounded reap/population wait and descriptor settlement','WNOWAIT leader','No source implementation','no independent review success claimed'): assert text in replan,text
governance_bytes=10000; extra=12000-5000+governance_bytes
assert max(3220000,3199781+extra)==3220000 and 3199781+extra==3216781 and 4566903+extra==4583903  # historical funding
for text in ('Completion closure allocation is closed/reduced','148->28','helper 160 lines/12,000 bytes','governance 48 lines/10,000 bytes','5,335+48+160+10+150+4=5,707','No deletion credit','3,216,781','4,583,903'): assert text in replan,text
q_bytes['integration'],expected_bytes['integration']=3220000,4600000  # historical endpoints below
for usage,limits,global_high,endpoint,full_integration in ((dict(route=0,revocation=0,completion=159893,lifecycle=267175,relay=204508,integration=3199781+extra),q_bytes,3900000,3848357,3851576),(dict(route=96627,revocation=114977,completion=228357+60000,lifecycle=478274+80000,relay=177404+120000,integration=4566903+extra),expected_bytes,6550000,5939542,5955639)):
 assert all(usage[o]<=limits[o] for o in usage) and sum(usage.values())==endpoint<global_high and f'{endpoint:,}' in replan
 assert sum(usage.values())+limits['integration']-usage['integration']==full_integration<global_high
q_bytes['integration'],expected_bytes['integration']=3900000,5200000  # restore current independent highs
assert 2497788+24000+5000+10000+11981+2*280680==3110129 and 3864910+24000+5000+10000+11981+2*280680==4477251 and 67993+19+38640==106652
assert 5383+156+2*5==5549 and 42+22==64 and 22+76==98 and 4295+40+115==4450 and 11603+40+157==11800
assert 300+579==879 and 20000+90000==110000==120000-10000 and 84508+110000==194508 and 177404+110000==287404
for base,other,limits,cap,total in ((3110129,621576,q_bytes,4500000,4454357),(4477251,1345639,expected_bytes,6550000,6545542)):
 endpoint=base+106652+2*300000+11000+5000; assert endpoint<limits['integration'] and endpoint+other==total<cap; assert f'{endpoint:,}' in replan and f'{total:,}' in replan
assert 6545542+10000>6550000 and 621576+3900000>4500000 and 1345639+5200000<6550000
for text in ('5e008f934792741f3050204a944f12e8c875960a','O_DIRECTORY|O_NOFOLLOW','fstat','descriptor-relative lstat','helpers-cgroup','No path-only exists/rmdir','foreign empty cgroup','final events/kill/rmdir','106,652','348+42','governance 64/11,000','correction 76/5,000','associated task bytes 10,000','KVM gate 300/20,000'): assert text in replan,text
assert plan['integration_synchronization_gross_byte_forecast']==60000 and 25249+18687==43936 and 43936-12000==31936
assert 60000-43936==16064 and 727775+908==728683 and 12000+6000+8000+20000+236550+60000==342550
assert 728683+342550==1071233>1011233>1000000 and 1200000-1071233==128767
assert 159893+267175+204508+1071233==1702809 and 1850000-1702809==147191
assert 159893+267175+204508+1200000==1831576<1850000 and 3183647+342550+260000==3786197<5970000
assert 2095805+342550==2438355<2700000 and 2095805+(1200000-728683)==2567122<2700000
assert 4846+61+130+150+100==5287 and 40+60==100  # governance synchronization is inside this task, not additional lines
import hashlib
for name,size,digest in (('stage4-offline-readiness-artifacts/local-validation.json',25249,'8ff3d8daad3fecfc7a8c20b5c7dc68ce4df88a8eb2f39db68fae548c3d508b24'),('stage4-offline-readiness-package.json',18687,'42ca1e7c043dda78e5942cf58dd5e14ebac6798aa263db879f76d87ab28419b1')):
 raw=m['_git_raw'](['show','086b2c2cda3fa09f4455baa8c5c4dedcb212bb44:docs/security-evidence/'+name]); assert len(raw)==size and raw.count(b'\n')==1 and hashlib.sha256(raw).hexdigest()==digest and digest in replan
for text in ('403baa5740442a6afe608f701f33635c7dc00561d90e1f6022f0e5814f7e07f2','2c402ebbd5cc8d4ea2e0efcf0a4561ff6ba4a72d61dab74db4ab5c85c594708a','43,936','31,936','NOT measured regenerated totals','No splitting/reformatting, compression, deletion/net-byte credit','1,071,233','1,702,809','at most 40 gross lines','SAME 100','No line cap changes'): assert text in replan,text
assert all(t in Path('docs/adr/README.md').read_text() for t in ('43,936','31,936','60,000','1,200,000','1,702,809','All line caps unchanged'))
expected_forecasts.update(relay=2800,integration=5200,completion=3000); q_bytes['integration']=1000000  # Historical ledgers below, not current capacity.
historical_forecasts=dict(relay=2800,lifecycle=4300,integration=4500,completion=3500)
for owner,used,remaining in (('relay',732,2068),('lifecycle',2446,1854),('integration',3379,1121),('completion',2047,1453)):
 assert historical_forecasts[owner]-used==remaining  # original gate ledger remains historical
checkpoint=dict(route=0,revocation=0,relay=1771,lifecycle=3984,completion=2552,integration=4475)
pivot_forecasts={**expected_forecasts,'lifecycle':4300,'integration':5000}  # historical caps, not current capacity
assert sum(checkpoint.values())==12782 and sum(pivot_forecasts[o]-n for o,n in checkpoint.items())==2318
pivot={**checkpoint,'integration':4497}; assert sum(pivot.values())==12804 and sum(pivot_forecasts[o]-n for o,n in pivot.items())==2296
assert 90+180+46==pivot_forecasts['lifecycle']-pivot['lifecycle'] and 70+80+150+100+103==pivot_forecasts['integration']-pivot['integration']
assert 30+240+46==316 and 80+50+50+150+100+10==pivot_forecasts['integration']-(pivot['integration']+63)==440
assert 448+1029+316+440==2233 and '2,233 total lines remain before this revision' in replan  # historical, not spendable
assert 26+50+20+20+150+100+10==pivot_forecasts['integration']-(4497+63+64)==376
assert 30+120+120+46==pivot_forecasts['lifecycle']-3984==316 and 448+1029+316+376==2169
for text in ('Reconciled remaining-task ledger from \x60eb9a3ec0\x60', 'ci-smoke wrapper sentinel/tool-spy guards 20',
 'report CLI denial/guards 20', 'complete-driver denial conversion/entry sentinels 120',
 'equivalent internal driver behavior preservation in existing isolated model tests 120',
 'wrapper guard tests are not charged to lifecycle', 'No lifecycle charge transfer', '2,169 total lines remain before this amendment'):
 assert text in replan,text
assert 132>120 and 30+190+120+46==386>316
assert expected_forecasts['lifecycle']-3984==30+190+120+46+80==466
assert 5100-4648==102+50+20+20+150+100+10==452 and 448+1029+466+452==2395  # historical
assert expected_forecasts['integration']-4737==102+61+20+20+150+100+10==463 and 61-50==11
assert 30+190+120+46+40+40==466 and 448+1029+466+463==2406
assert sum(q_lines.values())+sum(m['PRODUCT_TEST_FORECASTS'].values())==45142<=b['global_gross_line_high']==45200
assert all(q_lines[o]+m['PRODUCT_TEST_FORECASTS'][o]<=highs[o] for o in highs)
assert 99462+15537==114999<m['HARD_LIMIT'] and 95359+15537==110896<m['HARD_LIMIT']
assert plan['wrapper_report_minimum']==dict(gross_lines=130,gross_bytes=8000) and 5287-4798==48+61+130+150+100
assert 1011233-716683==12000+6000+8000+20000+236550+12000 and 1631576+11233==1642809<1850000
for text in ('1004c6c90080e213f416bb300c80ed3e5078a43f9aaa8dc995a0166b90f5507a','102/40','4,831/4,000','Bash 3.2','trap on_error ERR','130 lines/8,000 bytes','45,142','114,999'): assert text in replan,text
assert 700000-681198-12000==6802 and 1850000-989430==860570  # historical, not current headroom
assert 236550-6802==229748 and 693198+236550+10000+60000==999748<=q_bytes['integration']
assert q_bytes['integration']-693198==236550+10000+60252==306802
assert 99893+187175+84508+693198+306802==1371576<plan['global_gross_byte_forecast']
assert 2080477+306802==2387279<=expected_bytes['integration'] and 3168319+306802==3475121<5970000
assert 4707+30==4737 and 5100-4737==13+350==363  # prior full allowance remains charged
assert q_bytes['integration']-703198==236550+15000+6000+2000+2000+20000+12000+3252==296802
assert 2000+20000+18000+6000+10000+24000==80000
tasks=dict(completion=60000,lifecycle=80000,relay=120000,integration=296802)
charges=dict(completion=99893,lifecycle=187175,relay=84508,integration=703198)
assert sum(tasks.values())==556802 and sum(charges.values())+sum(tasks.values())==1631576<plan['global_gross_byte_forecast']
assert all(charges[o]+tasks[o]<=q_bytes[o] for o in tasks) and 1850000-1631576==218424
assert 3171880+556802==3728682<5970000 and 2084038+296802==2380840<expected_bytes['integration']
for text in ('61/50 gross lines', '11-line overrun', '2,918 raw added-line bytes', '318 lines/13,020 bytes',
 '/tmp/cogs42-external-ingress-denial-draft.patch', 'fe5625a70ef08181e6d910c837164d8e7c6420ce0055f098961fa1c2bab443c6',
 'two passes and one failure', 'insecure-container docker state is invalid', 'expected 0, actual 1',
 'separately from preservation 120', 'correction spending requires the existing explicit reviewed task checkpoint',
 '2,406', '1,631,576', '114,911', '102 lines/15,000 bytes', 'two independent governance reviews of the exact final diff'):
 assert text in replan,text
for text in ('canonical artifact indivisibly', '229,748 shortfall before implementation', '999,748, rounded to 1,000,000',
 'remaining implementation/contingency 60,252', '2,150,000', '300,000 excess is not spendable global capacity'):
 assert text in replan,text
for text in ('132/120 gross lines', 'complete-driver denial conversion/entry sentinels 190', 'inherited contingency 46 + withheld fit buffer 80',
 'this governance 102', '2,395 total remain before this amendment', '44,955', '114,811', '12,000 gross added-line bytes',
 'complete future implementation byte fit is not proven', 'No accounting algorithm changes'):
 assert text in replan,text
index=Path('docs/adr/README.md').read_text(); assert all(t in index for t in ('132/120','61/50','15,450','45,055','45,200','114,911','1,631,576'))
for text in (q,plan['base_tree'],'pre-source governance/budget gate; source implementation separately authorized','Raising a ceiling is not implementation or execution authority',
 'No historical gross transfers','100 gross-line deterministic-regeneration forecast','Stop immediately before every AWS-facing command',
 'Finding 12 is no longer deferred','schema-valid does not mean production-admissible','not implemented by this gate'):
 assert text in adr,text
for finding in (4,5,6,8,9,10,14): assert '| '+str(finding)+' ' in adr
assert '0333-authorize-controlled-product-test-corrections.md' in Path('docs/adr/README.md').read_text()
# Isolate budget-parser mutations from the real worktree, retaining exact Q git evidence.
ns['_git']=lambda args:cache[tuple(args)]
def veto(call,label):
 try: call()
 except m['LineBudgetError']: return
 raise AssertionError(label)
with tempfile.TemporaryDirectory() as directory:
 ns['ROOT']=Path(directory); path=ns['ROOT']/'config/external-review-remediation-budget-v1.json'
 path.parent.mkdir(); ns['REMEDIATION_BUDGET_PATH']=path
 def check(bad):
  path.write_text(json.dumps(bad)); return f()
 check(b)
 for value in (6500000,6549999,6550001,6550000.0,True,None):
  bad=copy.deepcopy(b); bad['global_gross_byte_high']=value; veto(lambda:check(bad),'remediation global bytes')
 for field in b['source_limits']:
  for delta in (-1,1):
   bad=copy.deepcopy(b); bad['source_limits'][field]+=delta; veto(lambda:check(bad),(field,delta))
 for name,owner in expected_new.items():
  bad=copy.deepcopy(b)
  next(e for e in bad['product_test_correction']['owners'] if e['name']==owner)['new_files'].remove(name)
  veto(lambda:check(bad),'missing '+name)
  next(e for e in bad['owners'] if e['name']==owner)['paths'].remove(name)
  veto(lambda:check(bad),'removed from both allocations '+name)
  bad=copy.deepcopy(b); target='docs/adr/0336-unallocated-execution-gate.md'
  for entries,field in ((bad['owners'],'paths'),(bad['product_test_correction']['owners'],'new_files')):
   entry=next(e for e in entries if e['name']==owner)
   entry[field]=sorted(target if p==name else p for p in entry[field])
  veto(lambda:check(bad),'same-count file substitution '+name)
 bad=copy.deepcopy(b)
 for entries,field in ((bad['owners'],'paths'),(bad['product_test_correction']['owners'],'new_files')):
  entries[-1][field]=sorted([*entries[-1][field],'docs/adr/0336-unallocated-execution-gate.md'])
 veto(lambda:check(bad),'ninth allocated file')
 for owner in range(len(b['owners'])):
  for field in ('gross_line_high','new_file_high'):
   bad=copy.deepcopy(b); bad['owners'][owner][field]+=1; veto(lambda:check(bad),(owner,field))
  bad=copy.deepcopy(b); bad['owners'][owner]['gross_byte_forecast']['total']+=1
  bad['owners'][(owner+1)%6]['gross_byte_forecast']['total']-=1
  veto(lambda:check(bad),(owner,'byte-transfer-with-unchanged-total'))
  for field in ('gross_line_forecast','gross_byte_forecast'):
   bad=copy.deepcopy(b); bad['product_test_correction']['owners'][owner][field]+=1
   veto(lambda:check(bad),(owner,field))
 for field in ('gross_lines','gross_bytes'):
  bad=copy.deepcopy(b); bad['product_test_correction']['wrapper_report_minimum'][field]-=1; veto(lambda:check(bad),field)
 for field in ('global_gross_line_forecast','global_gross_byte_forecast'):
  bad=copy.deepcopy(b); bad['product_test_correction'][field]+=1; veto(lambda:check(bad),field)
 for value in (200,300,348,399,401,400.0,True,None):
  bad=copy.deepcopy(b); bad['product_test_correction']['integration_regeneration_gross_line_forecast']=value; veto(lambda:check(bad),'synchronization lines')
 for value in (12000,59999,60001,60000.0,True,None):
  bad=copy.deepcopy(b); bad['product_test_correction']['integration_synchronization_gross_byte_forecast']=value; veto(lambda:check(bad),'synchronization bytes')
 for mutation in ('planned-overrun','owner-transfer','duplicate-owner','missing-new','global-high','forecast-high','regeneration-free','q-drift','tree-drift'):
  bad=copy.deepcopy(b); p=bad['product_test_correction']
  if mutation=='planned-overrun': bad['owners'][-1]['paths'].append('test/planned-extra.ts')
  elif mutation=='owner-transfer':
   name='test/production-compose.test.ts'; bad['owners'][3]['paths'].remove(name)
   bad['owners'][-1]['paths']=sorted([*bad['owners'][-1]['paths'],name])
  elif mutation=='duplicate-owner': bad['owners'][-1]['paths']=sorted([*bad['owners'][-1]['paths'],'src/api/server.ts'])
  elif mutation=='missing-new': p['owners'][-1]['new_files'].pop()
  elif mutation=='global-high': bad['global_gross_line_high']+=1
  elif mutation=='forecast-high': p['owners'][-1]['gross_line_forecast']+=1
  elif mutation=='regeneration-free': p['integration_regeneration_gross_line_forecast']=0
  elif mutation=='q-drift': p['base_revision']='f'*40
  else: p['base_tree']='f'*40
  veto(lambda:check(bad),mutation)
`);
});
test("ADR0335 actual current integrated worktree passes the unmocked central budget gate", () => {
  const result = spawnSync("python3", ["-I", "-B", "scripts/check-stage2-retained-lines.py"], {
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr || "actual integrated budget rejected");
  const report = JSON.parse(result.stdout);
  for (const key of [
    "correction_slice_limits_satisfied",
    "post_h_reserve_limits_satisfied",
    "remediation_limits_satisfied",
    "hard_satisfied",
    "mutable_owner_line_limit_satisfied",
  ])
    assert.equal(report[key], true, key);
  for (const [kind, limit] of [
    ["lines", 15537],
    ["line_bytes", 4500000],
  ] as const) {
    const usage = report[`product_test_workstream_gross_added_${kind}`];
    assert.equal(usage.route, 0);
    assert.equal(usage.revocation, 0);
    for (const owner of ["relay", "lifecycle", "completion", "integration"]) assert.ok(usage[owner] > 0, owner);
    const total = Object.values(usage).reduce<number>((sum, value) => sum + Number(value), 0);
    assert.equal(report[`product_test_gross_added_${kind}_no_deletion_credit`], total);
    assert.ok(total <= limit, `${kind}: ${total}/${limit}`);
  }
});
test("ADR0335 independent correction, hard and Q-relative limits reject isolated overruns", () => {
  assertBudgetProgram(String.raw`
import copy,runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['measure']; ns=f.__globals__
b,highs,paths,new,forecasts=m['_remediation_budget'](); zero={o:0 for o in highs}
ns['_remediation_gross']=lambda:(zero,zero,b,forecasts)
ns['_product_test_gross']=lambda budget:zero
ns['_gross_added_line_bytes']=lambda paths,revision:0
ns['_lines']=lambda path:0  # isolate arithmetic enforcement from physical line counts
values=dict(deploy=0,retained=0,workflow=0)
def gross(paths,allowed,revision):
 if revision==m['POST_H_REVISION']: return 0
 assert revision==m['FINAL_H_REVISION']
 return values['deploy' if paths==(m['DEPLOY_ROOT'],) else 'workflow' if paths==(m['WORKFLOW_ROOT'],) else 'retained']
ns['_gross_slice']=gross
# File validation is orthogonal and tested below; do not synthesize zero-line canonical JSON.
ns['_validate_control_data_members']=lambda names:None
assert f()['hard_satisfied'] is True
def veto(call,label):
 try: call()
 except m['LineBudgetError']: return
 raise AssertionError(label)
ns['_remediation_gross']=lambda:(remediation,zero,b,forecasts)
for owner,high in highs.items():
 remediation=dict(zero); remediation[owner]=high
 assert f()['remediation_workstream_gross_added_lines']==remediation
 remediation[owner]+=1
 assert sum(remediation.values())<b['global_gross_line_high']
 veto(f,owner+' cumulative owner high+1 with other owners zero')
remediation=dict(highs); remediation['integration']-=712
assert sum(highs.values())==45912
assert f()['remediation_gross_added_lines_no_deletion_credit']==45200
remediation['integration']+=1
assert all(remediation[o]<=highs[o] for o in highs)
veto(f,'remediation global high+1 with every owner within high')
ns['_remediation_gross']=lambda:(zero,zero,b,forecasts)
base=dict(deploy=21948,retained=11844,workflow=4836)
for key,limit in [('deploy',24500),('retained',31000),('workflow',6000)]:
 values=dict(deploy=0,retained=0,workflow=0); values[key]=limit-base[key]+1
 veto(f,key)
# Isolate correction global within real slice ceilings, then restore the tighter conservative hard stop.
ns['HARD_LIMIT']=120000
values=dict(deploy=24500-base['deploy'],retained=30018-base['retained'],workflow=5482-base['workflow'])
assert f()['correction_global_gross_added_lines']==60000
values['retained']+=1; veto(f,'correction global')
ns['HARD_LIMIT']=115000
# Strict conservative equality fails with every real correction slice in range.
values=dict(deploy=24500-base['deploy'],workflow=5482-base['workflow'],retained=115000-55354-24500-5482-base['retained']-1)
assert f()['conservative_lines_no_deletion_credit']==114999
values['retained']+=1; veto(f,'hard equality')
values=dict(deploy=0,retained=0,workflow=0)
physical=114999
ns['_lines']=lambda path:physical if path==m['ROOT']/m['RETAINED_FILES'][0] else 0
assert f()['current_lines']==114999
physical+=1; veto(f,'physical hard equality with conservative below hard limit')
mutable=1999
ns['_lines']=lambda path:mutable if path==m['ROOT']/m['MUTABLE_OWNER_FILES'][0] else 0
assert f()['mutable_owner_lines']==1999
mutable+=1; veto(f,'mutable owner strict equality')
# Q-relative accounting is another independent gross diff, not endpoint subtraction.
g=m['_product_test_gross']; gs=g.__globals__
changed='src/api/server.ts\0'; ordinary=''
def git(args):
 if 'diff' in args:
  assert m['PRODUCT_TEST_Q'] in args and '--no-renames' in args
  return changed
 return ordinary
values=dict(m['PRODUCT_TEST_FORECASTS'])
gs['_git']=git
def q_gross(names,allowed,revision):
 assert revision==m['PRODUCT_TEST_Q'] and all(allowed(p) for p in names)
 return values[next(e['name'] for e in b['product_test_correction']['owners'] if tuple(e['existing_paths']+e['new_files'])==names)]
gs['_gross_slice']=q_gross
assert sum(g(b).values())==15537
for owner,high in m['PRODUCT_TEST_FORECASTS'].items():
 values=dict(zero); values[owner]=high
 assert g(b)==values
 if owner=='revocation':
  # No allocated paths: a real revocation change is rejected by scope below.
  continue
 values[owner]+=1
 assert sum(values.values())<b['product_test_correction']['global_gross_line_forecast']
 veto(lambda:g(b),owner+' Q owner high+1 with other owners zero')
values={o:0 for o in values}
changed='dev/launcher/openbao.ts\0'; veto(lambda:g(b),'legacy-owned but out of scope')
changed='docs/operations/runbooks/index.json\0'; veto(lambda:g(b),'zero-forecast index drift even with no added lines')
changed=''; ordinary='dev/product-test/unplanned.ts\0'; veto(lambda:g(b),'unplanned ordinary file')
ordinary='docs/adr/0333-authorize-controlled-product-test-corrections.md\0'
assert sum(g(b).values())==0
# A tighter synthetic global proves the combined Q cap is also checked independently.
values=dict(m['PRODUCT_TEST_FORECASTS']); tight=copy.deepcopy(b)
tight['product_test_correction']['global_gross_line_forecast']=15449
veto(lambda:g(tight),'Q global')
`);
});
test("ADR0335 central measure invokes the Q-relative gate and reports its nonzero totals", () => {
  assertBudgetProgram(String.raw`
import runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['measure']; ns=f.__globals__
b,highs,paths,new,forecasts=m['_remediation_budget'](); zero={o:0 for o in highs}
ns['_remediation_gross']=lambda:(zero,zero,b,forecasts)
ns['_gross_added_line_bytes']=lambda paths,revision:0
original_git=ns['_git']
changed='src/api/server.ts\0'
def git(args):
 if 'diff' in args and m['PRODUCT_TEST_Q'] in args:
  assert '--name-only' in args and '-z' in args
  return changed
 if args==['ls-files','--others','--exclude-standard','-z','--','.']: return ''
 return original_git(args)
ns['_git']=git
expected=dict(route=0,revocation=0,relay=11,lifecycle=22,completion=33,integration=44)
values=dict(expected)
def gross(names,allowed,revision):
 if revision!=m['PRODUCT_TEST_Q']:
  assert revision in (m['FINAL_H_REVISION'],m['POST_H_REVISION'])
  return 0
 assert all(allowed(p) for p in names)
 owner=next(e['name'] for e in b['product_test_correction']['owners']
            if tuple(e['existing_paths']+e['new_files'])==names)
 return values[owner]
ns['_gross_slice']=gross
# Keep _product_test_gross real: central measurement must reject bypassed calls or zeroed totals.
report=f()
assert report['product_test_base_revision']=='8ddd4c3164bae32dbe02c67d2ee9b82eb8315a38'
assert report['product_test_workstream_gross_added_lines']==expected
assert report['product_test_gross_added_lines_no_deletion_credit']==110
assert report['product_test_global_gross_line_forecast']==15537
def veto(label):
 try: f()
 except m['LineBudgetError']: return
 raise AssertionError(label+' bypassed by central measure')
values=dict(zero); values['completion']=2580
assert f()['product_test_gross_added_lines_no_deletion_credit']==2580
values['completion']=2581
assert sum(values.values())<15450
veto('Q owner overrun')
values=dict(zero)
for changed in ('dev/launcher/openbao.ts\0','docs/operations/runbooks/index.json\0'):
 veto('out-of-scope or zero-forecast change')
`);
});
test("ADR0335 central measure enforces every independent byte ceiling with zero line additions", () => {
  assertBudgetProgram(`
import runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['measure']; ns=f.__globals__
b,highs,paths,new,forecasts=m['_remediation_budget'](); zero={o:0 for o in highs}
ns['_remediation_gross']=lambda:(zero,zero,b,forecasts)
ns['_product_test_gross']=lambda budget:zero
ns['_gross_slice']=lambda *args:0
assert m['PRODUCT_TEST_GLOBAL_BYTE_FORECAST']==4500000 and m['REMEDIATION_GLOBAL_BYTE_HIGH']==6550000
cumulative=dict(route=1,revocation=2,relay=3,lifecycle=4,completion=5,integration=6)
correction=dict(route=0,revocation=0,relay=7,lifecycle=8,completion=9,integration=10)
def raw_bytes(names,revision):
 is_q=revision==m['PRODUCT_TEST_Q']
 assert is_q or revision==m['REMEDIATION_BASE_REVISION']
 entries=b['product_test_correction']['owners'] if is_q else b['owners']
 owner=next(e['name'] for e in entries if tuple(e['existing_paths']+e['new_files'] if is_q else e['paths'])==names)
 return (correction if is_q else cumulative)[owner]
ns['_gross_added_line_bytes']=raw_bytes  # keep both real byte gates and central calls
report=f()
assert report['remediation_workstream_gross_added_line_bytes']==cumulative
assert report['product_test_workstream_gross_added_line_bytes']==correction
assert report['remediation_gross_added_line_bytes_no_deletion_credit']==21
assert report['product_test_gross_added_line_bytes_no_deletion_credit']==34
assert report['product_test_global_gross_byte_forecast']==4500000
assert report['product_test_workstream_gross_byte_forecasts']==m['PRODUCT_TEST_BYTE_FORECASTS']
def veto(label):
 try: f()
 except m['LineBudgetError']: return
 raise AssertionError(label+' bypassed by central measure')
for is_q in (False,True):
 limits=m['PRODUCT_TEST_BYTE_FORECASTS' if is_q else 'REMEDIATION_BYTE_HIGHS']
 for owner,high in limits.items():
  cumulative=dict(zero); correction=dict(zero)
  values=correction if is_q else cumulative; values[owner]=high
  assert f()['remediation_gross_added_lines_no_deletion_credit']==0
  values[owner]+=1
  assert sum(values.values())<(4500000 if is_q else 6550000)
  veto(str((is_q,owner,'isolated byte high+1')))
 cumulative=dict(zero); correction=dict(zero)
 values=correction if is_q else cumulative; values.update(limits)
 if sum(limits.values())>m['PRODUCT_TEST_GLOBAL_BYTE_FORECAST' if is_q else 'REMEDIATION_GLOBAL_BYTE_HIGH']:
  veto('owner highs are not simultaneous global spending authority')
  values['integration']-=sum(values.values())-m['PRODUCT_TEST_GLOBAL_BYTE_FORECAST' if is_q else 'REMEDIATION_GLOBAL_BYTE_HIGH']
 f()  # all owners within highs; global exactly at its independent high
 key='PRODUCT_TEST_GLOBAL_BYTE_FORECAST' if is_q else 'REMEDIATION_GLOBAL_BYTE_HIGH'
 ns[key]-=1; veto('independent byte global with all owners within ceilings'); ns[key]+=1
`);
});
test("ADR0335 actual gross added-line bytes charge UTF-8, CRLF, full generated lines and ordinary files", () => {
  assertBudgetProgram(String.raw`
import runpy,subprocess,tempfile
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['_gross_added_line_bytes']; ns=f.__globals__
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory); ns['ROOT']=root
 def git(*args): return subprocess.check_output(['git',*args],cwd=root).decode().strip()
 def put(name,raw): (root/name).write_bytes(raw)
 git('init','-q')
 original={'edit.ts':b'keep\r\nold\r\nremove me\n','no-eof.ts':b'old',
  'from.ts':b'moved\n','copy.ts':b'copied\n','generated.json':b'{"old":1}\n'}
 for name,raw in original.items(): put(name,raw)
 git('add','.'); base=git('write-tree')  # no commit, even in the temporary fixture
 put('edit.ts',b'keep\r\nnew-\xc3\xa9\r\n'); put('no-eof.ts',b'new-\xce\xbb')
 (root/'from.ts').rename(root/'to.ts'); put('copy-new.ts',original['copy.ts'])
 generated=b'{"new":"'+b'x'*20000+b'"}\n'; put('generated.json',generated)
 headerlike=b'++ literal\n@@ -1 +1 @@\n\\ No newline at end of file\n'
 put('headers.ts',headerlike); git('add','.')
 ordinary=b'ordinary-\xce\xbb'; put('ordinary.ts',ordinary)
 names=tuple(sorted(set(original)|{'to.ts','copy-new.ts','headers.ts','ordinary.ts'}))
 expected=len(b'new-\xc3\xa9\r\n')+len(b'new-\xce\xbb')+len(b'moved\n')+len(b'copied\n')
 expected+=len(generated)+len(headerlike)+len(ordinary)
 run=subprocess.run
 def checked_run(args,**kwargs):
  if 'diff' in args and 'check-attr' not in args:
   assert all(flag in args for flag in ('--no-renames','--no-textconv','--no-ext-diff'))
   if '--patch' in args:
    assert all(flag in args for flag in ('--no-color','--unified=3','--numstat','-z','--diff-algorithm=myers','--indent-heuristic'))
   assert base in args and not kwargs.get('text')
  return run(args,**kwargs)
 subprocess.run=checked_run
 # Full added-line bytes, not current net size or deleted bytes, even under copy-detect config.
 git('config','diff.renames','copies')
 assert f(names,base)==expected,(f(names,base),expected)
 assert f(('generated.json',),base)==len(generated)
 assert f(('from.ts',),base)==0 and f((),base)==0
 def veto(names):
  try: f(names,base)
  except m['LineBudgetError']: return
  raise AssertionError(names)
 for raw in (b'\0bad',b'\xffbad'):
  put('binary.ts',raw); git('add','binary.ts'); veto(('binary.ts',))
  put('untracked.ts',raw); veto(('untracked.ts',))
 (root/'linked.ts').symlink_to(root/'edit.ts'); git('add','linked.ts'); veto(('linked.ts',))
 import os
 os.link(root/'edit.ts',root/'hardlink.ts'); git('add','hardlink.ts'); veto(('hardlink.ts',))
 put('.gitignore',b'ignored.ts\n'); put('ignored.ts',b'not free\n'); veto(('ignored.ts',))
`);
});
test("ADR0335 patch accounting cross-checks historical numstat selection, including src/api/server", () => {
  assertBudgetProgram(String.raw`
import runpy,subprocess,tempfile
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['_gross_added_line_bytes']; ns=f.__globals__
name='src/api/server.ts'; q=m['PRODUCT_TEST_Q']; head='252a72c323bad966a7f6a1a81364c379997c5181'
# Fixed historical blobs keep this regression stable through later source work.
old=subprocess.check_output(['git','show',q+':'+name])
new=subprocess.check_output(['git','show',head+':'+name])
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory); ns['ROOT']=root; path=root/name; path.parent.mkdir(parents=True)
 def git(*args): return subprocess.check_output(['git',*args],cwd=root)
 git('init','-q'); path.write_bytes(old); git('add','.'); base=git('write-tree').decode().strip()
 path.write_bytes(new)
 assert git('diff','--numstat',base,'--',name)==b'560\t59\tsrc/api/server.ts\n'
 assert ns['_gross_slice']((name,),lambda p:p==name,base)==560
 assert f((name,),base)==21177
 patch=git('diff','--unified=3',base,'--',name)
 added=[line for line in patch.split(b'\n') if line.startswith(b'+') and not line.startswith(b'+++')]
 assert (len(added),sum(map(len,added)))==(560,21177)
 zero=git('diff','--unified=0',base,'--',name)
 added=[line for line in zero.split(b'\n') if line.startswith(b'+') and not line.startswith(b'+++')]
 assert (len(added),sum(map(len,added)))==(558,21174)  # the original undercharge
 for key,value in (('diff.context','0'),('diff.algorithm','histogram'),('diff.indentHeuristic','false'),('diff.interHunkContext','999')):
  git('config',key,value)
 assert ns['_gross_slice']((name,),lambda p:p==name,base)==560 and f((name,),base)==21177
 # Production cross-check fails closed if patch additions and numstat diverge.
 original=ns['_git_raw']
 ns['_git_raw']=lambda args:original(args).replace(b'560\t59\t',b'559\t59\t',1)
 try: f((name,),base)
 except m['LineBudgetError']: pass
 else: raise AssertionError('numstat/patch mismatch accepted')
`);
});
test("ADR0335 hostile repo, info and global transformations cannot hide raw worktree accounting", () => {
  assertBudgetProgram(String.raw`
import os,runpy,subprocess,tempfile
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['_gross_added_line_bytes']; ns=f.__globals__
with tempfile.TemporaryDirectory() as directory:
 outside=Path(directory); root=outside/'repo'; root.mkdir(); ns['ROOT']=root
 home=outside/'home'; home.mkdir(); marker=outside/'filter-executed'
 os.environ.update(HOME=str(home),XDG_CONFIG_HOME=str(home/'.config'))
 env={k:v for k,v in os.environ.items() if not k.startswith('GIT_')}
 env['GIT_CONFIG_NOSYSTEM']='1'
 def git(*args): return subprocess.check_output(['git',*args],cwd=root,env=env)
 git('init','-q'); path=root/'counted.ts'; path.write_bytes(b'base\n')
 git('add','.'); base=git('write-tree').decode().strip(); config=(root/'.git/config').read_bytes()
 global_attrs=home/'.config/git/attributes'; global_attrs.parent.mkdir(parents=True)
 attributes={'repo':root/'.gitattributes','info':root/'.git/info/attributes','global':global_attrs}
 extra=(b'charged-\xc3\xa9'+b'x'*3000+b'\r\n')*4+b'$Id: must not contract $\n'
 def reset():
  for target in (*attributes.values(),home/'.gitconfig',marker): target.unlink(missing_ok=True)
  (root/'.git/config').write_bytes(config); git('read-tree',base); path.write_bytes(b'base\n'+extra)
 def measured():
  return (ns['_gross_slice'](('counted.ts',),lambda p:p=='counted.ts',base),f(('counted.ts',),base))
 def veto():
  for call in (lambda:ns['_gross_slice'](('counted.ts',),lambda p:True,base),lambda:f(('counted.ts',),base)):
   try: call()
   except m['LineBudgetError']: pass
   else: raise AssertionError('transforming repository attribute accepted')
 for source,target in attributes.items():
  for config_scope in ('--local','--global'):
   reset(); target.write_text('counted.ts filter=hide\n')
   command='touch '+str(marker)+"; printf 'base\\n'"
   git('config',config_scope,'filter.hide.clean',command)
   git('config',config_scope,'filter.hide.required','true')
   # Prove the attack, then exercise both unstaged and already-cleaned index cases.
   assert git('diff','--numstat',base,'--','counted.ts')==b''
   assert marker.exists(); marker.unlink()
   for staged in (False,True):
    if staged:
     git('add','counted.ts')
     assert git('write-tree').decode().strip()==base
     marker.unlink(missing_ok=True)
    if source=='repo': veto()
    else: assert measured()==(5,len(extra)),(source,config_scope,staged,measured())
    assert not marker.exists(),'accounting executed a filter'
 # Reject every transforming repo attribute, macro expansion and deleted-file index fallback.
 for attribute in ('filter=hide','diff=hide','-diff','text','text=auto','eol=lf','crlf','ident','working-tree-encoding=UTF-16'):
  reset(); attributes['repo'].write_text('counted.ts '+attribute+'\n'); veto()
 reset(); attributes['repo'].write_text('[attr]hide filter=hide\ncounted.ts hide\n'); veto()
 git('add','.gitattributes'); attributes['repo'].unlink(); veto()
 # Config and non-repository attributes are ignored, not merely textconv-disabled.
 for source in ('info','global'):
  reset(); attributes[source].write_text('counted.ts text eol=lf ident diff=hide working-tree-encoding=ISO-8859-1\n')
  for scope in ('--local','--global'):
   for key,value in (('core.autocrlf','true'),('core.eol','lf'),('diff.hide.textconv','touch '+str(marker)),
                     ('diff.external','touch '+str(marker)),('diff.algorithm','histogram'),('diff.context','0')):
    git('config',scope,key,value)
  os.environ.update(GIT_CONFIG_COUNT='1',GIT_CONFIG_KEY_0='core.attributesFile',
                    GIT_CONFIG_VALUE_0=str(attributes[source]),GIT_CONFIG_GLOBAL=str(home/'.gitconfig'))
  assert measured()==(5,len(extra)) and not marker.exists()
 reset(); git('update-index','--assume-unchanged','counted.ts')
 assert measured()==(5,len(extra))  # index flags are not raw-byte evidence
 git('update-index','--no-assume-unchanged','--skip-worktree','counted.ts')
 assert measured()==(5,len(extra))
`);
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
root = Path(tempfile.mkdtemp(prefix="cogs-budget-v6-"))
budget.ROOT = root
budget.FINAL_CONTROL_DATA_ROOT = "v6"
budget.FINAL_CONTROL_DATA_MEMBERS = ("v6/a.json", "v6/b.json")
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
    (root / "v6").mkdir(mode=0o700)
    for name in budget.FINAL_CONTROL_DATA_MEMBERS:
        (root / name).write_bytes(b"{}\n")

try:
    assert budget._final_control_data_state()[0] == "absent"

    reset(); write_members(); state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    assert budget._final_control_data_state()[0] == "member-set-complete"

    reset(); write_members(); state["tracked"].add("v6/a.json"); state["ordinary"].add("v6/b.json")
    assert budget._final_control_data_state()[0] == "member-set-complete"

    reset(); state["tracked"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v6/b.json").unlink(); state["tracked"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); state["ordinary"].add("v6/a.json")
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); state["ordinary"].update((*budget.FINAL_CONTROL_DATA_MEMBERS, "v6/extra.json"))
    expect_failure(budget._final_control_data_state)

    reset(); state["ignored"].add("v6/a.json")
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v6/b.json").write_bytes(b"\x00" * 100000)
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v6/b.json").write_bytes(b"not-json\n")
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v6/b.json").write_bytes(b'{"value":NaN}\n')
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); write_members(); (root / "v6/b.json").unlink(); os.link(root / "v6/a.json", root / "v6/b.json")
    state["ordinary"].update(budget.FINAL_CONTROL_DATA_MEMBERS)
    expect_failure(budget._final_control_data_state)

    reset(); outside = root / "outside"; outside.mkdir(); (outside / "a.json").write_bytes(b"{}\n"); (outside / "b.json").write_bytes(b"{}\n")
    (root / "v6").symlink_to(outside, target_is_directory=True)
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
