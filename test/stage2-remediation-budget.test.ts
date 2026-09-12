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

test("ADR0337 preserves protected-squash accounting", () => {
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
assert highs==dict(route=2200,revocation=3000,relay=7000,lifecycle=14000,completion=6200,integration=31000); assert sum(new.values())==200
assert b['global_gross_line_high']==63127 and b['global_gross_byte_high']==26000000 and b['base_revision']=='242bbefeae5444118d9e97b46597130b509ca253'
assert m['FINAL_H_REVISION']=='8907eba3191d07573cd84573cb0b2adddff17bd6'
assert (m['HARD_LIMIT'],m['DEPLOY_CORRECTION_HIGH'],m['RETAINED_CORRECTION_HIGH'],m['WORKFLOW_CORRECTION_HIGH'],m['GLOBAL_CORRECTION_HIGH'],m['MUTABLE_OWNER_LINE_LIMIT'])==(115000,24500,31000,6500,60000,2000)
assert new==dict(route=1,revocation=0,relay=5,lifecycle=10,completion=4,integration=180)
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
assert len(set(paths)-baseline)==116
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
assert b['source_limits']==dict(tracked_files=1620,source_inventory_bytes=45000000,serialized_source_inventory_bytes=262144)
adr0338=Path('docs/adr/0338-plan-pre-h-final-corrections.md').read_text()
for phrase in ('Merging this plan **never authorizes dispatch**', 'Principal separation and external custody are **unimplemented and blocking**', 'unconditionally denied', 'completion_campaign_aws_adapter.py', 'max_attempts=1', 'NotAfter + configured skew', 'versioned S3 backend/object custody', 'DynamoDB conditional journal/lease', 'pause an old operation **after', 'admission**', 'dev/linux-kvm/git-tools.sh', 'exact-head Quality, secret, images', 'regeneration must refresh and pass', 'may not mint credentials/resources', 'OpenBao is deferred and nonblocking **only**', 'No product behavior, full/readiness'):
 assert phrase in adr0338,phrase
# The authorized integration tranche synchronizes implementation, not serialized or per-file bounds.
source_inventory=Path('scripts/stage4-offline-source-inventory.ts').read_text()
for constant in ('MAXIMUM_TRACKED_FILES = 1530;', 'MAXIMUM_AGGREGATE_BYTES = 34_000_000;',
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
ns['_product_test_consumption']=lambda budget:(zero,zero,{}, {},0)
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
test("ADR0338 closes every future path into a named task and validates mutations in an isolated repository", () => {
  assertBudgetProgram(`
import copy,json,runpy,subprocess,tempfile
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['_remediation_budget']; ns=f.__globals__
b,highs,paths,new,forecasts=f(); p=b['product_test_correction']; t=p['remaining_tranche']
assert (b['global_gross_line_high'],b['global_gross_byte_high'])==(63127,26000000)
assert b['source_limits']==dict(tracked_files=1620,source_inventory_bytes=45000000,serialized_source_inventory_bytes=262144)
assert (p['retained_allocation'],p['remediation_retained_allocation'])==({'gross_lines':18000,'gross_bytes':8000000},{'gross_lines':48000,'gross_bytes':11000000})
assert (p['global_gross_line_forecast'],p['global_gross_byte_forecast'])==(33127,23000000)
assert (t['gross_lines'],t['gross_bytes'])==(15127,15000000)
assert [x['name'] for x in t['allocations']]==['pre_h_final_governance','aws_principal_denial_and_cycle_custody','protected_product_and_kvm_contract','generated_readiness_and_no_mint_authorization','final_hgq_control_reserve']
assert [(x['gross_lines'],x['gross_bytes']) for x in t['allocations']]==[(1400,1000000),(4300,4800000),(4000,3200000),(1800,2000000),(3627,4000000)]
assert [(x['pre_h_gross_lines'],x['pre_h_gross_bytes']) for x in t['allocations']]==[(1400,1000000),(4300,4800000),(4000,3200000),(1800,2000000),(1127,1000000)]
assert t['allocations'][-1]['final_minimum_lines']==2500 and t['allocations'][-1]['final_minimum_bytes']==3000000
planned={q:e['name'] for e in p['owners'] for q in e['existing_paths']+e['new_files']}
task_paths={x['name']:set(x['paths']) for x in t['allocations']}
assert set().union(*task_paths.values())==set(planned)
assert sum(map(len,task_paths.values()))==len(planned)
aws=task_paths['aws_principal_denial_and_cycle_custody']
assert {'deploy/aws-feasibility/completion_campaign_aws_adapter.py','test/aws-stage2-completion-campaign-aws-adapter.py','test/aws-stage2-completion-campaign-aws-adapter.test.ts','test/aws-stage2-completion-campaign-aws-provider.py'} <= aws
assert 'dev/linux-kvm/git-tools.sh' in task_paths['protected_product_and_kvm_contract']
assert {'.github/workflows/ci.yml','test/ci-infrastructure-boundary.test.ts'} <= task_paths['pre_h_final_governance']
assert {'deploy/aws-feasibility/versions.tf','deploy/aws-feasibility/run-runtime-validation.sh','deploy/aws-feasibility/run-measurement-campaign.sh','deploy/aws-feasibility/run-measurement-validation.sh','deploy/aws-feasibility/remote/validate-runtime.sh'} <= aws
legacy_shells={'deploy/aws-feasibility/'+path for path in ('apply.sh','destroy.sh','inventory.sh','plan.sh','recover-production-campaign-entry.sh','recover-production-campaign.sh','run-measurement-campaign.sh','run-measurement-validation.sh','run-production-campaign.sh','run-production-effect.sh','run-production-inventory.sh','run-production-remote.sh','run-runtime-validation.sh','validate.sh','remote/measure-runtime.sh','remote/recover-stage2-completion-remote.sh','remote/run-stage2-completion-full-rehearsal.sh','remote/run-stage2-completion-full.sh','remote/run-stage2-completion-readiness-rehearsal.sh','remote/run-stage2-completion-readiness.sh','remote/run-stage2-completion-remote.sh','remote/validate-runtime.sh')}
assert {path for path in aws if path.startswith('deploy/aws-feasibility/') and path.endswith('.sh')}==legacy_shells
assert 'scripts/stage4-offline-readiness-regenerate.ts' in task_paths['generated_readiness_and_no_mint_authorization']
final=task_paths['final_hgq_control_reserve']
mirrors={'.github/workflows/'+name+'.yml' for name in ('stage2-prebuilt-rootfs-producer','stage2-prebuilt-rootfs-diagnostic-producer','stage2-prebuilt-rootfs-publisher','stage2-prebuilt-rootfs-diagnostic-publisher','stage2-local-static-control-prebuilt-candidate','stage2-prebuilt-mixed-hg-preflight','stage2-prebuilt-local-kata-qualification','stage2-prebuilt-kvm-rehearsal','stage2-prebuilt-kvm-integration-diagnostic','stage2-production-plan','stage2-production-approval','stage2-production-campaign')}
assert mirrors <= final
assert sum('/stage2-completion-local-control-v8/' in name for name in final)==13
assert {'biome.json','scripts/check-stage2-retained-lines.py','test/stage2-remediation-budget.test.ts','scripts/prepare-stage2-fixed-source.py','scripts/stage2-hosted-opt-mode.py','scripts/stage2-local-settlement.py','scripts/stage2-native-settlement.py','scripts/stage2-prebuilt-kvm-diagnostic-lock.py','scripts/stage2-prebuilt-local-qualification-guard.py','scripts/stage2-prebuilt-rootfs-producer.py','scripts/stage2-prebuilt-rootfs-publisher.py','scripts/stage2-prebuilt-static-control-runtime-boundary.py','scripts/stage2-stage-prebuilt-control.py','deploy/aws-feasibility/remote/completion_kata_preparation.py','deploy/aws-feasibility/remote/completion_formal_cycle_authority.py','deploy/aws-feasibility/remote/completion_formal_cycle_full.py','deploy/aws-feasibility/remote/completion_formal_cycle_readiness.py','schemas/stage2-formal-local-cycle-receipt-v2.json','test/stage2-prebuilt-local-kata-workflow.test.ts','test/stage2-prebuilt-static-control-runtime-boundary.py'} <= final
assert task_paths['final_hgq_control_reserve']==set(m['PRODUCT_TEST_TASK_PATHS']['final_hgq_control_reserve'])
assert {'schemas/aws-stage2-production-principal-contract-v1.json','schemas/aws-stage2-production-custody-v1.json'} <= set(planned)
# A detached worktree retains the real historical objects and path semantics. Its
# unchanged copied fixture must pass before each isolated mutation is attempted.
original={key:ns[key] for key in ('ROOT','REMEDIATION_BUDGET_PATH','SOURCE_INVENTORY_PRODUCER')}
with tempfile.TemporaryDirectory() as d:
 fixture=Path(d)/'fixture'
 subprocess.run(['git','worktree','add','--detach','--quiet',str(fixture),'HEAD'],check=True)
 try:
  path=fixture/'config/external-review-remediation-budget-v1.json'; path.write_text(json.dumps(b))
  ns['ROOT']=fixture; ns['REMEDIATION_BUDGET_PATH']=path; ns['SOURCE_INVENTORY_PRODUCER']=fixture/'scripts/stage4-offline-source-inventory.ts'
  f()  # valid isolated fixture
  def veto(kind,bad):
   path.write_text(json.dumps(bad))
   try: f()
   except m['LineBudgetError']: return
   raise AssertionError(kind+' mutation accepted')
  for kind in ('path','owner','reserve','pre_h','minimum','source'):
   bad=copy.deepcopy(b)
   if kind=='path': bad['product_test_correction']['remaining_tranche']['allocations'][1]['paths'].remove('deploy/aws-feasibility/completion_campaign_aws_adapter.py')
   elif kind=='owner': bad['product_test_correction']['owners'][5]['existing_paths'].remove('scripts/stage2-production-planner.py')
   elif kind=='reserve': bad['product_test_correction']['remaining_tranche']['allocations'][4]['gross_lines']+=1
   elif kind=='pre_h': bad['product_test_correction']['remaining_tranche']['allocations'][4]['pre_h_gross_lines']+=1
   elif kind=='minimum': bad['product_test_correction']['remaining_tranche']['allocations'][4]['final_minimum_lines']-=1
   else: bad['source_limits']['tracked_files']-=1
   veto(kind,bad); path.write_text(json.dumps(b)); f()
 finally:
  ns.update(original)
  subprocess.run(['git','worktree','remove','--force',str(fixture)],check=True)
`);
});
test("ADR0338 retained plus task ceilings reject exact +1 line and byte overruns", () => {
  assertBudgetProgram(`
import runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); b,_,_,_,_=m['_remediation_budget'](); f=m['_product_test_consumption']; ns=f.__globals__
p=b['product_test_correction']; planned={path:entry['name'] for entry in p['owners'] for path in (*entry['existing_paths'],*entry['new_files'])}
tasks={task['name']:m['_product_test_task_paths'](task['name'],planned) for task in p['remaining_tranche']['allocations']}
head='f'*40; ns['_git']=lambda args: head if args==['rev-parse','HEAD'] else ''
ns['_product_test_linear_commits']=lambda current: (); ns['_product_test_changes']=lambda revision,target=None:set(planned)
def run(extra_lines=0,extra_bytes=0):
 def charge(names,field):
  names=tuple(names)
  for task in p['remaining_tranche']['allocations']:
   limit=task['pre_h_'+field]
   if names==tasks[task['name']]: return limit+(extra_lines if field=='gross_lines' else extra_bytes)
   for allocation in task['owner_allocations']:
    owner_names=tuple(path for path in tasks[task['name']] if planned[path]==allocation['name'])
    if names==owner_names: return limit if task['name']=='final_hgq_control_reserve' else allocation[field]
  for owner in p['owners']:
   owner_names=tuple(owner['existing_paths']+owner['new_files'])
   if names==owner_names:
    return sum((task['pre_h_'+field] if task['name']=='final_hgq_control_reserve' else allocation[field])
               for task in p['remaining_tranche']['allocations'] for allocation in task['owner_allocations']
               if allocation['name']==owner['name'])
  return 0
 ns['_gross_slice']=lambda names,*ignored:charge(names,'gross_lines')
 ns['_gross_added_line_bytes']=lambda names,*ignored:charge(names,'gross_bytes')
 return f(b)
assert run()[0]['integration']==10227 and run()[1]['integration']==10100000
for lines,raw in ((1,0),(0,1)):
 try: run(lines,raw)
 except m['LineBudgetError']: pass
 else: raise AssertionError('task +1 accepted')
`);
});
test("ADR0337 protected-squash real-git lineage and gross-charge regressions fail closed", () => {
  assertBudgetProgram(String.raw`
import runpy,subprocess,tempfile
from pathlib import Path
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); ns=m['_product_test_linear_commits'].__globals__
def git(root,*args): return subprocess.check_output(['git',*args],cwd=root,text=True).strip()
def commit(root,message): git(root,'add','.'); git(root,'commit','-qm',message); return git(root,'rev-parse','HEAD')
def veto(call):
 try: call()
 except m['LineBudgetError']: return
 raise AssertionError('unauthorized history accepted')
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory); git(root,'init','-q','-b','main'); git(root,'config','user.email','test@example.invalid'); git(root,'config','user.name','test')
 (root/'governance.ts').write_text('base\n'); q=commit(root,'base'); (root/'governance.ts').write_text('one\n'); one=commit(root,'one'); (root/'governance.ts').write_text('two\n'); two=commit(root,'two'); (root/'governance.ts').unlink(); gone=commit(root,'delete')
 ns['ROOT']=root; ns['PRODUCT_TEST_Q']=q
 assert list(m['_product_test_linear_commits'](gone))==[(q,one),(one,two),(two,gone)]
 assert sum(m['_gross_slice'](('governance.ts',),lambda p:p=='governance.ts',a,b) for a,b in ((q,one),(one,two),(two,gone)))==2
 assert sum(m['_gross_added_line_bytes'](('governance.ts',),a,b) for a,b in ((q,one),(one,two),(two,gone)))==8
 (root/'governance.ts').write_text('two\n'); first=(m['_gross_slice'](('governance.ts',),lambda p:p=='governance.ts',gone),m['_gross_added_line_bytes'](('governance.ts',),gone)); assert first==(1,4)==(m['_gross_slice'](('governance.ts',),lambda p:p=='governance.ts',gone),m['_gross_added_line_bytes'](('governance.ts',),gone))
 git(root,'reset','--hard','-q'); git(root,'clean','-fdq'); git(root,'checkout','-q','main'); git(root,'checkout','-qb','side',q); (root/'unauthorized.ts').write_text('no\n'); side=commit(root,'unauthorized'); git(root,'checkout','-q','main'); git(root,'merge','--no-ff','-qm','merge',side); veto(lambda:list(m['_product_test_linear_commits'](git(root,'rev-parse','HEAD'))))
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory); git(root,'init','-q'); git(root,'config','user.email','test@example.invalid'); git(root,'config','user.name','test'); (root/'allowed.ts').write_text('base\n'); q=commit(root,'base'); (root/'unauthorized.ts').write_text('no\n'); bad=commit(root,'bad'); (root/'unauthorized.ts').unlink(); head=commit(root,'revert')
 ns['ROOT']=root; ns['PRODUCT_TEST_Q']=q
 assert m['_product_test_changes'](q,bad)=={'unauthorized.ts'} and m['_product_test_changes'](bad,head)=={'unauthorized.ts'}
 veto(lambda:m['_require'](m['_product_test_changes'](q,bad)<={'allowed.ts'}))
`);
});
test("ADR0335 actual current integrated worktree passes the unmocked central budget gate", () => {
  const result = spawnSync("python3", ["-I", "-B", "scripts/check-stage2-retained-lines.py"], {
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.equal(result.status, 0, result.stderr || "actual integrated budget rejected");
  const report = JSON.parse(result.stdout);
  const consumedProductLines = Object.values(report.product_test_workstream_gross_added_lines).reduce<number>(
    (sum, value) => sum + Number(value),
    0,
  );
  assert.ok(report.conservative_lines_no_deletion_credit >= 99_463);
  assert.ok(consumedProductLines <= 15_127);
  assert.ok(report.conservative_lines_no_deletion_credit + (15_127 - consumedProductLines) < report.hard_limit);
  assert.deepEqual(report.product_test_final_hgq_minimum, { lines: 2500, bytes: 3000000 });
  for (const kind of ["lines", "line_bytes"] as const) {
    const consumed = report[`product_test_task_gross_added_${kind}`];
    const maxima = report[`product_test_task_pre_h_${kind === "lines" ? "line" : "byte"}_maxima`];
    const remaining = report[`product_test_task_remaining_${kind}`];
    for (const task of Object.keys(maxima)) assert.ok(consumed[task] <= maxima[task], `${task}:${kind}`);
    assert.ok(
      remaining.final_hgq_control_reserve >=
        report.product_test_final_hgq_minimum[kind === "lines" ? "lines" : "bytes"],
    );
  }
  for (const key of [
    "correction_slice_limits_satisfied",
    "post_h_reserve_limits_satisfied",
    "remediation_limits_satisfied",
    "hard_satisfied",
    "mutable_owner_line_limit_satisfied",
  ])
    assert.equal(report[key], true, key);
  for (const [kind, limit] of [
    ["lines", 33127],
    ["line_bytes", 23000000],
  ] as const) {
    const usage = report[`product_test_workstream_gross_added_${kind}`];
    assert.equal(usage.route, 0);
    assert.equal(usage.revocation, 0);
    for (const owner of ["relay", "lifecycle", "completion", "integration"]) assert.ok(usage[owner] >= 0, owner);
    const total = Object.values(usage).reduce<number>((sum, value) => sum + Number(value), 0);
    assert.equal(report[`product_test_gross_added_${kind}_no_deletion_credit`], total);
    assert.ok(total <= limit, `${kind}: ${total}/${limit}`);
  }
});
test("ADR0335 independent correction, hard and Q-relative limits reject isolated overruns", () => {
  assertBudgetProgram(`
import copy,runpy
m=runpy.run_path('scripts/check-stage2-retained-lines.py'); f=m['measure']; ns=f.__globals__
b,highs,paths,new,forecasts=m['_remediation_budget'](); zero={o:0 for o in highs}
ns['_remediation_gross']=lambda:(zero,zero,b,forecasts)
ns['_product_test_gross']=lambda budget:zero
ns['_product_test_consumption']=lambda budget:(zero,zero,{}, {},0)
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
remediation=dict(highs)
assert sum(highs.values())==63400>b['global_gross_line_high']
remediation['integration']-=273
assert sum(remediation.values())==63127
assert f()['remediation_gross_added_lines_no_deletion_credit']==63127
ns['_remediation_gross']=lambda:(zero,zero,b,forecasts)
base=dict(deploy=21948,retained=11844,workflow=4836)
for key,limit in [('deploy',24500),('retained',31000),('workflow',6500)]:
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
# The first-parent tranche, task closure, and mutation cases are ADR0336-tested above.
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
changed='scripts/stage2-production-planner.py\0'
def git(args):
 if 'diff' in args and m['PRODUCT_TEST_Q'] in args:
  assert '--name-only' in args and '-z' in args
  return changed
 if args==['ls-files','--others','--exclude-standard','-z','--','.']: return ''
 return original_git(args)
ns['_git']=git
expected=dict(route=0,revocation=0,relay=11,lifecycle=0,completion=0,integration=44)
values=dict(expected)
ns['_product_test_consumption']=lambda budget:(dict(values),zero,{}, {},0)
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
assert report['product_test_base_revision']=='eda2dc499153f3053772790c02ea6d332403742e'
assert report['product_test_workstream_gross_added_lines']==expected
assert report['product_test_gross_added_lines_no_deletion_credit']==55
assert report['product_test_global_gross_line_forecast']==33127
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
assert m['PRODUCT_TEST_GLOBAL_BYTE_FORECAST']==23000000 and m['REMEDIATION_GLOBAL_BYTE_HIGH']==26000000
cumulative=dict(route=1,revocation=2,relay=3,lifecycle=4,completion=5,integration=6)
correction=dict(route=0,revocation=0,relay=7,lifecycle=8,completion=9,integration=10)
ns['_product_test_consumption']=lambda budget:(zero,dict(correction),{}, {},0)
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
assert report['product_test_global_gross_byte_forecast']==23000000
assert report['product_test_workstream_gross_byte_forecasts']==m['PRODUCT_TEST_BYTE_FORECASTS']
def veto(label):
 try: f()
 except m['LineBudgetError']: return
 raise AssertionError(label+' bypassed by central measure')
for is_q in (False,):
 limits=m['PRODUCT_TEST_BYTE_FORECASTS' if is_q else 'REMEDIATION_BYTE_HIGHS']
 for owner,high in limits.items():
  cumulative=dict(zero); correction=dict(zero)
  values=correction if is_q else cumulative; values[owner]=high
  assert f()['remediation_gross_added_lines_no_deletion_credit']==0
  values[owner]+=1
  assert sum(values.values())<(23000000 if is_q else 26000000)
  veto(str((is_q,owner,'isolated byte high+1')))
 cumulative=dict(zero); correction=dict(zero)
 values=correction if is_q else cumulative; values.update(limits)
 key='PRODUCT_TEST_GLOBAL_BYTE_FORECAST' if is_q else 'REMEDIATION_GLOBAL_BYTE_HIGH'
 original_global=ns[key]; ns[key]=sum(values.values())
 f()  # all owners within highs; synthetic global exactly at its independent high
 ns[key]-=1; veto('independent byte global with all owners within ceilings'); ns[key]=original_global
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
name='src/api/server.ts'; q='8ddd4c3164bae32dbe02c67d2ee9b82eb8315a38'; head='eda2dc499153f3053772790c02ea6d332403742e'
# Fixed historical blobs keep this regression stable through later source work.
old=subprocess.check_output(['git','show',q+':'+name])
new=subprocess.check_output(['git','show',head+':'+name])
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory); ns['ROOT']=root; path=root/name; path.parent.mkdir(parents=True)
 def git(*args): return subprocess.check_output(['git',*args],cwd=root)
 git('init','-q'); path.write_bytes(old); git('add','.'); base=git('write-tree').decode().strip()
 path.write_bytes(new)
 assert git('diff','--numstat',base,'--',name)==b'578\t69\tsrc/api/server.ts\n'
 assert ns['_gross_slice']((name,),lambda p:p==name,base)==578
 assert f((name,),base)==21883
 patch=git('diff','--unified=3',base,'--',name)
 added=[line for line in patch.split(b'\n') if line.startswith(b'+') and not line.startswith(b'+++')]
 assert (len(added),sum(map(len,added)))==(578,21883)
 zero=git('diff','--unified=0',base,'--',name)
 added=[line for line in zero.split(b'\n') if line.startswith(b'+') and not line.startswith(b'+++')]
 assert (len(added),sum(map(len,added)))==(576,21880)  # the original undercharge
 for key,value in (('diff.context','0'),('diff.algorithm','histogram'),('diff.indentHeuristic','false'),('diff.interHunkContext','999')):
  git('config',key,value)
 assert ns['_gross_slice']((name,),lambda p:p==name,base)==578 and f((name,),base)==21883
 # Production cross-check fails closed if patch additions and numstat diverge.
 original=ns['_git_raw']
 ns['_git_raw']=lambda args:original(args).replace(b'578\t69\t',b'577\t69\t',1)
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
