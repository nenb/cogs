import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

test("AWS fixture is pinned to one CPU-only nested-virtualization host", () => {
  const versions = read("deploy/aws-feasibility/versions.tf");
  const main = read("deploy/aws-feasibility/main.tf");
  const variables = read("deploy/aws-feasibility/variables.tf");
  assert.match(versions, /required_version = "= 1\.12\.4"/);
  assert.match(versions, /version = "= 6\.54\.0"/);
  assert.equal((main.match(/resource "aws_instance"/g) ?? []).length, 1);
  assert.match(variables, /var\.instance_type == "c8i-flex\.large"/);
  assert.match(main, /nested_virtualization = "enabled"/);
  assert.match(main, /core_count\s+= 1/);
  assert.match(main, /threads_per_core\s+= 2/);
  assert.doesNotMatch(main, /resource "aws_(?:eks|nat_gateway|eip|lb|efs|autoscaling|spot_fleet|sagemaker)/);
});

test("AWS fixture has no inbound rule and requires three independent termination controls", () => {
  const main = read("deploy/aws-feasibility/main.tf");
  assert.doesNotMatch(main, /\bingress\s*\{/);
  assert.match(main, /action_after_completion\s+= "DELETE"/);
  assert.match(main, /ec2:terminateInstances/);
  assert.match(main, /schedule-group\/default/);
  assert.doesNotMatch(main, /schedule\/default\/\$\{local\.name\}-terminate/);
  assert.match(main, /instance_initiated_shutdown_behavior = "terminate"/);
  assert.match(main, /shutdown -P \+220/);
  assert.match(main, /limit_amount = "20"/);
});

test("AWS runtime validation requires active KVM and a distinct root Kata guest", () => {
  const remote = read("deploy/aws-feasibility/remote/validate-runtime.sh");
  const controller = read("deploy/aws-feasibility/run-runtime-validation.sh");
  assert.match(remote, /qemu-system-x86_64 -S -nodefaults -display none -machine accel=kvm/);
  assert.match(remote, /query-kvm/);
  assert.match(remote, /'enabled': True, 'present': True/);
  assert.match(remote, /kata_version=3\.32\.0/);
  assert.match(remote, /kata-static-\$kata_version-amd64\.tar\.zst/);
  assert.match(remote, /1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01/);
  assert.match(remote, /containerd-shim-kata-v2/);
  assert.match(remote, /--runtime io\.containerd\.kata\.v2/);
  assert.match(remote, /--runtime-config-path "\$config"/);
  assert.match(remote, /--rootfs --read-only "\$rootfs"/);
  assert.doesNotMatch(remote, /kata-runtime .* run|--bundle|runc spec/);
  assert.match(remote, /guest_uid.*== 0/);
  assert.match(remote, /guest_kernel.*!=.*host_kernel/);
  assert.doesNotMatch(remote, /accel=tcg|--runtime.*runc/);
  assert.match(remote, /cogs-stage2-failure-stage=/);
  assert.match(remote, /cogs-stage2-bounded-diagnostic=/);
  assert.match(remote, /tail -c 2048/);
  assert.match(controller, /runtime-failure\.json/);
  assert.match(controller, /runtime-command-id\.txt/);
  assert.match(controller, /timeout 2700/);
  assert.match(controller, /nested_virtualization.*enabled/);
});

test("Stage 2 decision package is accepted, bounded, and redacted", () => {
  const report = read("docs/test-reports/stage-2-aws-feasibility.md");
  const adr = read("docs/adr/0012-use-aws-virtual-nested-kvm-for-stage-4-candidate.md");
  const index = read("docs/adr/README.md");
  assert.match(adr, /Status: Accepted/);
  assert.match(adr, /Accepted by: Nick Byrne on 2026-07-14/);
  assert.match(index, /0012.*Accepted/);
  assert.doesNotMatch(adr, /Status: Proposed/);
  assert.match(report, /2036bb7d0e115bba2fa4b84f875e657559243c80/);
  assert.match(report, /6e42a6df1ceff65f3b45a9805d91cdce5fbd7a5fb775789fe56c4ebe4a2466be/);
  assert.match(report, /c8i-flex\.large/);
  assert.match(report, /ami-052355af2a014bd2c/);
  assert.match(report, /QMP KVM present \/ enabled\s*\| `true` \/ `true`/);
  assert.match(report, /Kata boot\s*\| 2,097 ms/);
  assert.match(report, /campaign-scoped SSM instance profile/);
  assert.doesNotMatch(report, /digest-bound validation script|integration credentials, AWS credentials/);
  assert.match(report, /does not currently record or verify a separate script digest/);
  for (const pr of ["47", "48", "49", "50", "51"]) {
    assert.match(report + adr, new RegExp(`PR #${pr}`));
  }
  assert.match(report, /15 partial resources/);
  assert.match(report, /destroyed 16 resources/);
  assert.match(report, /containerd v2\.2\.1/);
  assert.match(
    report + adr,
    /github\.com\/containerd\/containerd\/blob\/v2\.2\.1\/cmd\/ctr\/commands\/run\/run_unix\.go/,
  );
  assert.doesNotMatch(report + adr, /containerd release\/1\.7|blob\/release\/1\.7/);
  assert.match(report, /were skipped on that PR and are not the authoritative AWS campaign evidence/);
  assert.match(report, /total `0`/);
  assert.match(report, /not release evidence for EKS, production, general availability/);
  assert.match(adr, /Mandatory Stage 4 reruns and qualifications/);
  assert.doesNotMatch(
    report + adr,
    /\b\d{12}\b|\bi-[0-9a-f]{8,}\b|\bvpc-[0-9a-f]{8,}\b|\bsubnet-[0-9a-f]{8,}\b|\bsg-[0-9a-f]{8,}\b|\blt-[0-9a-f]{8,}\b|\b[0-9a-f-]{36}\b|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i,
  );
});

test("Stage 2 measurement harness is bounded, redacted, and does not widen AWS scope", () => {
  const remote = read("deploy/aws-feasibility/remote/measure-runtime.sh");
  const controller = read("deploy/aws-feasibility/run-measurement-validation.sh");
  const schema = read("schemas/aws-stage2-measurement-evidence-v1alpha1.json");
  const validator = read("scripts/validate-aws-stage2-measurement-report.ts");
  const renderer = read("scripts/render-aws-stage2-measurement-report.ts");
  const orchestrator = read("deploy/aws-feasibility/run-measurement-campaign.sh");
  const readme = read("deploy/aws-feasibility/README.md");
  const plan = read("docs/test-reports/stage-2-measurement-plan.md");
  assert.match(remote, /COGS_STAGE2_MEASUREMENT_SAMPLES:-7/);
  assert.match(remote, /samples.*-ge 5.*samples.*-le 9/);
  assert.match(remote, /--runtime io\.containerd\.kata\.v2 --runtime-config-path "\$config" --rootfs --read-only/);
  assert.match(remote, /kata_cold_boot/);
  assert.match(remote, /warm_cpu_workload/);
  assert.match(remote, /warm_filesystem_workload/);
  assert.match(remote, /host_git_baseline/);
  assert.match(remote, /host_package_build_baseline/);
  assert.match(remote, /\/bin\/busybox find/);
  assert.match(remote, /ctr --namespace cogs-stage2 tasks exec/);
  assert.match(remote, /Path\('\/proc'\)[\s\S]*exe/);
  assert.match(remote, /assert_qemu_baseline/);
  assert.match(remote, /tasks rm/);
  assert.match(remote, /configured_guest_memory_mib/);
  assert.match(remote, /density_estimate/);
  assert.match(remote, /SSM readiness has one sample per campaign; SSH-ready is not measured/);
  assert.match(controller, /stage2-measurement-evidence\.json/);
  assert.doesNotMatch(controller, /render-aws-stage2-measurement-report/);
  assert.match(controller, /timeout 2700/);
  assert.match(controller, /refusing to send measurement script from a dirty tree/);
  assert.match(controller, /apply_to_running_ms/);
  assert.match(controller, /apply_to_ssm_online_ms/);
  assert.match(controller, /estimated_cost_usd/);
  assert.match(orchestrator, /trap cleanup EXIT/);
  assert.match(orchestrator, /trap 'interrupt 130' INT/);
  assert.match(orchestrator, /trap 'interrupt 143' TERM/);
  assert.doesNotMatch(orchestrator, /trap cleanup EXIT INT TERM/);
  assert.match(orchestrator, /final-zero-resource-inventory\.json/);
  assert.match(schema, /cogs\.aws-stage2-measurement-evidence\/v1alpha1/);
  assert.match(validator, /sample count mismatch/);
  assert.match(validator, /ratio mismatch/);
  assert.match(validator, /memory density bound mismatch/);
  assert.match(renderer, /not EKS, production, release, general availability/);
  assert.match(readme + plan, /does not claim repeated EC2 launch p50\/p95[, or ]+SSH-ready timing/);
  assert.match(readme + plan, /issue #42 must stay open|Issue #42 must remain open/);
  assert.doesNotMatch(
    remote + controller + orchestrator,
    /aws ec2 run-instances|start-instances|aws eks|create-cluster|nat-gateway|allocate-address|create-load-balancer|create-file-system/i,
  );
});

const validStage2MeasurementEvidence = () => ({
  version: "cogs.aws-stage2-measurement-evidence/v1alpha1",
  authority: "aws-feasibility",
  result: "pass",
  source_revision: "0123456789abcdef0123456789abcdef01234567",
  region: "us-east-1",
  expires_at: "2026-07-14T20:00:00Z",
  launch: {
    instance_type: "c8i-flex.large",
    image_id: "ami-052355af2a014bd2c",
    architecture: "x86_64",
    imds_v2: true,
    nested_virtualization: "enabled",
    vcpu: 2,
    memory_mib: 4096,
    bare_metal: false,
    gpu: false,
  },
  campaign: {
    sample_count: 5,
    observed_duration_ms: 1_000_000,
    apply_to_running_ms: 100_000,
    apply_to_ssm_online_ms: 200_000,
    cleanup_observed: true,
    final_zero_inventory_total: 0,
    estimated_cost_usd: 0.027,
    cost_basis: "observed apply-start through destroy-complete duration; not SSH-ready timing",
  },
  measurement: {
    version: "cogs.aws-stage2-measurement-result/v1alpha1",
    result: "pass",
    host_kernel: "6.17.0-1019-aws",
    guest_kernel: "6.18.35",
    guest_root: true,
    cpu_vmx: true,
    kvm_device: true,
    qmp_kvm_present: true,
    qmp_kvm_enabled: true,
    containerd_version: "containerd 2.2.1",
    qemu_version: "QEMU emulator version 10.1.2",
    kata_runtime_version: "kata-runtime 3.32.0",
    kata_archive_sha256: "1449ecea50bd91fa73a94648db195d18950fe869ba4b1f12d05f55f1fa7c1b01",
    package_setup_ms: 31_000,
    measurement_duration_ms: 900_000,
    kata_cold_boot: { samples: [100, 110, 120, 130, 140], min_ms: 100, p50_ms: 120, p95_ms: 140, max_ms: 140 },
    warm_cpu_workload: {
      host: { samples: [50, 60, 70, 80, 90], min_ms: 50, p50_ms: 70, p95_ms: 90, max_ms: 90 },
      kata: { samples: [100, 120, 140, 160, 180], min_ms: 100, p50_ms: 140, p95_ms: 180, max_ms: 180 },
      kata_to_host_p50_ratio: 2,
    },
    warm_filesystem_workload: {
      host: { samples: [60, 70, 80, 90, 100], min_ms: 60, p50_ms: 80, p95_ms: 100, max_ms: 100 },
      kata: { samples: [90, 105, 120, 135, 150], min_ms: 90, p50_ms: 120, p95_ms: 150, max_ms: 150 },
      kata_to_host_p50_ratio: 1.5,
    },
    host_git_baseline: { samples: [40, 50, 60, 70, 80], min_ms: 40, p50_ms: 60, p95_ms: 80, max_ms: 80 },
    host_package_build_baseline: {
      samples: [200, 220, 240, 260, 280],
      min_ms: 200,
      p50_ms: 240,
      p95_ms: 280,
      max_ms: 280,
    },
    idle_memory: { qemu_rss_mib: 512, configured_guest_memory_mib: 2048, memory_basis_mib: 2048 },
    density_estimate: {
      basis:
        "min(memory_bound_after_1024_mib_host_reserve_using_max(qemu_rss,configured_guest_memory), cpu_bound_host_vcpus_per_configured_guest_vcpu)",
      host_vcpus: 2,
      configured_guest_vcpus: 1,
      memory_bound_sandboxes: 1,
      cpu_bound_sandboxes: 2,
      bounded_estimate_sandboxes: 1,
    },
  },
  limitations: [
    "single EC2 host campaign; EC2 launch p50/p95 requires multiple launches and is not measured by this harness",
    "SSM readiness has one sample per campaign; SSH-ready is not measured because Stage 2 access is SSM-only",
    "Git and package-build measurements are host baselines only; representative sandbox Git/build/package workload acceptance remains unmet by this evidence",
    "density estimate is a conservative bound, not a scheduler or isolation claim",
  ],
});

test("Stage 2 measurement validator accepts valid evidence and rejects adversarial evidence", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "cogs-stage2-measurement-"));
  const validPath = resolve(directory, "valid.json");
  writeFileSync(validPath, `${JSON.stringify(validStage2MeasurementEvidence())}\n`);
  execFileSync("npx", ["--no-install", "tsx", "scripts/validate-aws-stage2-measurement-report.ts", validPath], {
    cwd: root,
  });

  const badStats = validStage2MeasurementEvidence();
  badStats.measurement.kata_cold_boot.p95_ms = 130;
  const badStatsPath = resolve(directory, "bad-stats.json");
  writeFileSync(badStatsPath, `${JSON.stringify(badStats)}\n`);
  assert.throws(() =>
    execFileSync("npx", ["--no-install", "tsx", "scripts/validate-aws-stage2-measurement-report.ts", badStatsPath], {
      cwd: root,
    }),
  );

  const badRedaction = validStage2MeasurementEvidence();
  badRedaction.limitations.push("operator contact stage2@example.com");
  const badRedactionPath = resolve(directory, "bad-redaction.json");
  writeFileSync(badRedactionPath, `${JSON.stringify(badRedaction)}\n`);
  assert.throws(() =>
    execFileSync(
      "npx",
      ["--no-install", "tsx", "scripts/validate-aws-stage2-measurement-report.ts", badRedactionPath],
      { cwd: root },
    ),
  );

  const badDensity = validStage2MeasurementEvidence();
  badDensity.measurement.idle_memory.memory_basis_mib = 512;
  const badDensityPath = resolve(directory, "bad-density.json");
  writeFileSync(badDensityPath, `${JSON.stringify(badDensity)}\n`);
  assert.throws(() =>
    execFileSync("npx", ["--no-install", "tsx", "scripts/validate-aws-stage2-measurement-report.ts", badDensityPath], {
      cwd: root,
    }),
  );

  const provisional = validStage2MeasurementEvidence();
  provisional.campaign.cleanup_observed = false;
  provisional.campaign.final_zero_inventory_total = -1;
  const provisionalPath = resolve(directory, "provisional.json");
  writeFileSync(provisionalPath, `${JSON.stringify(provisional)}\n`);
  execFileSync(
    "npx",
    ["--no-install", "tsx", "scripts/validate-aws-stage2-measurement-report.ts", "--provisional", provisionalPath],
    {
      cwd: root,
    },
  );
  assert.throws(() =>
    execFileSync("npx", ["--no-install", "tsx", "scripts/validate-aws-stage2-measurement-report.ts", provisionalPath], {
      cwd: root,
    }),
  );
});

const makeOrchestratorFixture = (mode: string) => {
  const fixtureRoot = mkdtempSync(resolve(tmpdir(), `cogs-stage2-orchestrator-${mode}-`));
  const directory = resolve(fixtureRoot, "deploy/aws-feasibility");
  mkdirSync(resolve(directory, ".state"), { recursive: true });
  cpSync(
    resolve(root, "deploy/aws-feasibility/run-measurement-campaign.sh"),
    resolve(directory, "run-measurement-campaign.sh"),
  );
  chmodSync(resolve(directory, "run-measurement-campaign.sh"), 0o755);
  execFileSync("git", ["init", "-q"], { cwd: fixtureRoot });
  execFileSync("git", ["config", "user.email", "test@example.invalid"], { cwd: fixtureRoot });
  execFileSync("git", ["config", "user.name", "test"], { cwd: fixtureRoot });
  writeFileSync(resolve(fixtureRoot, "README.md"), "fixture\n");
  execFileSync("git", ["add", "."], { cwd: fixtureRoot });
  execFileSync("git", ["commit", "-q", "-m", "fixture"], { cwd: fixtureRoot });
  const log = resolve(directory, ".state/log");
  const stub = (name: string, body: string) => {
    writeFileSync(
      resolve(directory, name),
      `#!/usr/bin/env bash\nset -euo pipefail\necho ${name} >> ${JSON.stringify(log)}\n${body}\n`,
    );
    chmodSync(resolve(directory, name), 0o755);
  };
  stub("plan.sh", "exit 0");
  stub("apply.sh", "exit 0");
  stub(
    "run-measurement-validation.sh",
    mode === "measurement-fails"
      ? "exit 43"
      : `cat > ${JSON.stringify(resolve(directory, ".state/campaign-timing.json"))} <<'JSON'\n{"apply_started_at":"2026-07-14T00:00:00Z"}\nJSON\ncat > ${JSON.stringify(resolve(directory, ".state/stage2-measurement-evidence.json"))} <<'JSON'\n{"campaign":{"observed_duration_ms":1,"cleanup_observed":false,"final_zero_inventory_total":-1,"estimated_cost_usd":0,"cost_basis":"provisional"}}\nJSON`,
  );
  stub("destroy.sh", mode === "destroy-fails" ? "exit 44" : "exit 0");
  stub(
    "inventory.sh",
    mode === "nonzero-inventory" ? "printf '%s\\n' '{\"total\":1}'; exit 0" : "printf '%s\\n' '{\"total\":0}'; exit 0",
  );
  const validator = resolve(directory, "validator.sh");
  writeFileSync(
    validator,
    `#!/usr/bin/env bash\nset -euo pipefail\necho validator:$* >> ${JSON.stringify(log)}\n[[ ${JSON.stringify(mode)} != final-validation-fails ]] || exit 45\n`,
  );
  chmodSync(validator, 0o755);
  const renderer = resolve(directory, "renderer.sh");
  writeFileSync(renderer, `#!/usr/bin/env bash\nset -euo pipefail\necho renderer:$* >> ${JSON.stringify(log)}\n`);
  chmodSync(renderer, 0o755);
  execFileSync("git", ["add", "."], { cwd: fixtureRoot });
  execFileSync("git", ["commit", "-q", "-m", "stubs"], { cwd: fixtureRoot });
  return { fixtureRoot, directory, log, validator, renderer };
};

const runOrchestratorFixture = (mode: string, approved = true) => {
  const fixture = makeOrchestratorFixture(mode);
  const env = {
    ...process.env,
    COGS_AWS_FEASIBILITY_DIRECTORY: fixture.directory,
    COGS_STAGE2_MEASUREMENT_VALIDATOR: fixture.validator,
    COGS_STAGE2_MEASUREMENT_RENDERER: fixture.renderer,
    ...(approved ? { COGS_AWS_MEASUREMENT_CAMPAIGN_APPROVED: "run-one-stage2-measurement-campaign" } : {}),
  };
  const run = () =>
    execFileSync(resolve(fixture.directory, "run-measurement-campaign.sh"), { cwd: fixture.fixtureRoot, env });
  return { ...fixture, run };
};

test("measurement campaign orchestrator is no-op before approval", () => {
  const fixture = runOrchestratorFixture("success", false);
  assert.throws(fixture.run);
  assert.throws(() => readFileSync(fixture.log, "utf8"));
});

test("measurement campaign orchestrator destroys and finalizes after zero inventory", () => {
  const fixture = runOrchestratorFixture("success");
  fixture.run();
  const log = readFileSync(fixture.log, "utf8");
  assert.match(log, /plan\.sh\napply\.sh\nrun-measurement-validation\.sh\ndestroy\.sh\ninventory\.sh\nvalidator:/);
  assert.match(log, /renderer:/);
});

test("measurement campaign orchestrator destroys on measurement failure", () => {
  const fixture = runOrchestratorFixture("measurement-fails");
  assert.throws(fixture.run);
  const log = readFileSync(fixture.log, "utf8");
  assert.match(log, /run-measurement-validation\.sh\ndestroy\.sh\ninventory\.sh/);
  assert.doesNotMatch(log, /renderer:/);
});

test("measurement campaign orchestrator reports destroy, inventory, and final validation failures", () => {
  for (const mode of ["destroy-fails", "nonzero-inventory", "final-validation-fails"]) {
    const fixture = runOrchestratorFixture(mode);
    assert.throws(fixture.run);
    const log = readFileSync(fixture.log, "utf8");
    assert.match(log, /destroy\.sh/);
    assert.match(log, /inventory\.sh/);
    if (mode === "final-validation-fails") assert.match(log, /validator:/);
    assert.doesNotMatch(log, /renderer:/);
    rmSync(fixture.fixtureRoot, { recursive: true, force: true });
  }
});

test("measurement campaign orchestrator handles external SIGTERM/SIGINT without final publish", async () => {
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    const fixture = makeOrchestratorFixture("success");
    writeFileSync(
      resolve(fixture.directory, "run-measurement-validation.sh"),
      `#!/usr/bin/env bash\nset -euo pipefail\necho run-measurement-validation.sh >> ${JSON.stringify(fixture.log)}\nsleep 2\n`,
    );
    chmodSync(resolve(fixture.directory, "run-measurement-validation.sh"), 0o755);
    execFileSync("git", ["add", "."], { cwd: fixture.fixtureRoot });
    execFileSync("git", ["commit", "-q", "-m", `sleep stub ${signal}`], { cwd: fixture.fixtureRoot });
    const child = spawn(resolve(fixture.directory, "run-measurement-campaign.sh"), {
      cwd: fixture.fixtureRoot,
      env: {
        ...process.env,
        COGS_AWS_FEASIBILITY_DIRECTORY: fixture.directory,
        COGS_STAGE2_MEASUREMENT_VALIDATOR: fixture.validator,
        COGS_STAGE2_MEASUREMENT_RENDERER: fixture.renderer,
        COGS_AWS_MEASUREMENT_CAMPAIGN_APPROVED: "run-one-stage2-measurement-campaign",
      },
      stdio: "ignore",
    });
    for (let i = 0; i < 100; i++) {
      const log = existsSync(fixture.log) ? readFileSync(fixture.log, "utf8") : "";
      if (log.includes("run-measurement-validation.sh")) break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    child.kill(signal);
    const result = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
      child.on("close", (code, signal) => resolve({ code, signal })),
    );
    assert.notEqual(result.code, 0);
    const log = readFileSync(fixture.log, "utf8");
    assert.match(log, /run-measurement-validation\.sh\ndestroy\.sh\ninventory\.sh/);
    assert.doesNotMatch(log, /validator:|renderer:/);
  }
});

test("AWS apply and cleanup scripts preserve manual and tag-bound gates", () => {
  const apply = read("deploy/aws-feasibility/apply.sh");
  const plan = read("deploy/aws-feasibility/plan.sh");
  const destroy = read("deploy/aws-feasibility/destroy.sh");
  const inventory = read("deploy/aws-feasibility/inventory.sh");
  const installer = read("scripts/install-opentofu.sh");
  assert.match(apply, /COGS_AWS_APPLY_APPROVED/);
  assert.match(apply, /apply-one-cpu-instance/);
  assert.match(apply, /destroy -auto-approve/);
  assert.match(plan, /-var-file=\.state\/campaign\.auto\.tfvars\.json/);
  assert.match(destroy, /-var-file=\.state\/campaign\.auto\.tfvars\.json/);
  assert.match(inventory, /stage-2-nested-virtualization/);
  assert.match(inventory, /total == 0/);
  assert.match(installer, /version=1\.12\.4/);
  assert.equal((installer.match(/sha256:/g) ?? []).length, 0, "installer stores raw expected digests only");
  assert.equal((installer.match(/expected=[0-9a-f]{64}/g) ?? []).length, 4);
});
