import assert from "node:assert/strict";
import childProcess, { spawnSync } from "node:child_process";
import { chmod, mkdtemp, readdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ENVOY_IMAGE } from "../dev/launcher/envoy-egress.ts";
import { OPENBAO_IMAGE } from "../dev/openbao-model-auth/image.ts";
import {
  LAUNCHER_DOCKER,
  LAUNCHER_IMAGE_ENV,
  LAUNCHER_REQUIRED_IMAGES,
  prepareLauncherImages,
  verifyImageInspect,
} from "../scripts/prepare-launcher-images.ts";
import {
  cleanupSensitiveExport,
  expectedReportPath,
  isTmpfsType,
  launcherCommandDescriptor,
  reportFor,
  s3FailureStageFromLauncherExitCode,
  validateReportPath,
  validateS309Json,
  validateSmokeJson,
} from "../scripts/run-launcher-smoke-evidence.ts";

const sourceRevision = "a".repeat(40);

test("launcher smoke evidence renderer is applicability-aware and non-release", () => {
  const insecure = reportFor({
    profile: "insecure-container",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "pass",
    diagnostics: "metadata-only launcher smoke passed",
  });
  assert.equal(insecure.authority, "functional-only");
  assert.equal(insecure.environment.metadata.external_tmpfs_roots, true);
  assert.equal(insecure.tests[0]?.release_eligible, false);
  assert.equal(insecure.tests[0]?.dependency_modes.network_enforcement, "not-applicable");
  assert(!JSON.stringify(insecure).includes("launcher-smoke.json"));

  const kvm = reportFor({
    profile: "linux-kvm",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "pass",
    diagnostics: "metadata-only launcher smoke passed",
  });
  assert.equal(kvm.authority, "authoritative-local");
  assert.equal((kvm.environment.metadata as Record<string, unknown>).guest_root, true);
  assert.equal((kvm.environment.metadata as Record<string, unknown>).distinct_boot_ids, true);
  assert(kvm.known_limitations.some((item) => item.includes("same workflow's validated qualification")));
  assert.equal(kvm.tests[0]?.release_eligible, false);
  assert.equal(kvm.tests[0]?.dependency_modes.network_enforcement, "real");
});

test("s3-09 launcher evidence report and command are fixed and metadata-only", () => {
  const descriptor = launcherCommandDescriptor("linux-kvm", "s309", 600000, "s3-09");
  assert.deepEqual(descriptor.args.slice(-3), ["s3-09", "--timeout-ms", "600000"]);
  const report = reportFor({
    profile: "linux-kvm",
    scenario: "s3-09",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "pass",
    diagnostics: "metadata-only s3-09 passed",
  });
  assert.equal(report.authority, "authoritative-local");
  assert.equal(report.tests[0]?.id, "launcher.s3-09.integrated");
  assert.equal(report.tests[0]?.release_eligible, false);
  assert(report.known_limitations.some((item) => item.includes("blocked/not-run")));
  const serialized = JSON.stringify(report);
  for (const forbidden of ["session.jsonl", "credential", "/workspace", "sk-ant", "prompt"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal(
    expectedReportPath("linux-kvm", "s3-09"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-s3-09-linux-kvm.json"),
  );
  assert.equal(
    validateReportPath("linux-kvm", "docs/security-evidence/generated/launcher-s3-09-linux-kvm.json", "s3-09"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-s3-09-linux-kvm.json"),
  );
  assert.throws(() =>
    validateReportPath("linux-kvm", "docs/security-evidence/generated/launcher-linux-kvm.json", "s3-09"),
  );
});

test("s3-09 evidence maps only exact bounded launcher exit codes to metadata stages", () => {
  assert.equal(s3FailureStageFromLauncherExitCode(40), "s3-create");
  assert.equal(s3FailureStageFromLauncherExitCode(46), "s3-terminal-kind");
  assert.equal(s3FailureStageFromLauncherExitCode(47), "s3-git-mapping");
  assert.equal(s3FailureStageFromLauncherExitCode(48), "s3-live-count");
  assert.equal(s3FailureStageFromLauncherExitCode(49), "s3-proof-run");
  assert.equal(s3FailureStageFromLauncherExitCode(50), "s3-proof-terminal");
  assert.equal(s3FailureStageFromLauncherExitCode(51), "s3-egress-shape");
  assert.equal(s3FailureStageFromLauncherExitCode(52), "s3-egress-state");
  assert.equal(s3FailureStageFromLauncherExitCode(53), "s3-egress-credential");
  assert.equal(s3FailureStageFromLauncherExitCode(54), "s3-egress-denied");
  assert.equal(s3FailureStageFromLauncherExitCode(55), "s3-egress-total");
  assert.equal(s3FailureStageFromLauncherExitCode(58), "s3-export");
  assert.equal(s3FailureStageFromLauncherExitCode(62), "s3-cleanup");
  assert.equal(s3FailureStageFromLauncherExitCode(63), "s3-trusted-relay-zero-wal-zero");
  assert.equal(s3FailureStageFromLauncherExitCode(64), "s3-trusted-relay-zero-wal-pass");
  assert.equal(s3FailureStageFromLauncherExitCode(65), "s3-trusted-relay-one-wal-zero");
  assert.equal(s3FailureStageFromLauncherExitCode(66), "s3-trusted-relay-one-wal-pass");
  for (const forged of [1, 39, 67, "40", { valueOf: () => 40 }, new Proxy({}, { get: () => 40 })]) {
    assert.equal(s3FailureStageFromLauncherExitCode(forged), undefined);
  }
  const report = reportFor({
    profile: "linux-kvm",
    scenario: "s3-09",
    sourceRevision,
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    outcome: "fail",
    diagnostics: "launcher smoke failed at s3-trusted-relay-one-wal-pass",
  });
  assert.equal(report.tests[0]?.diagnostics_redacted, "launcher smoke failed at s3-trusted-relay-one-wal-pass");
});

test("launcher command descriptor uses exact node and minimal env with deadline", () => {
  const descriptor = launcherCommandDescriptor("insecure-container", "state", 600000);
  assert.equal(descriptor.executable, process.execPath);
  assert.deepEqual(descriptor.env, { HOME: process.cwd(), NO_COLOR: "1" });
  assert.equal(descriptor.cwd, process.cwd());
  assert.equal(descriptor.timeoutMs, 720000);
  assert.equal(descriptor.killGraceMs, 120000);
  assert.equal(descriptor.args.at(-1), "600000");
  assert.deepEqual(descriptor.args.slice(1), [
    join(process.cwd(), "dev", "launcher", "main.ts"),
    "--profile",
    "insecure-container",
    "--state",
    "state",
    "smoke",
    "--timeout-ms",
    "600000",
  ]);
  assert.equal(descriptor.args[0], join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs"));
});

test("launcher smoke metadata validator requires exact cleanup and abort terminal without getters", () => {
  const valid = {
    op: "smoke",
    complete: true,
    aborted: { terminal: "run_aborted", lastEventId: 9, eventCount: 3 },
    inventory: {
      profile: "linux-kvm",
      authority: "authoritative-local",
      phase: "sandbox-ready",
      descriptor: "none",
      workerLive: false,
      recovery: "absent",
      acquisitionUncertainty: "absent",
      retirement: "absent",
      cleanupRequired: false,
      driverState: "absent",
    },
  };
  validateSmokeJson(valid, "linux-kvm");
  for (const key of ["acquisitionUncertainty", "retirement"]) {
    for (const value of ["present", "unknown", undefined])
      assert.throws(() =>
        validateSmokeJson({ ...valid, inventory: { ...valid.inventory, [key]: value } }, "linux-kvm"),
      );
  }

  let invoked = false;
  assert.throws(() =>
    validateSmokeJson(
      Object.freeze(
        Object.defineProperty({}, "op", {
          enumerable: true,
          get() {
            invoked = true;
            return "smoke";
          },
        }),
      ),
      "insecure-container",
    ),
  );
  assert.equal(invoked, false);

  for (const aborted of [
    { terminal: "run_aborted" },
    { terminal: "run_settled", lastEventId: 9, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 0, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 9, eventCount: 0 },
    { terminal: "run_aborted", lastEventId: 1001, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 2, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 9.5, eventCount: 3 },
    { terminal: "run_aborted", lastEventId: 9, eventCount: 3, extra: true },
    Object.assign(Object.create(null), { terminal: "run_aborted", lastEventId: 9, eventCount: 3 }),
  ]) {
    assert.throws(() => validateSmokeJson({ ...valid, aborted }, "linux-kvm"));
  }

  const symbolAborted = { terminal: "run_aborted", lastEventId: 9, eventCount: 3, [Symbol("x")]: true };
  assert.throws(() => validateSmokeJson({ ...valid, aborted: symbolAborted }, "linux-kvm"));

  let abortedGetterInvoked = false;
  const getterAborted = Object.defineProperty({ terminal: "run_aborted", eventCount: 3 }, "lastEventId", {
    enumerable: true,
    get() {
      abortedGetterInvoked = true;
      return 9;
    },
  });
  assert.throws(() => validateSmokeJson({ ...valid, aborted: getterAborted }, "linux-kvm"));
  assert.equal(abortedGetterInvoked, false);
});

test("s3-09 metadata validator requires raw export opening proof", () => {
  const valid = {
    op: "s3-09",
    complete: true,
    terminal: "run_settled",
    lastEventId: 40,
    liveEventCount: 33,
    egressProof: true,
    history: { pages: 2, entries: 4 },
    rawExport: { descriptorValidated: true, mode: "raw", sensitive: true, rawExportOpened: true },
    inventory: {
      profile: "linux-kvm",
      authority: "authoritative-local",
      phase: "sandbox-ready",
      descriptor: "none",
      workerLive: false,
      recovery: "absent",
      acquisitionUncertainty: "absent",
      retirement: "absent",
      cleanupRequired: false,
      driverState: "absent",
    },
  };
  validateS309Json(valid);
  for (const key of ["acquisitionUncertainty", "retirement"]) {
    for (const value of ["present", "unknown", undefined])
      assert.throws(() => validateS309Json({ ...valid, inventory: { ...valid.inventory, [key]: value } }));
  }
  assert.throws(() => validateS309Json({ ...valid, liveEventCount: 32 }));
  assert.throws(() =>
    validateS309Json({ ...valid, rawExport: { descriptorValidated: true, mode: "raw", sensitive: true } }),
  );
  let invoked = false;
  assert.throws(() =>
    validateS309Json(
      Object.freeze(
        Object.defineProperty({}, "op", {
          enumerable: true,
          get() {
            invoked = true;
            return "s3-09";
          },
        }),
      ),
    ),
  );
  assert.equal(invoked, false);
});

test("launcher evidence helpers reject non-tmpfs and constrain report filename", () => {
  assert.equal(isTmpfsType(0x01021994), true);
  assert.equal(isTmpfsType(0x6969), false);
  assert.equal(
    expectedReportPath("linux-kvm"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-linux-kvm.json"),
  );
  assert.equal(
    validateReportPath("insecure-container", "docs/security-evidence/generated/launcher-insecure-container.json"),
    join(process.cwd(), "docs/security-evidence/generated/launcher-insecure-container.json"),
  );
  assert.throws(() => validateReportPath("insecure-container", "/tmp/launcher-insecure-container.json"));
});

test("historical OpenBao smokes refuse every profile before commands, setup or report writes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-retired-smoke-"));
  try {
    const effects = join(dir, "effects");
    const commands = [
      "docker",
      "timeout",
      "gtimeout",
      "dirname",
      "mktemp",
      "git",
      "date",
      "shasum",
      "sha256sum",
      "cut",
      "mkdir",
      "chmod",
      "sudo",
      "node",
      "python3",
      "rm",
      "seq",
    ];
    for (const command of commands) {
      const path = join(dir, command);
      await writeFile(path, '#!/bin/bash\nprintf EFFECT >> "$EFFECT_LOG"\nexit 97\n');
      await chmod(path, 0o700);
    }
    const before = await readdir(dir);
    for (const script of [
      "dev/openbao-model-auth/ci-smoke.sh",
      "test/egress-conformance/stage3-real-runtime/ci-smoke.sh",
    ]) {
      for (const profile of ["insecure-container", "linux-kvm", "invalid"]) {
        const result = spawnSync("/bin/bash", [join(process.cwd(), script), join(dir, "report")], {
          env: {
            PATH: dir,
            EFFECT_LOG: effects,
            COGS_STAGE3_REAL_RUNTIME_PROFILE: profile,
            OPENBAO_IMAGE: "caller-selected:replacement",
            COGS_SOURCE_REVISION: sourceRevision,
          },
          encoding: "utf8",
          timeout: 2000,
        });
        assert.equal(result.status, 2, `${script}:${profile}:${result.stderr}`);
        assert.equal(result.stdout, "");
        assert.match(result.stderr, /OpenBao 2\.6\.1 is retired; no admitted replacement/u);
        assert.deepEqual(await readdir(dir), before, "refusal must precede command/report effects");
      }
      assert.ok((await readFile(script, "utf8")).includes(OPENBAO_IMAGE), "retain historical pin bytes");
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("sensitive export cleanup treats post-acquisition removal as uncertain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-export-"));
  try {
    const path = join(dir, "launcher-smoke.json");
    await writeFile(path, "{}\n", { mode: 0o600 });
    await assert.rejects(() => cleanupSensitiveExport(path, async () => unlink(path)));
    await cleanupSensitiveExport(join(dir, "absent.json"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("launcher preparation excludes retired OpenBao and remains outside active workflows", async (t) => {
  assert.equal(LAUNCHER_DOCKER, "/usr/bin/docker");
  assert.deepEqual(LAUNCHER_IMAGE_ENV, { HOME: "/tmp" });
  assert.deepEqual(LAUNCHER_REQUIRED_IMAGES, [ENVOY_IMAGE]);
  assert.ok(Object.isFrozen(LAUNCHER_REQUIRED_IMAGES));
  const inspect = JSON.stringify([{ RepoDigests: [ENVOY_IMAGE.replace(":v1.38.3@", "@")] }]);
  assert.throws(() => verifyImageInspect(ENVOY_IMAGE, JSON.stringify([{ RepoDigests: [] }])));
  verifyImageInspect(ENVOY_IMAGE, inspect);
  const calls: unknown[][] = [];
  const exec = t.mock.method(childProcess, "execFileSync", (...args: unknown[]) => {
    calls.push(args);
    return inspect;
  });
  syncBuiltinESMExports();
  try {
    prepareLauncherImages(); // Only the injected recorder runs; never Docker.
    assert.deepEqual(
      calls.map((args) => args.slice(0, 2)),
      [
        [LAUNCHER_DOCKER, ["pull", ENVOY_IMAGE]],
        [LAUNCHER_DOCKER, ["image", "inspect", ENVOY_IMAGE]],
      ],
    );
    assert.ok(!JSON.stringify(calls).includes(OPENBAO_IMAGE));
  } finally {
    exec.mock.restore();
    syncBuiltinESMExports();
  }

  const insecure = await readFile(join(process.cwd(), ".github/workflows/insecure-container.yml"), "utf8");
  const kvm = await readFile(join(process.cwd(), ".github/workflows/kvm-qualification.yml"), "utf8");
  for (const workflow of [insecure, kvm]) {
    assert.doesNotMatch(
      workflow,
      /prepare-launcher-images|run-launcher-smoke-evidence|stage3-real-runtime|openbao-model-auth/,
    );
    assert.match(workflow, /COGS_SOURCE_REVISION: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
  }
  assert.match(insecure, /id: envoy_response[\s\S]*COGS_ENVOY_RESPONSE_TEST: "1"/u);
  assert.match(insecure, /docker pull "node@sha256:8ea2348b068a9544dae7317b4f3aafcdc032df1647bb7d768a05a5cad1a7683f"/u);
  assert.match(
    insecure,
    /ENVOY_RESPONSE_OUTCOME: \$\{\{ steps\.envoy_response\.outcome \}\}[\s\S]*test "\$ENVOY_RESPONSE_OUTCOME" = success/u,
  );
  assert.match(kvm, /id: envoy_suite\n {8}if: [^\n]*stage2-only[^\n]*\n {8}continue-on-error: true/);
  assert.match(kvm, /id: destroy\n {8}if: always\(\) && steps\.guest\.outcome == 'success'/);
  assert.match(kvm, /id: domain_cleanup\n {8}if: always\(\) && env\.COGS_KVM_NETNS != ''/);
  assert.match(kvm, /id: evidence\n {8}if: always\(\)/);
  for (const [variable, step] of [
    ["GUEST_OUTCOME", "guest"],
    ["ENVOY_OUTCOME", "envoy_suite"],
    ["DESTROY_OUTCOME", "destroy"],
    ["DOMAIN_OUTCOME", "domain_cleanup"],
    ["EVIDENCE_OUTCOME", "evidence"],
  ] as const) {
    assert(kvm.includes(`${variable}: \${{ steps.${step}.outcome }}`));
  }
  assert.match(kvm, /if \[\[ "\$STAGE2_ONLY" == true \]\]; then[\s\S]*"\$GUEST_OUTCOME" = skipped/u);
  assert.match(kvm, /else[\s\S]*"\$ENVOY_OUTCOME" = success[\s\S]*"\$DESTROY_OUTCOME" = success/u);
  assert.match(kvm, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
});
