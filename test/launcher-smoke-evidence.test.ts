import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ENVOY_IMAGE } from "../dev/launcher/envoy-egress.ts";
import { OPENBAO_IMAGE } from "../dev/openbao-model-auth/image.ts";
import {
  LAUNCHER_DOCKER,
  LAUNCHER_IMAGE_ENV,
  LAUNCHER_REQUIRED_IMAGES,
  verifyImageInspect,
} from "../scripts/prepare-launcher-images.ts";
import {
  cleanupSensitiveExport,
  expectedReportPath,
  isTmpfsType,
  launcherCommandDescriptor,
  reportFor,
  validateReportPath,
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

test("launcher command descriptor uses exact node and minimal env with deadline", () => {
  const descriptor = launcherCommandDescriptor("insecure-container", "state", 600000);
  assert.equal(descriptor.executable, process.execPath);
  assert.deepEqual(descriptor.env, { HOME: process.cwd(), NO_COLOR: "1", COGS_LAUNCHER_DEBUG_STAGE: "1" });
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

test("launcher debug smoke markers are fixed and allowlisted on debug branch only", async () => {
  const markerSources = await Promise.all([
    ...["operations.ts", "supervisor.ts", "worker-process.ts", "trusted-compose.ts"].map((file) =>
      readFile(join(process.cwd(), "dev/launcher", file), "utf8"),
    ),
    readFile(join(process.cwd(), "src/pi/session.ts"), "utf8"),
    readFile(join(process.cwd(), "src/skills/session-preparer.ts"), "utf8"),
    readFile(join(process.cwd(), "src/skills/sftp-materializer.ts"), "utf8"),
  ]);
  const sourceText = markerSources.join("\n");
  const harness = await readFile(join(process.cwd(), "scripts/run-launcher-smoke-evidence.ts"), "utf8");
  for (const stage of [
    "after-create",
    "after-start",
    "after-normal-run",
    "after-history",
    "after-export",
    "after-abort-request",
    "after-abort-terminal",
    "after-shutdown",
    "after-inventory",
    "after-destroy",
    "supervisor-manifest",
    "supervisor-controls",
    "supervisor-token",
    "supervisor-startup-control",
    "supervisor-worker-process-return",
    "worker-spawn",
    "child-runtime-start",
    "trusted-admission",
    "trusted-egress-root",
    "trusted-ssh-controls",
    "trusted-egress",
    "trusted-before-create-pi",
    "trusted-create-pi-return",
    "trusted-verify-snapshot",
    "trusted-verify-session-file",
    "trusted-verify-prepared-metadata",
    "trusted-api-ready",
    "pi-launch-validated",
    "pi-skill-preparer-validated",
    "pi-prepare-raw-returned",
    "pi-skills-prepared",
    "pi-credential-resolved",
    "pi-create-cogs-pi-return",
    "pi-options",
    "pi-model-found",
    "pi-session-manager",
    "pi-history",
    "pi-git",
    "pi-export",
    "pi-session-created",
    "pi-ports-return",
    "skill-prep-callback-entered",
    "skill-prep-entered",
    "skill-prep-shared-resolved",
    "skill-prep-private-snapshot",
    "skill-prep-host-temp-done",
    "skill-prep-bundles-loaded",
    "skill-prep-before-withsftp",
    "skill-prep-inside-withsftp",
    "skill-prep-shared-materialized",
    "skill-prep-user-materialized",
    "skill-prep-agents-read",
    "skill-prep-withsftp-returned",
    "skill-prep-preparer-returned",
    "sftp-shared-root-lstat",
    "sftp-shared-canonical-realpath",
    "sftp-shared-final-missing",
    "sftp-shared-staging-mkdir",
    "sftp-shared-metadata-write-read",
    "sftp-shared-rename",
    "sftp-shared-final-mode-read",
    "sftp-shared-return",
    "sftp-user-root-lstat",
    "sftp-user-canonical-realpath",
    "sftp-user-final-missing",
    "sftp-user-staging-mkdir",
    "sftp-user-metadata-write-read",
    "sftp-user-rename",
    "sftp-user-final-mode-read",
    "sftp-user-return",
  ]) {
    const sftpSuffix = stage.replace(/^sftp-(shared|user)-/u, "");
    const sourcePattern = stage.startsWith("sftp-")
      ? new RegExp(`debugSftpStage\\(\\\`sftp-\\$\\{scope\\}-${sftpSuffix}\\\`\\)`)
      : new RegExp(
          `debugStartupStage\\("${stage}"\\)|debugSmokeStage\\("${stage}"\\)|debugPiStage\\("${stage}"\\)|debugSkillPrepStage\\("${stage}"\\)`,
        );
    assert.match(sourceText, sourcePattern);
    assert.match(harness, new RegExp(`"${stage}"`));
  }
  assert.match(sourceText, /process\.env\.COGS_LAUNCHER_DEBUG_STAGE === "1"/);
  assert.match(harness, /line\.match\(\/\^launcher-debug-stage:\(\[a-z-\]\+\)\$\/u\)/);
  assert.match(sourceText, /\(\?:worker\|child\|trusted\|supervisor\|pi\|skill-prep\|sftp\)-\[a-z-\]\+/);
});

test("launcher smoke metadata validator requires exact cleanup and abort terminal without getters", () => {
  validateSmokeJson(
    {
      op: "smoke",
      complete: true,
      aborted: { terminal: "run_aborted" },
      inventory: {
        profile: "linux-kvm",
        authority: "authoritative-local",
        phase: "sandbox-ready",
        descriptor: "none",
        workerLive: false,
        recovery: "absent",
        cleanupRequired: false,
        driverState: "absent",
      },
    },
    "linux-kvm",
  );
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
  assert.throws(() =>
    validateSmokeJson(
      {
        op: "smoke",
        complete: true,
        aborted: { terminal: "run_settled" },
        inventory: {
          profile: "insecure-container",
          authority: "functional-only",
          phase: "sandbox-ready",
          descriptor: "none",
          workerLive: false,
          recovery: "absent",
          cleanupRequired: false,
          driverState: "absent",
        },
      },
      "insecure-container",
    ),
  );
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

test("launcher image prerequisite uses exact pinned OpenBao and Envoy images", async () => {
  assert.equal(LAUNCHER_DOCKER, "/usr/bin/docker");
  assert.deepEqual(LAUNCHER_IMAGE_ENV, { HOME: "/tmp" });
  assert.deepEqual(LAUNCHER_REQUIRED_IMAGES, [OPENBAO_IMAGE, ENVOY_IMAGE]);
  assert.throws(() => verifyImageInspect(OPENBAO_IMAGE, JSON.stringify([{ RepoDigests: [] }])));
  verifyImageInspect(OPENBAO_IMAGE, JSON.stringify([{ RepoDigests: [OPENBAO_IMAGE.replace(":2.6.0@", "@")] }]));
  const kvm = await readFile(join(process.cwd(), ".github/workflows/kvm-qualification.yml"), "utf8");
  assert.match(kvm, /id: launcher_images[\s\S]*npx --no-install tsx scripts\/prepare-launcher-images\.ts/);
  assert.match(kvm, /LAUNCHER_IMAGES_OUTCOME: \$\{\{ steps\.launcher_images\.outcome \}\}/);
  assert.match(kvm, /test "\$LAUNCHER_IMAGES_OUTCOME" = success/);
});

test("launcher workflows preserve nonempty roots and use exact checkout", async () => {
  const insecure = await readFile(join(process.cwd(), ".github/workflows/insecure-container.yml"), "utf8");
  const kvm = await readFile(join(process.cwd(), ".github/workflows/kvm-qualification.yml"), "utf8");
  for (const text of [insecure, kvm]) {
    assert.match(text, /test "\$\(find "\$root" -mindepth 1 -maxdepth 1 \| wc -l\)" = 0[\s\S]*sudo umount "\$root"/);
    assert.doesNotMatch(text, /rmdir \/run\/cogs[\s\S]*\|\| true/);
    assert.match(text, /COGS_SOURCE_REVISION: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
  }
  assert.match(kvm, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \|\| github\.sha \}\}/);
});
