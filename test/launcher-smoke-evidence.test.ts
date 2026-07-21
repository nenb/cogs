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
      cleanupRequired: false,
      driverState: "absent",
    },
  };
  validateSmokeJson(valid, "linux-kvm");

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
    lastEventId: 9,
    liveEventCount: 5,
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
      cleanupRequired: false,
      driverState: "absent",
    },
  };
  validateS309Json(valid);
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
  assert.match(kvm, /id: launcher_s309[\s\S]*--scenario s3-09[\s\S]*launcher-s3-09-linux-kvm\.json/);
  assert.match(kvm, /LAUNCHER_IMAGES_OUTCOME: \$\{\{ steps\.launcher_images\.outcome \}\}/);
  assert.match(kvm, /LAUNCHER_S309_OUTCOME: \$\{\{ steps\.launcher_s309\.outcome \}\}/);
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
