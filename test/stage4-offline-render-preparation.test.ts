import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import {
  canonicalStage4OfflineReadinessBytes,
  stage4OfflineReadinessSha256,
} from "../scripts/stage4-offline-readiness.ts";
import { STAGE4_PINNED_HELM, STAGE4_PINNED_NODE } from "../scripts/stage4-offline-render-preparation.ts";

const root = resolve(import.meta.dirname, "..");
const generator = resolve(root, "scripts/stage4-offline-render-preparation.ts");
const artifactRoot = resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts");

type Run = Readonly<{ status: number | null; stdout: Uint8Array; stderr: string }>;

function run(script = generator, prefix: readonly string[] = []): Run {
  const result = spawnSync(STAGE4_PINNED_NODE.executable, [...prefix, script], {
    cwd: root,
    encoding: null,
    env: { HOME: tmpdir(), PATH: "/usr/bin:/bin" },
    maxBuffer: 1024 * 1024,
    timeout: 30_000,
    shell: false,
  });
  assert.equal(result.error, undefined);
  return { status: result.status, stdout: new Uint8Array(result.stdout), stderr: result.stderr.toString("utf8") };
}

function copyInputTree(): { temporary: string; script: string } {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-render-hostile-"));
  const copy = (path: string): void => {
    const source = resolve(root, path);
    const destination = resolve(temporary, path);
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(source, destination, { recursive: true });
  };
  for (const path of [
    "scripts/stage4-offline-render-preparation.ts",
    "deploy/helm/cogs",
    "test/fixtures/helm/stage4-notes-source-shapes-valid.yaml",
    "docs/security-evidence/stage4-offline-readiness-artifacts/chart-inventory.json",
    "docs/security-evidence/stage4-offline-readiness-artifacts/notes-render.yaml",
    "docs/security-evidence/stage4-offline-readiness-artifacts/notes-render-repeat.yaml",
  ])
    copy(path);
  return { temporary, script: resolve(temporary, "scripts/stage4-offline-render-preparation.ts") };
}

test("trusted CLI binds pinned Node, source, immutable Helm copy, and two fresh renders", () => {
  const result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  const committed = new Uint8Array(readFileSync(join(artifactRoot, "render-preparation-receipt.json")));
  assert.deepEqual(result.stdout, committed);
  const receipt = JSON.parse(new TextDecoder().decode(result.stdout));
  assert.deepEqual(result.stdout, canonicalStage4OfflineReadinessBytes(receipt));
  assert.equal(receipt.execution, "pinned-node-native-typescript-authenticated-helm-copy");
  assert.equal(receipt.typescript_loader, "none-node-native-strip-types");
  assert.equal(receipt.node_executable_sha256, STAGE4_PINNED_NODE.sha256);
  assert.equal(receipt.node_version, STAGE4_PINNED_NODE.version);
  assert.equal(receipt.helm_executable_sha256, STAGE4_PINNED_HELM.sha256);
  assert.equal(receipt.helm_execution_copy_sha256, STAGE4_PINNED_HELM.sha256);
  assert.equal(receipt.generator_source_sha256, stage4OfflineReadinessSha256(new Uint8Array(readFileSync(generator))));
  assert.equal(receipt.trusted_preparation_complete, true);
  assert.equal(receipt.cloud_execution_observed, false);
  assert.equal(receipt.kubernetes_execution_observed, false);
  assert.equal(receipt.provider_execution_observed, false);
});

test("forged identical committed renders fail despite being internally digest-consistent", () => {
  const fixture = copyInputTree();
  try {
    const forged = new TextEncoder().encode("forged-identical-render\n");
    writeFileSync(
      resolve(fixture.temporary, "docs/security-evidence/stage4-offline-readiness-artifacts/notes-render.yaml"),
      forged,
    );
    writeFileSync(
      resolve(fixture.temporary, "docs/security-evidence/stage4-offline-readiness-artifacts/notes-render-repeat.yaml"),
      forged,
    );
    const result = run(fixture.script);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "STAGE4_RENDER_PREPARATION_COMMITTED_RENDER_MISMATCH\n");
    assert.equal(result.stdout.byteLength, 0);
  } finally {
    rmSync(fixture.temporary, { recursive: true, force: true });
  }
});

test("chart and values rewrites fail before trusted completion", () => {
  for (const mutate of [
    (temporary: string) =>
      writeFileSync(resolve(temporary, "deploy/helm/cogs/templates/_forged.tpl"), "{{/* forged */}}\n"),
    (temporary: string) => {
      const path = resolve(temporary, "test/fixtures/helm/stage4-notes-source-shapes-valid.yaml");
      writeFileSync(path, `${readFileSync(path, "utf8")}# forged\n`);
    },
  ]) {
    const fixture = copyInputTree();
    try {
      mutate(fixture.temporary);
      const result = run(fixture.script);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /^STAGE4_RENDER_PREPARATION_(?:CHART_INVENTORY|VALUES)_DRIFT\n$/u);
      assert.equal(result.stdout.byteLength, 0);
    } finally {
      rmSync(fixture.temporary, { recursive: true, force: true });
    }
  }
});

test("caller path, tsx loader, and extra arguments cannot impersonate the generator execution layer", () => {
  const loader = run(generator, ["--import", "tsx"]);
  assert.equal(loader.status, 1);
  assert.equal(loader.stderr, "STAGE4_RENDER_PREPARATION_EXECUTION_LAYER_INVALID\n");

  const extra = spawnSync(STAGE4_PINNED_NODE.executable, [generator, "forged-source.ts"], {
    cwd: root,
    encoding: "utf8",
    env: { HOME: tmpdir(), PATH: "/usr/bin:/bin" },
    timeout: 30_000,
    shell: false,
  });
  assert.equal(extra.status, 1);
  assert.equal(extra.stderr, "STAGE4_RENDER_PREPARATION_ARGUMENTS_FORBIDDEN\n");
});

test("generator executes only a private exact-byte Helm copy and reauthenticates it", () => {
  const source = readFileSync(generator, "utf8");
  assert.match(source, /boundedBytes\(import\.meta\.filename/u);
  assert.doesNotMatch(source, /generatorSource/u);
  assert.match(source, /materializeAuthenticatedHelm/u);
  assert.match(source, /writeExclusive\(path, helmBytes/u);
  assert.match(source, /spawnSync\(executor\.path/u);
  assert.doesNotMatch(source, /spawnSync\(STAGE4_PINNED_HELM\.(?:executable|realExecutable)/u);
  assert.match(source, /function verifyExecutor/u);
  assert.match(source, /fstatSync\(executor\.fileFd/u);
  assert.match(source, /fstatSync\(executor\.directoryFd/u);
  assert.match(source, /file\.ctimeNs !== expectedFile\.ctimeNs/u);
  assert.match(source, /parent\.ctimeNs !== expectedParent\.ctimeNs/u);
  assert.match(source, /process\.execArgv\.length !== 0/u);
  assert.match(source, /"template",\s+RELEASE,\s+chart,/u);
  assert.match(source, /"--dry-run=client"/u);
  assert.match(source, /shell: false/u);
  assert.doesNotMatch(
    source,
    /\b(?:install|upgrade|rollback|uninstall|dependency update|repo add|plugin install|kubectl|opentofu|terraform|aws)\b/iu,
  );
  assert.doesNotMatch(source, /process\.env|enable-dns|dry-run=server/iu);
});
