/* biome-ignore-all lint/suspicious/noExplicitAny: hostile package mutations intentionally cross strict JSON types */
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  canonicalStage4OfflineReadinessBytes,
  stage4OfflineReadinessSha256,
} from "../scripts/stage4-offline-readiness.ts";
import {
  defaultStage4RenderPreparationPaths,
  prepareAndVerifyStage4OfflineRender,
  STAGE4_PINNED_HELM,
} from "../scripts/stage4-offline-render-preparation.ts";

const root = resolve(import.meta.dirname, "..");
const artifactRoot = resolve(root, "docs/security-evidence/stage4-offline-readiness-artifacts");
const exactPackage = (): Record<string, any> =>
  JSON.parse(readFileSync(resolve(root, "docs/security-evidence/stage4-offline-readiness-package.json"), "utf8"));

function assertCode(callback: () => unknown, code: string): void {
  assert.throws(callback, (error: unknown) => error instanceof Error && error.message === code);
}

test("trusted local preparation authenticates pinned Helm and freshly renders twice", () => {
  const result = prepareAndVerifyStage4OfflineRender(defaultStage4RenderPreparationPaths(root));
  const committedReceipt = new Uint8Array(readFileSync(join(artifactRoot, "render-preparation-receipt.json")));
  assert.deepEqual(result.receiptBytes, committedReceipt);
  assert.deepEqual(result.render, new Uint8Array(readFileSync(join(artifactRoot, "notes-render.yaml"))));
  assert.deepEqual(result.repeatedRender, new Uint8Array(readFileSync(join(artifactRoot, "notes-render-repeat.yaml"))));
  assert.equal(result.receipt.authority, "trusted-local-static-render-preparation");
  assert.equal(result.receipt.helm_executable_sha256, STAGE4_PINNED_HELM.sha256);
  assert.equal(result.receipt.trusted_preparation_complete, true);
  assert.equal(result.receipt.cloud_execution_observed, false);
  assert.equal(result.receipt.kubernetes_execution_observed, false);
  assert.equal(result.receipt.provider_execution_observed, false);
});

test("forged identical committed renders and package digest rewrites cannot replace fresh Helm output", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-forged-render-"));
  try {
    const first = join(temporary, "render.yaml");
    const second = join(temporary, "render-repeat.yaml");
    const forged = new TextEncoder().encode("forged-identical-render\n");
    writeFileSync(first, forged);
    writeFileSync(second, forged);
    const forgedPackage = exactPackage();
    forgedPackage.artifact_bindings.render_sha256 = stage4OfflineReadinessSha256(forged);
    forgedPackage.artifact_bindings.repeated_render_sha256 = stage4OfflineReadinessSha256(forged);
    writeFileSync(join(temporary, "forged-package.json"), canonicalStage4OfflineReadinessBytes(forgedPackage));
    assert.equal(
      JSON.parse(readFileSync(join(temporary, "forged-package.json"), "utf8")).artifact_bindings.render_sha256,
      stage4OfflineReadinessSha256(forged),
    );
    assertCode(
      () =>
        prepareAndVerifyStage4OfflineRender({
          ...defaultStage4RenderPreparationPaths(root),
          committedRender: first,
          committedRepeatedRender: second,
        }),
      "STAGE4_RENDER_PREPARATION_COMMITTED_RENDER_MISMATCH",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("chart inventory and values rewrites fail before rendering", () => {
  const temporary = mkdtempSync(join(tmpdir(), "cogs-stage4-forged-input-"));
  try {
    const chart = join(temporary, "chart");
    cpSync(resolve(root, "deploy/helm/cogs"), chart, { recursive: true });
    writeFileSync(join(chart, "templates/_forged.tpl"), "{{/* forged */}}\n");
    assertCode(
      () => prepareAndVerifyStage4OfflineRender({ ...defaultStage4RenderPreparationPaths(root), chartRoot: chart }),
      "STAGE4_RENDER_PREPARATION_CHART_INVENTORY_DRIFT",
    );

    const values = join(temporary, "values.yaml");
    writeFileSync(values, readFileSync(resolve(root, "test/fixtures/helm/stage4-notes-source-shapes-valid.yaml")));
    writeFileSync(values, `${readFileSync(values, "utf8")}# forged\n`);
    assertCode(
      () => prepareAndVerifyStage4OfflineRender({ ...defaultStage4RenderPreparationPaths(root), values }),
      "STAGE4_RENDER_PREPARATION_VALUES_DRIFT",
    );
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("generator process surface is bounded to pinned local Helm version and template", () => {
  const source = readFileSync(resolve(root, "scripts/stage4-offline-render-preparation.ts"), "utf8");
  assert.match(source, /\["version", "--short"\]/u);
  assert.match(source, /"template",\s+RELEASE,\s+chart,/u);
  assert.match(source, /"--dry-run=client"/u);
  assert.match(source, /"--hide-notes=false"/u);
  assert.match(source, /shell: false/u);
  assert.doesNotMatch(
    source,
    /\b(?:install|upgrade|rollback|uninstall|dependency update|repo add|plugin install|kubectl|opentofu|terraform|aws)\b/iu,
  );
  assert.doesNotMatch(source, /process\.env|enable-dns|dry-run=server/iu);
});
