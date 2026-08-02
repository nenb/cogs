import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import {
  classifyStage4ExitReviewTemplate,
  STAGE4_EXIT_CRITERION_IDS,
  STAGE4_EXIT_REJECTION_IDS,
  stage4ExitMatrixSha256,
  stage4ExitReportSha256,
} from "../scripts/stage4-exit-review.ts";

type JsonObject = Record<string, unknown>;
const fixture = (name: string): JsonObject =>
  JSON.parse(readFileSync(resolve(import.meta.dirname, `fixtures/stage4-campaign/${name}`), "utf8")) as JsonObject;
const matrixFixture = (): JsonObject => fixture("s4-11-exit-matrix-template-v1.json");
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const reportFixture = (): JsonObject => fixture("s4-11-exit-report-template-v1.json");

test("#362 matrix/report fixtures are strict, bound, unreviewed, and always exit false", () => {
  const matrix = matrixFixture();
  const report = reportFixture();
  const result = classifyStage4ExitReviewTemplate(matrix, report);
  assert.equal(result.template_valid, true);
  assert.equal(result.review_complete, false);
  assert.equal(result.stage4_exit_satisfied, false);
  assert.equal(result.release_eligible, false);
  assert.equal(result.status, "valid-blocked-template");
  assert.equal(result.reason_code, "STAGE4_EXIT_TEMPLATE_VALID_BLOCKED");
  assert.equal(result.matrix_sha256, stage4ExitMatrixSha256(matrix));
  assert.equal(result.report_sha256, stage4ExitReportSha256(report));
  assert.equal(report.matrix_sha256, result.matrix_sha256);
  assert.deepEqual(
    (matrix.criteria as JsonObject[]).map((row) => row.id),
    STAGE4_EXIT_CRITERION_IDS,
  );
  assert.deepEqual(
    (report.rejection_checks as JsonObject[]).map((row) => row.id),
    STAGE4_EXIT_REJECTION_IDS,
  );
  assert.ok((matrix.criteria as JsonObject[]).every((row) => row.state === "unreviewed-reject"));
  assert.ok((report.rejection_checks as JsonObject[]).every((row) => row.state === "unreviewed-reject"));
  assert.equal((report.decision as JsonObject).stage4_exit_satisfied, false);
  assert.equal((report.decision as JsonObject).release_eligible, false);
  assert.equal(report.temporary_launcher_is_not_daemon, true);
  assert.equal(report.not_ga_compliance_or_production_approval, true);
});

test("#362 rejects stubs, skips, fallback, leaks, mixed revisions, exceptions, and cleanup uncertainty promotions", () => {
  for (const [index, id] of STAGE4_EXIT_REJECTION_IDS.entries()) {
    const matrix = matrixFixture();
    const report = reportFixture();
    const row = (report.rejection_checks as JsonObject[])[index];
    assert.ok(row);
    row.state = "accepted";
    row.evidence_sha256 = "a".repeat(64);
    const result = classifyStage4ExitReviewTemplate(matrix, report);
    assert.equal(result.template_valid, false, id);
    assert.equal(result.stage4_exit_satisfied, false, id);
    assert.equal(result.release_eligible, false, id);
  }
});

test("#362 rejects matrix omissions, reordering, mixed binding, unreviewed exceptions, and authority promotion", () => {
  const cases: Array<[string, (matrix: JsonObject, report: JsonObject) => void, string]> = [
    ["criterion omission", (matrix) => (matrix.criteria as JsonObject[]).pop(), "STAGE4_EXIT_TEMPLATE_INVALID"],
    ["criterion reorder", (matrix) => (matrix.criteria as JsonObject[]).reverse(), "STAGE4_EXIT_TEMPLATE_INVALID"],
    [
      "mixed matrix",
      (_matrix, report) => (report.matrix_sha256 = "f".repeat(64)),
      "STAGE4_EXIT_MATRIX_BINDING_MISMATCH",
    ],
    [
      "stub",
      (matrix) => (((matrix.criteria as JsonObject[])[1] as JsonObject).dependency_mode = "stubbed"),
      "STAGE4_EXIT_TEMPLATE_INVALID",
    ],
    [
      "skip",
      (matrix) => (((matrix.criteria as JsonObject[])[2] as JsonObject).state = "skipped"),
      "STAGE4_EXIT_TEMPLATE_INVALID",
    ],
    [
      "exception",
      (matrix) => (((matrix.criteria as JsonObject[])[8] as JsonObject).exception_sha256 = "b".repeat(64)),
      "STAGE4_EXIT_TEMPLATE_INVALID",
    ],
    ["unknown waiver", (_matrix, report) => (report.waiver = true), "STAGE4_EXIT_TEMPLATE_INVALID"],
    ["matrix exit", (matrix) => (matrix.stage4_exit_satisfied = true), "STAGE4_EXIT_AUTHORITY_PROMOTION"],
    [
      "report exit",
      (_matrix, report) => ((report.decision as JsonObject).stage4_exit_satisfied = true),
      "STAGE4_EXIT_AUTHORITY_PROMOTION",
    ],
    [
      "release",
      (_matrix, report) => ((report.decision as JsonObject).release_eligible = true),
      "STAGE4_EXIT_AUTHORITY_PROMOTION",
    ],
  ];
  for (const [name, mutate, reason] of cases) {
    const matrix = matrixFixture();
    const report = reportFixture();
    mutate(matrix, report);
    const result = classifyStage4ExitReviewTemplate(matrix, report);
    assert.equal(result.template_valid, false, name);
    assert.equal(result.reason_code, reason, name);
    assert.equal(result.stage4_exit_satisfied, false, name);
    assert.equal(result.release_eligible, false, name);
  }
});

test("#362 verdict schema couples template validity, status, reason, and digests exactly", () => {
  const schema = JSON.parse(
    readFileSync(resolve(import.meta.dirname, "../schemas/stage4-exit-review-verdict-v1.json"), "utf8"),
  ) as object;
  const validate = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true }).compile(
    schema,
  ) as ValidateFunction;
  const valid = classifyStage4ExitReviewTemplate(matrixFixture(), reportFixture());
  assert.equal(validate(valid), true, JSON.stringify(validate.errors));
  const mismatchReport = reportFixture();
  mismatchReport.matrix_sha256 = "f".repeat(64);
  const mismatch = classifyStage4ExitReviewTemplate(matrixFixture(), mismatchReport);
  assert.equal(mismatch.matrix_sha256, stage4ExitMatrixSha256(matrixFixture()));
  assert.equal(mismatch.report_sha256, null);
  assert.equal(validate(mismatch), true, JSON.stringify(validate.errors));
  const promotedReport = reportFixture();
  (promotedReport.decision as JsonObject).stage4_exit_satisfied = true;
  const promoted = classifyStage4ExitReviewTemplate(matrixFixture(), promotedReport);
  assert.equal(promoted.matrix_sha256, null);
  assert.equal(promoted.report_sha256, null);
  assert.equal(validate(promoted), true, JSON.stringify(validate.errors));

  for (const mutation of [
    { ...valid, template_valid: false },
    { ...valid, status: "reject" },
    { ...valid, reason_code: "STAGE4_EXIT_TEMPLATE_INVALID" },
    { ...valid, matrix_sha256: null },
    { ...valid, report_sha256: null },
    { ...mismatch, report_sha256: "a".repeat(64) },
    { ...mismatch, reason_code: "STAGE4_EXIT_TEMPLATE_INVALID" },
    { ...promoted, template_valid: true },
    { ...promoted, matrix_sha256: "a".repeat(64) },
  ]) {
    assert.equal(validate(mutation), false);
  }
});

test("#362 hostile objects are rejected without invoking getters or proxy traps", () => {
  let invoked = 0;
  const matrix = matrixFixture();
  Object.defineProperty(matrix, "criteria", {
    enumerable: true,
    get: () => {
      invoked += 1;
      return [];
    },
  });
  assert.equal(classifyStage4ExitReviewTemplate(matrix, reportFixture()).template_valid, false);
  assert.equal(invoked, 0);
  const proxy = new Proxy(reportFixture(), {
    ownKeys: () => {
      invoked += 1;
      throw new Error("must not run");
    },
  });
  assert.equal(classifyStage4ExitReviewTemplate(matrixFixture(), proxy).template_valid, false);
  assert.equal(invoked, 0);
});
