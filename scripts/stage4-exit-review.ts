import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { types } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const matrixSchema = require("../schemas/stage4-exit-review-matrix-template-v1.json") as object;
const reportSchema = require("../schemas/stage4-exit-review-report-template-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validateMatrix = ajv.compile(matrixSchema) as ValidateFunction;
const validateReport = ajv.compile(reportSchema) as ValidateFunction;

export const STAGE4_EXIT_CRITERION_IDS = Object.freeze([
  "binding.one-exact-source-artifact-image-revision",
  "dependencies.real-no-mandatory-stubs",
  "evidence.no-skips-or-missing-criteria",
  "network.guest-root-cannot-bypass",
  "identity.no-kubernetes-cloud-openbao-credentials",
  "conformance.complete-unchanged-real-dependencies",
  "storage.ebs-lifecycle-no-concurrent-writer",
  "functional.real-pi-end-to-end",
  "performance.p95-or-agreed-percentile-under-30s-or-reviewed-exception",
  "recovery.all-design-failure-modes-no-prompt-replay",
  "lifecycle.repeatable-install-destroy",
  "runtime.no-container-tcg-runc-or-policy-fallback",
  "privacy.no-sensitive-data-leak",
  "cleanup.destroyed-and-independent-zero-inventory",
] as const);

export const STAGE4_EXIT_REJECTION_IDS = Object.freeze([
  "mandatory-stub-or-non-real-dependency",
  "skip-or-missing-evidence",
  "runtime-or-policy-fallback",
  "sensitive-data-leak",
  "mixed-source-artifact-or-image-revision",
  "unreviewed-exception",
  "cleanup-or-inventory-uncertainty",
] as const);

export type Stage4ExitReviewVerdict = Readonly<{
  version: "cogs.stage4-exit-review-verdict/v1";
  authority: "local-static-stage4-exit-template-classifier";
  template_valid: boolean;
  review_complete: false;
  stage4_exit_satisfied: false;
  release_eligible: false;
  matrix_sha256: string | null;
  report_sha256: string | null;
  status: "valid-blocked-template" | "reject";
  reason_code:
    | "STAGE4_EXIT_TEMPLATE_VALID_BLOCKED"
    | "STAGE4_EXIT_TEMPLATE_INVALID"
    | "STAGE4_EXIT_MATRIX_BINDING_MISMATCH"
    | "STAGE4_EXIT_AUTHORITY_PROMOTION";
}>;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };

function snapshotJson(input: unknown): JsonRecord | null {
  let nodes = 0;
  const visit = (value: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > 2048 || depth > 16) throw new TypeError("bounded shape exceeded");
    if (((typeof value === "object" && value !== null) || typeof value === "function") && types.isProxy(value)) {
      throw new TypeError("proxy rejected");
    }
    if (value === null || typeof value === "boolean" || typeof value === "string") return value;
    if (typeof value === "number" && Number.isSafeInteger(value)) return value;
    if (typeof value !== "object") throw new TypeError("non-JSON value");
    const prototype = Object.getPrototypeOf(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) throw new TypeError("symbol key");
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype || value.length > 64) throw new TypeError("array bound");
      const expected = [...Array.from({ length: value.length }, (_, index) => String(index)), "length"];
      if (keys.length !== expected.length || expected.some((key) => !keys.includes(key))) {
        throw new TypeError("sparse array");
      }
      return Array.from({ length: value.length }, (_, index) => {
        const descriptor = descriptors[String(index)];
        if (!descriptor?.enumerable || !("value" in descriptor)) throw new TypeError("array accessor");
        return visit(descriptor.value, depth + 1);
      });
    }
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError("prototype rejected");
    if (keys.length > 64) throw new TypeError("property bound");
    const output: JsonRecord = Object.create(null) as JsonRecord;
    for (const key of keys as string[]) {
      const descriptor = descriptors[key];
      if (!descriptor?.enumerable || !("value" in descriptor)) throw new TypeError("accessor rejected");
      output[key] = visit(descriptor.value, depth + 1);
    }
    return output;
  };
  try {
    const value = visit(input, 0);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

function compareCodePoints(left: string, right: string): number {
  const a = Array.from(left, (value) => value.codePointAt(0) ?? 0);
  const b = Array.from(right, (value) => value.codePointAt(0) ?? 0);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a.length - b.length;
}

function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value)
      .sort(compareCodePoints)
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(domain: string, value: JsonRecord): string {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(value), "utf8")
    .digest("hex");
}

export function stage4ExitMatrixSha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  return snapshot === null ? null : digest("cogs.stage4/exit-review-matrix-template/v1", snapshot);
}

export function stage4ExitReportSha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  return snapshot === null ? null : digest("cogs.stage4/exit-review-report-template/v1", snapshot);
}

function verdict(
  reason: Stage4ExitReviewVerdict["reason_code"],
  matrixSha256: string | null,
  reportSha256: string | null,
): Stage4ExitReviewVerdict {
  const valid = reason === "STAGE4_EXIT_TEMPLATE_VALID_BLOCKED";
  return Object.freeze({
    version: "cogs.stage4-exit-review-verdict/v1",
    authority: "local-static-stage4-exit-template-classifier",
    template_valid: valid,
    review_complete: false,
    stage4_exit_satisfied: false,
    release_eligible: false,
    matrix_sha256: matrixSha256,
    report_sha256: reportSha256,
    status: valid ? "valid-blocked-template" : "reject",
    reason_code: reason,
  });
}

function attemptedPromotion(matrix: JsonRecord, report: JsonRecord): boolean {
  const decision = report.decision;
  return (
    matrix.stage4_exit_satisfied === true ||
    (decision !== null &&
      typeof decision === "object" &&
      !Array.isArray(decision) &&
      (decision.stage4_exit_satisfied === true || decision.release_eligible === true))
  );
}

/** Validates only the fail-closed #362 matrix/report templates; it cannot decide Stage 4 exit. */
export function classifyStage4ExitReviewTemplate(matrixInput: unknown, reportInput: unknown): Stage4ExitReviewVerdict {
  const matrix = snapshotJson(matrixInput);
  const report = snapshotJson(reportInput);
  if (matrix === null || report === null) return verdict("STAGE4_EXIT_TEMPLATE_INVALID", null, null);
  const matrixSha256 = stage4ExitMatrixSha256(matrix);
  const reportSha256 = stage4ExitReportSha256(report);
  if (attemptedPromotion(matrix, report)) {
    return verdict("STAGE4_EXIT_AUTHORITY_PROMOTION", matrixSha256, reportSha256);
  }
  if (!validateMatrix(matrix) || !validateReport(report)) {
    return verdict("STAGE4_EXIT_TEMPLATE_INVALID", matrixSha256, reportSha256);
  }
  const criteria = matrix.criteria as JsonRecord[];
  const rejections = report.rejection_checks as JsonRecord[];
  if (
    criteria.some((row, index) => row.id !== STAGE4_EXIT_CRITERION_IDS[index]) ||
    rejections.some((row, index) => row.id !== STAGE4_EXIT_REJECTION_IDS[index])
  ) {
    return verdict("STAGE4_EXIT_TEMPLATE_INVALID", matrixSha256, reportSha256);
  }
  if (report.matrix_sha256 !== matrixSha256) {
    return verdict("STAGE4_EXIT_MATRIX_BINDING_MISMATCH", matrixSha256, reportSha256);
  }
  return verdict("STAGE4_EXIT_TEMPLATE_VALID_BLOCKED", matrixSha256, reportSha256);
}
