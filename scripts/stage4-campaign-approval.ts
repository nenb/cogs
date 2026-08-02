import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { types } from "node:util";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const draftSchema = require("../schemas/stage4-campaign-approval-draft-v1.json") as object;
const validateDraft = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  ownProperties: true,
}).compile(draftSchema) as ValidateFunction;

export type Stage4CampaignApprovalReason =
  | "STAGE4_APPROVAL_DRAFT_VALID_BLOCKED"
  | "STAGE4_APPROVAL_DRAFT_INVALID_SHAPE"
  | "STAGE4_APPROVAL_DRAFT_AUTHORITY_PROMOTION";

export type Stage4CampaignApprovalVerdict = Readonly<{
  version: "cogs.stage4-campaign-approval-verdict/v1";
  authority: "local-static-unapproved-envelope-classifier";
  draft_valid: boolean;
  approval_present: false;
  execution_authorized: false;
  retry_authorized: false;
  provider_truth_observed: false;
  stage4_exit_satisfied: false;
  envelope_sha256: string | null;
  status: "valid-unapproved-blocked-draft" | "preserve-uncertain";
  reason_code: Stage4CampaignApprovalReason;
}>;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
type JsonRecord = { [key: string]: JsonValue };
const MAX_NODES = 512;
const MAX_DEPTH = 16;

function snapshotJson(input: unknown): JsonRecord | null {
  let nodes = 0;
  const visit = (value: unknown, depth: number): JsonValue => {
    nodes += 1;
    if (nodes > MAX_NODES || depth > MAX_DEPTH) throw new TypeError("bounded shape exceeded");
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
        throw new TypeError("sparse or extended array");
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

export function stage4CampaignApprovalDraftSha256(input: unknown): string | null {
  const snapshot = snapshotJson(input);
  if (snapshot === null) return null;
  return createHash("sha256")
    .update("cogs.stage4/campaign-approval-draft/v1", "utf8")
    .update(Uint8Array.of(0))
    .update(canonicalJson(snapshot), "utf8")
    .digest("hex");
}

function attemptedPromotion(value: JsonRecord): boolean {
  const approval = value.approval;
  const attempt = value.attempt;
  return (
    value.execution_authorized === true ||
    (approval !== null && typeof approval === "object" && !Array.isArray(approval) && approval.state === "approved") ||
    (attempt !== null &&
      typeof attempt === "object" &&
      !Array.isArray(attempt) &&
      (attempt.maximum_attempts !== 1 || attempt.retry !== "prohibited"))
  );
}

function verdict(reason: Stage4CampaignApprovalReason, digest: string | null): Stage4CampaignApprovalVerdict {
  const valid = reason === "STAGE4_APPROVAL_DRAFT_VALID_BLOCKED";
  return Object.freeze({
    version: "cogs.stage4-campaign-approval-verdict/v1",
    authority: "local-static-unapproved-envelope-classifier",
    draft_valid: valid,
    approval_present: false,
    execution_authorized: false,
    retry_authorized: false,
    provider_truth_observed: false,
    stage4_exit_satisfied: false,
    envelope_sha256: digest,
    status: valid ? "valid-unapproved-blocked-draft" : "preserve-uncertain",
    reason_code: reason,
  });
}

/**
 * Classifies only an absent/unapproved #358 envelope draft. It performs no I/O
 * and this v1 domain has no approved or executable state.
 */
export function classifyStage4CampaignApprovalDraft(input: unknown): Stage4CampaignApprovalVerdict {
  const snapshot = snapshotJson(input);
  if (snapshot === null) return verdict("STAGE4_APPROVAL_DRAFT_INVALID_SHAPE", null);
  const digest = stage4CampaignApprovalDraftSha256(snapshot);
  if (attemptedPromotion(snapshot)) return verdict("STAGE4_APPROVAL_DRAFT_AUTHORITY_PROMOTION", digest);
  if (!validateDraft(snapshot)) return verdict("STAGE4_APPROVAL_DRAFT_INVALID_SHAPE", digest);
  return verdict("STAGE4_APPROVAL_DRAFT_VALID_BLOCKED", digest);
}
