import { authorizeCogsPolicyAction, type CogsPolicyDecision } from "./static-policy.ts";

export type CogsPolicyAuthorizer = (input: unknown) => CogsPolicyDecision;

export class CogsPolicyDeniedError extends Error {
  public readonly code = "COGS_POLICY_DENIED";
  public constructor() {
    super("policy denied");
    this.name = "CogsPolicyDeniedError";
  }
}

export function requireCogsPolicyAllow(
  input: unknown,
  authorizer: CogsPolicyAuthorizer = authorizeCogsPolicyAction,
): void {
  try {
    if (!isAllowedDecisionSnapshot(authorizer(input))) throw new CogsPolicyDeniedError();
  } catch (error) {
    if (error instanceof CogsPolicyDeniedError) throw error;
    throw new CogsPolicyDeniedError();
  }
}

function isAllowedDecisionSnapshot(value: unknown): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  if (!Object.isFrozen(value)) return false;
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return false;
  if (Object.getOwnPropertySymbols(value).length > 0) return false;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.getOwnPropertyNames(value);
  if (!sameKeys(keys, ["version", "decision_id", "allow", "reason"])) return false;
  const version = dataValue(descriptors, "version");
  const decisionId = dataValue(descriptors, "decision_id");
  const allow = dataValue(descriptors, "allow");
  const reason = dataValue(descriptors, "reason");
  return (
    version === "cogs.policy-decision/v1alpha1" &&
    typeof decisionId === "string" &&
    /^sha256:[0-9a-f]{64}$/.test(decisionId) &&
    allow === true &&
    reason === "allowed"
  );
}

function dataValue(descriptors: PropertyDescriptorMap, key: string): unknown {
  const descriptor = descriptors[key];
  if (descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) return undefined;
  return descriptor.value;
}

function sameKeys(actual: readonly string[], expected: readonly string[]): boolean {
  if (actual.length !== expected.length) return false;
  const sortedActual = [...actual].sort();
  const sortedExpected = [...expected].sort();
  return sortedActual.every((key, index) => key === sortedExpected[index]);
}
