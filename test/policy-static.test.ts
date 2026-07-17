import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options } from "ajv";
import { CogsPolicyDeniedError, requireCogsPolicyAllow } from "../src/policy/require-policy.ts";
import { authorizeCogsPolicyAction } from "../src/policy/static-policy.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const fixturePath = resolve(root, "test/fixtures/policy/opa-parity-v1alpha1.json");
const policySchema = JSON.parse(readFileSync(resolve(root, "schemas/policy-v1alpha1.json"), "utf8")) as object;
const decisionSchema = JSON.parse(
  readFileSync(resolve(root, "schemas/policy-decision-v1alpha1.json"), "utf8"),
) as object;

const base = {
  version: "cogs.policy/v1alpha1",
  user: "user-123",
  session: "session-123",
} as const;

function envelope(action: string, resource: string, attributes: Record<string, unknown>): Record<string, unknown> {
  return { ...base, action, resource, attributes };
}

const allowedCases = [
  envelope("mount.validate", "workspace", { mount_class: "workspace" }),
  envelope("mount.validate", "shared_skill", { mount_class: "shared_skill" }),
  envelope("mount.validate", "user_skill", { mount_class: "user_skill" }),
  envelope("mount.validate", "proxy_public", { mount_class: "proxy_public" }),
  envelope("config.validate", "launch", { integration_count: 2, mount_classes: ["workspace", "shared_skill"] }),
  envelope("config.validate", "egress_route_plan", { route_count: 3, credential_route_count: 1 }),
  envelope("tool.enable", "read", { tool: "read" }),
  envelope("tool.enable", "write", { tool: "write" }),
  envelope("tool.enable", "edit", { tool: "edit" }),
  envelope("tool.enable", "bash", { tool: "bash" }),
  envelope("tool.dispatch", "bash", { tool: "bash" }),
  envelope("tool.dispatch", "read", { tool: "read", path_class: "workspace" }),
  envelope("tool.dispatch", "read", { tool: "read", path_class: "shared_skill" }),
  envelope("tool.dispatch", "read", { tool: "read", path_class: "user_skill" }),
  envelope("tool.dispatch", "write", { tool: "write", path_class: "workspace" }),
  envelope("tool.dispatch", "edit", { tool: "edit", path_class: "workspace" }),
  envelope("egress.authorize", "route-123", {
    integration_id: "integration-123",
    route_id: "route-123",
    method: "GET",
    credential_required: true,
  }),
  envelope("egress.authorize", "route-456", {
    integration_id: "integration-123",
    route_id: "route-456",
    method: "CONNECT",
    credential_required: false,
  }),
  envelope("secret.use", "egress_integration_credential", {
    secret_class: "egress_integration_credential",
    integration_id: "integration-123",
  }),
  envelope("secret.use", "model_api_key_runtime", { secret_class: "model_api_key_runtime" }),
  envelope("secret.use", "proxy_capability", { secret_class: "proxy_capability" }),
  envelope("secret.use", "proxy_leaf_key", { secret_class: "proxy_leaf_key" }),
  envelope("export.create", "local_bundle", {
    mode: "raw",
    sensitive: true,
    sanitized: false,
    anonymized: false,
    attachments_included: false,
  }),
];

const denialCases: Array<{ name: string; input: unknown; reason: string }> = [
  { name: "unknown action", input: envelope("unknown.action", "bash", { tool: "bash" }), reason: "unknown_action" },
  { name: "wrong resource", input: envelope("tool.enable", "curl", { tool: "curl" }), reason: "unsupported_surface" },
  {
    name: "malformed extra top",
    input: { ...envelope("tool.dispatch", "bash", { tool: "bash" }), extra: true },
    reason: "invalid_envelope",
  },
  {
    name: "raw command rejected",
    input: envelope("tool.dispatch", "bash", { tool: "bash", command: "SECRET_COMMAND" }),
    reason: "invalid_envelope",
  },
  {
    name: "raw path rejected",
    input: envelope("tool.dispatch", "read", { tool: "read", path_class: "workspace", path: "/host/secret" }),
    reason: "invalid_envelope",
  },
  {
    name: "source rejected",
    input: envelope("config.validate", "launch", {
      integration_count: 1,
      mount_classes: ["workspace"],
      source: "private source",
    }),
    reason: "invalid_envelope",
  },
  {
    name: "query rejected",
    input: envelope("egress.authorize", "route-123", {
      integration_id: "integration-123",
      route_id: "route-123",
      method: "GET",
      credential_required: false,
      query: "token=secret",
    }),
    reason: "invalid_envelope",
  },
  {
    name: "secret value rejected",
    input: envelope("secret.use", "model_api_key_runtime", {
      secret_class: "model_api_key_runtime",
      secret: "sk-real",
    }),
    reason: "invalid_envelope",
  },
  {
    name: "oauth refresh class denied",
    input: envelope("secret.use", "oauth_refresh_token", { secret_class: "oauth_refresh_token" }),
    reason: "unsupported_surface",
  },
  {
    name: "write only workspace",
    input: envelope("tool.dispatch", "write", { tool: "write", path_class: "shared_skill" }),
    reason: "unsupported_surface",
  },
  {
    name: "sanitized export mode denied",
    input: envelope("export.create", "local_bundle", {
      mode: "sanitized",
      sensitive: true,
      sanitized: true,
      anonymized: false,
      attachments_included: false,
    }),
    reason: "mode_denied",
  },
  { name: "restore reserved", input: envelope("restore.request", "restore", {}), reason: "restore_reserved" },
];

test("require policy helper converts hostile authorizer results into generic denial", () => {
  const allowed = Object.freeze({
    version: "cogs.policy-decision/v1alpha1" as const,
    decision_id: `sha256:${"a".repeat(64)}` as const,
    allow: true,
    reason: "allowed" as const,
  });
  assert.doesNotThrow(() => requireCogsPolicyAllow(envelope("tool.dispatch", "bash", { tool: "bash" }), () => allowed));
  for (const authorizer of [
    () => {
      throw new Error("SECRET_THROW");
    },
    () =>
      new Proxy(allowed, {
        getOwnPropertyDescriptor() {
          throw new Error("SECRET_PROXY");
        },
      }),
    () => {
      const value: Record<string, unknown> = { ...allowed };
      Object.defineProperty(value, "extra", {
        enumerable: true,
        get() {
          throw new Error("SECRET_ACCESSOR");
        },
      });
      return value;
    },
    () => ({ ...allowed, [Symbol("secret")]: true }),
    () => ({ ...allowed, extra: true }),
    () => ({ ...allowed, allow: false }),
    () => ({
      version: "cogs.policy-decision/v1alpha1" as const,
      decision_id: `sha256:${"a".repeat(64)}` as const,
      allow: true,
      reason: "allowed" as const,
    }),
  ]) {
    assert.throws(
      () => requireCogsPolicyAllow(envelope("tool.dispatch", "bash", { tool: "bash" }), authorizer as never),
      CogsPolicyDeniedError,
    );
  }
});

test("static policy allows only exact authorized combinations", () => {
  for (const input of allowedCases) {
    const decision = authorizeCogsPolicyAction(input);
    assert.deepEqual(Object.keys(decision), ["version", "decision_id", "allow", "reason"]);
    assert.equal(Object.isFrozen(decision), true);
    assert.equal(decision.version, "cogs.policy-decision/v1alpha1");
    assert.match(decision.decision_id, /^sha256:[0-9a-f]{64}$/);
    assert.equal(decision.allow, true, JSON.stringify(input));
    assert.equal(decision.reason, "allowed");
  }
});

test("static policy returns bounded deny reasons", () => {
  for (const { name, input, reason } of denialCases) {
    const decision = authorizeCogsPolicyAction(input);
    assert.equal(decision.allow, false, name);
    assert.equal(decision.reason, reason, name);
    assert.match(decision.decision_id, /^sha256:[0-9a-f]{64}$/);
  }
});

test("denied and malformed input uses fixed non-content sentinel decision ids", () => {
  const invalidA = authorizeCogsPolicyAction(null);
  const invalidB = authorizeCogsPolicyAction({
    ...base,
    action: "tool.dispatch",
    resource: "bash",
    attributes: { tool: "bash" },
    leak: "x",
  });
  const invalidCommandA = authorizeCogsPolicyAction({
    ...base,
    action: "tool.dispatch",
    resource: "bash",
    attributes: { tool: "bash", command: "SECRET_COMMAND_A" },
  });
  const invalidCommandB = authorizeCogsPolicyAction({
    ...base,
    action: "tool.dispatch",
    resource: "bash",
    attributes: { tool: "bash", command: "SECRET_COMMAND_B" },
  });
  const invalidPath = authorizeCogsPolicyAction({
    ...base,
    action: "tool.dispatch",
    resource: "read",
    attributes: { tool: "read", path_class: "workspace", path: "/host/SECRET_PATH" },
  });
  const invalidQuery = authorizeCogsPolicyAction({
    ...base,
    action: "egress.authorize",
    resource: "route-123",
    attributes: {
      integration_id: "integration-123",
      route_id: "route-123",
      method: "GET",
      credential_required: false,
      query: "token=SECRET_QUERY",
    },
  });
  const invalidSecret = authorizeCogsPolicyAction({
    ...base,
    action: "secret.use",
    resource: "model_api_key_runtime",
    attributes: { secret_class: "model_api_key_runtime", secret: "SECRET_VALUE" },
  });
  assert.equal(invalidA.reason, "invalid_envelope");
  for (const decision of [invalidB, invalidCommandA, invalidCommandB, invalidPath, invalidQuery, invalidSecret]) {
    assert.equal(decision.reason, "invalid_envelope");
    assert.equal(decision.decision_id, invalidA.decision_id);
    assert.equal(JSON.stringify(decision).includes("SECRET"), false);
  }

  const unsupportedA = authorizeCogsPolicyAction(envelope("tool.enable", "curl-secret-a", { tool: "curl-secret-a" }));
  const unsupportedB = authorizeCogsPolicyAction(envelope("tool.enable", "curl-secret-b", { tool: "curl-secret-b" }));
  assert.equal(unsupportedA.reason, "unsupported_surface");
  assert.equal(unsupportedA.decision_id, unsupportedB.decision_id);

  const modeDeniedA = authorizeCogsPolicyAction(
    envelope("export.create", "local_bundle", {
      mode: "archive-secret-a",
      sensitive: true,
      sanitized: false,
      anonymized: false,
      attachments_included: false,
    }),
  );
  const modeDeniedB = authorizeCogsPolicyAction(
    envelope("export.create", "local_bundle", {
      mode: "archive-secret-b",
      sensitive: true,
      sanitized: false,
      anonymized: false,
      attachments_included: false,
    }),
  );
  assert.equal(modeDeniedA.reason, "mode_denied");
  assert.equal(modeDeniedA.decision_id, modeDeniedB.decision_id);
});

test("hostile getters symbols proxies toJSON and inherited fields do not throw or leak", () => {
  let getterInvoked = false;
  const getterEnvelope: Record<string, unknown> = { ...envelope("tool.dispatch", "bash", { tool: "bash" }) };
  Object.defineProperty(getterEnvelope, "evil", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("getter secret");
    },
  });
  assert.equal(authorizeCogsPolicyAction(getterEnvelope).reason, "invalid_envelope");
  assert.equal(getterInvoked, false);

  const symbolEnvelope = { ...envelope("tool.dispatch", "bash", { tool: "bash" }), [Symbol("secret")]: "hidden" };
  assert.equal(authorizeCogsPolicyAction(symbolEnvelope).reason, "invalid_envelope");

  const inherited = Object.create({ inherited: true }) as Record<string, unknown>;
  Object.assign(inherited, envelope("tool.dispatch", "bash", { tool: "bash" }));
  assert.equal(authorizeCogsPolicyAction(inherited).reason, "invalid_envelope");

  const toJson = {
    ...envelope("tool.dispatch", "bash", { tool: "bash" }),
    toJSON: () => assert.fail("toJSON invoked"),
  };
  assert.equal(authorizeCogsPolicyAction(toJson).reason, "invalid_envelope");

  const proxy = new Proxy(envelope("tool.dispatch", "bash", { tool: "bash" }), {
    getOwnPropertyDescriptor() {
      throw new Error("proxy secret");
    },
  });
  assert.equal(authorizeCogsPolicyAction(proxy).reason, "invalid_envelope");

  let attributeGetterInvoked = false;
  const accessorAttributes: Record<string, unknown> = { tool: "bash" };
  Object.defineProperty(accessorAttributes, "command", {
    enumerable: true,
    get() {
      attributeGetterInvoked = true;
      throw new Error("attribute getter secret");
    },
  });
  assert.equal(
    authorizeCogsPolicyAction(envelope("tool.dispatch", "bash", accessorAttributes)).reason,
    "invalid_envelope",
  );
  assert.equal(attributeGetterInvoked, false);

  const nonEnumerableAttributes: Record<string, unknown> = { tool: "bash" };
  Object.defineProperty(nonEnumerableAttributes, "hidden", { enumerable: false, value: "secret" });
  assert.equal(
    authorizeCogsPolicyAction(envelope("tool.dispatch", "bash", nonEnumerableAttributes)).reason,
    "invalid_envelope",
  );

  const symbolAttributes = { tool: "bash", [Symbol("secret")]: "hidden" };
  assert.equal(
    authorizeCogsPolicyAction(envelope("tool.dispatch", "bash", symbolAttributes)).reason,
    "invalid_envelope",
  );

  const proxyAttributes = new Proxy(
    { tool: "bash" },
    {
      getOwnPropertyDescriptor() {
        throw new Error("attribute proxy secret");
      },
    },
  );
  assert.equal(
    authorizeCogsPolicyAction(envelope("tool.dispatch", "bash", proxyAttributes)).reason,
    "invalid_envelope",
  );

  const nullPrototypeAttributes = Object.create(null) as Record<string, unknown>;
  nullPrototypeAttributes.tool = "bash";
  assert.equal(authorizeCogsPolicyAction(envelope("tool.dispatch", "bash", nullPrototypeAttributes)).reason, "allowed");
});

test("strict array snapshots reject hostile arrays and isolate mutation", () => {
  const valid = envelope("config.validate", "launch", {
    integration_count: 1,
    mount_classes: ["workspace", "shared_skill"],
  });
  const decision = authorizeCogsPolicyAction(valid);
  assert.equal(decision.reason, "allowed");
  const originalDecisionId = decision.decision_id;
  ((valid.attributes as Record<string, unknown>).mount_classes as string[])[0] = "user_skill";
  assert.equal(decision.reason, "allowed");
  assert.equal(decision.decision_id, originalDecisionId);
  assert.notEqual(
    authorizeCogsPolicyAction({
      ...valid,
      attributes: { integration_count: 1, mount_classes: ["user_skill", "shared_skill"] },
    }).decision_id,
    originalDecisionId,
  );

  let arrayGetterInvoked = false;
  const getterArray = ["workspace"];
  Object.defineProperty(getterArray, "0", {
    enumerable: true,
    get() {
      arrayGetterInvoked = true;
      throw new Error("array getter secret");
    },
  });
  const invalidSentinel = authorizeCogsPolicyAction(null).decision_id;
  assert.equal(
    authorizeCogsPolicyAction(
      envelope("config.validate", "launch", { integration_count: 1, mount_classes: getterArray }),
    ).decision_id,
    invalidSentinel,
  );
  assert.equal(arrayGetterInvoked, false);

  const proxyArray = new Proxy(["workspace"], {
    getOwnPropertyDescriptor() {
      throw new Error("array proxy secret");
    },
  });
  assert.equal(
    authorizeCogsPolicyAction(
      envelope("config.validate", "launch", { integration_count: 1, mount_classes: proxyArray }),
    ).decision_id,
    invalidSentinel,
  );

  const holeArray = ["workspace"];
  holeArray.length = 3;
  holeArray[2] = "shared_skill";
  assert.equal(
    authorizeCogsPolicyAction(envelope("config.validate", "launch", { integration_count: 1, mount_classes: holeArray }))
      .decision_id,
    invalidSentinel,
  );

  const symbolArray = ["workspace"] as Array<string> & { [key: symbol]: string };
  symbolArray[Symbol("secret")] = "hidden";
  assert.equal(
    authorizeCogsPolicyAction(
      envelope("config.validate", "launch", { integration_count: 1, mount_classes: symbolArray }),
    ).decision_id,
    invalidSentinel,
  );

  const extraArray = ["workspace"] as string[] & { extra?: string };
  extraArray.extra = "secret";
  assert.equal(
    authorizeCogsPolicyAction(
      envelope("config.validate", "launch", { integration_count: 1, mount_classes: extraArray }),
    ).decision_id,
    invalidSentinel,
  );
});

test("canonical decision id is stable across key order and isolated from later mutation", () => {
  const first = envelope("egress.authorize", "route-123", {
    integration_id: "integration-123",
    route_id: "route-123",
    method: "POST",
    credential_required: true,
  });
  const second = {
    attributes: { credential_required: true, method: "POST", route_id: "route-123", integration_id: "integration-123" },
    resource: "route-123",
    session: "session-123",
    user: "user-123",
    action: "egress.authorize",
    version: "cogs.policy/v1alpha1",
  };
  const firstDecision = authorizeCogsPolicyAction(first);
  const secondDecision = authorizeCogsPolicyAction(second);
  assert.equal(firstDecision.decision_id, secondDecision.decision_id);

  (first.attributes as Record<string, unknown>).method = "GET";
  assert.equal(firstDecision.reason, "allowed");
  assert.equal(Object.isFrozen(firstDecision), true);
});

test("policy and decision schemas validate static contract fixtures", () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
  const validatePolicy = ajv.compile(policySchema);
  const validateDecision = ajv.compile(decisionSchema);
  const fixtures = JSON.parse(readFileSync(fixturePath, "utf8")) as Array<{
    name: string;
    envelope: unknown;
    decision: unknown;
  }>;
  assert.ok(fixtures.length >= 10);
  for (const fixture of fixtures) {
    const actual = authorizeCogsPolicyAction(fixture.envelope);
    assert.deepEqual(actual, fixture.decision, fixture.name);
    assert.equal(validateDecision(actual), true, `${fixture.name}: ${ajv.errorsText(validateDecision.errors)}`);
    assert.equal(
      validateDecision({ ...actual, allow: !actual.allow }),
      false,
      `${fixture.name}: decision schema must couple allow and reason`,
    );
    if ((fixture.envelope as { action?: unknown }).action !== "unknown.action") {
      assert.equal(validatePolicy(fixture.envelope), true, `${fixture.name}: ${ajv.errorsText(validatePolicy.errors)}`);
    }
  }
});
