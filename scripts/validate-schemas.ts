import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import { type SecurityResultSemanticsInput, validateSecurityResultSemantics } from "./security-result-semantics.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const addFormats = require("ajv-formats") as (ajv: AjvCore) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const schemaDir = resolve(root, "schemas");
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
addFormats(ajv);

const schemaFiles = readdirSync(schemaDir)
  .filter((name) => name.endsWith(".json"))
  .sort();
for (const name of schemaFiles) {
  ajv.addSchema(JSON.parse(readFileSync(resolve(schemaDir, name), "utf8")));
}

const digest = `sha256:${"a".repeat(64)}`;
const opaque = "opaque-123";
const integration = {
  version: "cogs.integration/v1alpha1",
  id: "github-clone",
  preset_revision: digest,
  dns: { mode: "proxy-connect-authority", guest_resolution: false },
  rules: [
    {
      name: "github-api",
      host: "github.com",
      port: 443,
      methods: ["GET"],
      path_patterns: ["/*"],
      path_policy: { strategy: "segment-glob", normalization: "reject-ambiguous" },
      query_policy: { mode: "deny" },
      redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
      inject_auth: true,
    },
  ],
  auth: {
    type: "bearer_header",
    header: "Authorization",
    prefix: "Bearer ",
    placeholder: "COGS_PLACEHOLDER_GITHUB",
    secret_handle: "users/opaque/integrations/github",
  },
};

const validSamples: Record<string, unknown> = {
  "egress-case-manifest-v1alpha1.json": {
    version: "cogs.egress-cases/v1alpha1",
    cases: [
      {
        id: "route.allowed",
        group: "identity-route",
        timeout_ms: 5000,
        profiles: ["insecure-container", "linux-kvm"],
        dependencies: ["identity", "authorization"],
      },
    ],
  },
  "integration-v1alpha1.json": integration,
  "launch-v1alpha1.json": {
    version: "cogs.dev/v1alpha1",
    user_id: opaque,
    session_id: "session-123",
    workspace_id: "workspace-123",
    sandbox: {
      ssh_endpoint: "sandbox.internal:22",
      ssh_host_key: `SHA256:${"A".repeat(43)}`,
      client_key_path: "/run/cogs/ssh/id",
      proxy_auth_handle: "sessions/session-123/proxy-capability",
    },
    model: { provider: "anthropic", id: "model-id", credential_handle: "users/opaque/models/anthropic" },
    skills: {
      shared_revision: digest,
      shared_path: "/shared/skills",
      user_revision: digest,
      user_path: "/user/skills",
    },
    integrations: [integration],
    limits: { cpu: 2, memory_bytes: 4_294_967_296, tool_timeout_seconds: 900, max_tool_output_bytes: 1_048_576 },
  },
  "events-v1alpha1.json": {
    version: "cogs.event/v1alpha1",
    seq: 0,
    timestamp: "2026-07-10T12:00:00Z",
    session_id: "session-123",
    kind: "run_settled",
    correlation_id: "correlation-123",
    payload: {},
  },
  "policy-v1alpha1.json": {
    version: "cogs.policy/v1alpha1",
    action: "tool.dispatch",
    user: opaque,
    session: "session-123",
    resource: "bash",
    attributes: { tool: "bash" },
  },
  "policy-decision-v1alpha1.json": {
    version: "cogs.policy-decision/v1alpha1",
    decision_id: digest,
    allow: true,
    reason: "allowed",
  },
  "export-manifest-v1alpha1.json": {
    version: "cogs.export/v1alpha1",
    cogs_version: "0.0.0",
    pi_version: "0.80.6",
    session_id: "session-123",
    created_at: "2026-07-10T12:00:00Z",
    mode: "raw",
    files: [
      { path: "git-map.json", sha256: "b".repeat(64), bytes: 1 },
      { path: "session.jsonl", sha256: "a".repeat(64), bytes: 1 },
      { path: "skills.json", sha256: "c".repeat(64), bytes: 1 },
      { path: "transform-report.json", sha256: "d".repeat(64), bytes: 1 },
      { path: "warnings.json", sha256: "e".repeat(64), bytes: 1 },
    ],
    skills: { shared_revision: digest, user_revision: digest },
    attachments_included: false,
  },
  "guest-probe-result-v1alpha1.json": {
    version: "cogs.guest-probe/v1alpha1",
    operation: "tcp",
    outcome: "reached",
    detail_code: "connected",
    duration_ms: 10,
    root: true,
    artifact_sha256: "a".repeat(64),
  },
  "git-mapping-v1alpha1.json": {
    version: "cogs.git-mapping/v1alpha1",
    repo: "repo-123",
    commit: "a".repeat(40),
    session: "session-123",
    entry: "abcdef12",
    turn: 1,
    observed_at: "2026-07-10T12:00:00Z",
    confidence: "exact",
  },
  "security-report-v1alpha1.json": JSON.parse(
    readFileSync(resolve(root, "docs/security-evidence/example-report.json"), "utf8"),
  ),
};

function validatorFor(file: string): ValidateFunction {
  const schema = JSON.parse(readFileSync(resolve(schemaDir, file), "utf8")) as { $id: string };
  const validator = ajv.getSchema(schema.$id);
  assert.ok(validator, `schema ${file} was not registered`);
  return validator;
}

for (const [file, sample] of Object.entries(validSamples)) {
  const validate = validatorFor(file);
  assert.equal(validate(sample), true, `${file}: ${ajv.errorsText(validate.errors)}`);

  const withUnknown = { ...(sample as Record<string, unknown>), unexpected_security_field: true };
  assert.equal(validate(withUnknown), false, `${file} must reject unknown top-level fields`);
}

const decisionValidator = validatorFor("policy-decision-v1alpha1.json");
for (const invalidDecision of [
  { version: "cogs.policy-decision/v1alpha1", decision_id: digest, allow: true, reason: "invalid_envelope" },
  { version: "cogs.policy-decision/v1alpha1", decision_id: digest, allow: false, reason: "allowed" },
]) {
  assert.equal(decisionValidator(invalidDecision), false, "policy decisions must couple allow with reason");
}

const launchValidator = validatorFor("launch-v1alpha1.json");
const launchWithInlineSecret = structuredClone(validSamples["launch-v1alpha1.json"]) as Record<string, unknown>;
launchWithInlineSecret.secret = "real-secret-must-never-be-inline";
assert.equal(launchValidator(launchWithInlineSecret), false, "launch documents must reject inline secret fields");

const reportValidator = validatorFor("security-report-v1alpha1.json");
const invalidAuthority = structuredClone(validSamples["security-report-v1alpha1.json"]) as Record<string, unknown>;
invalidAuthority.authority = "authoritative-local";
assert.equal(reportValidator(invalidAuthority), false, "insecure profiles cannot claim authoritative evidence");

assert.deepEqual(
  validateSecurityResultSemantics({ result: "pass", release_eligible: true, dependency_modes: { audit: "stubbed" } }),
  [
    "a passing test with a stubbed dependency requires result=stubbed",
    "release-eligible test dependencies must all be real",
  ],
);
assert.deepEqual(
  validateSecurityResultSemantics({ result: "fail", release_eligible: false, dependency_modes: { audit: "stubbed" } }),
  [],
  "a real mechanism failure must remain fail even when a dependency is stubbed",
);
const exampleReport = validSamples["security-report-v1alpha1.json"] as { tests: SecurityResultSemanticsInput[] };
for (const result of exampleReport.tests) assert.deepEqual(validateSecurityResultSemantics(result), []);

for (const reportPath of process.argv.slice(2)) {
  const report = JSON.parse(readFileSync(resolve(reportPath), "utf8")) as {
    authority: string;
    profile: string;
    started_at: string;
    completed_at: string;
    environment: { metadata?: Record<string, unknown> };
    tests: Array<SecurityResultSemanticsInput & { id: string }>;
  };
  assert.equal(reportValidator(report), true, `${reportPath}: ${ajv.errorsText(reportValidator.errors)}`);
  assert.ok(
    Date.parse(report.completed_at) >= Date.parse(report.started_at),
    `${reportPath}: completion precedes start`,
  );
  assert.equal(
    new Set(report.tests.map((test) => test.id)).size,
    report.tests.length,
    `${reportPath}: duplicate test IDs`,
  );
  for (const [index, result] of report.tests.entries()) {
    assert.deepEqual(
      validateSecurityResultSemantics(result),
      [],
      `${reportPath}: invalid test semantics at index ${index}`,
    );
    if (result.release_eligible) {
      assert.notEqual(
        report.authority,
        "functional-only",
        `${reportPath}: functional profiles cannot be release eligible`,
      );
    }
    if (result.id === "runner.kvm-acceleration" && result.result === "pass") {
      for (const field of ["kvm_present", "kvm_enabled", "guest_root", "distinct_boot_ids"]) {
        assert.equal(
          report.environment.metadata?.[field],
          true,
          `${reportPath}: passing KVM evidence requires ${field}=true`,
        );
      }
    }
  }
}

console.log(`Validated ${schemaFiles.length} schemas, valid examples, negative cases, and report semantics.`);
