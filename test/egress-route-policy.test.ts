import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { canonicalPresetPolicyRevision } from "../src/egress/preset-revision.ts";
import { EgressRoutePolicyError, lowerLaunchEgressRoutePlan } from "../src/egress/route-policy.ts";
import { validateLaunchConfig } from "../src/launch/config.ts";

const digest = `sha256:${"a".repeat(64)}`;

function bindRevision<T extends Record<string, unknown>>(integration: T): T {
  return { ...integration, preset_revision: canonicalPresetPolicyRevision(integration) };
}

function preset(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(import.meta.dirname, `../integrations/presets/${name}`), "utf8")) as Record<
    string,
    unknown
  >;
}

function launch(integrations: unknown[], userId = "preset-user") {
  return validateLaunchConfig({
    version: "cogs.dev/v1alpha1",
    user_id: userId,
    session_id: "session-1",
    workspace_id: "workspace-1",
    sandbox: {
      ssh_endpoint: "sandbox.local:2222",
      ssh_host_key: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      client_key_path: "/run/cogs/ssh/session-1",
      proxy_auth_handle: "sessions/session-1/proxy",
    },
    model: { provider: "provider-1", id: "model", credential_handle: `users/${userId}/model` },
    skills: {
      shared_revision: digest,
      shared_path: "/shared/skills",
      user_revision: digest,
      user_path: "/user/skills",
    },
    integrations,
    limits: { cpu: 1, memory_bytes: 268435456, tool_timeout_seconds: 30, max_tool_output_bytes: 4096 },
  });
}

function sampleIntegration(update?: (integration: Record<string, unknown>) => void): Record<string, unknown> {
  const integration = structuredClone(preset("github-smart-http-v1.json")) as Record<string, unknown>;
  update?.(integration);
  return bindRevision(integration);
}

function firstRule(integration: Record<string, unknown>): Record<string, unknown> {
  const [rule] = integration.rules as Array<Record<string, unknown>>;
  assert.ok(rule);
  return rule;
}

test("valid presets lower into frozen secret-free deterministic route policy", () => {
  const plan = lowerLaunchEgressRoutePlan(
    launch([preset("npm-v1.json"), preset("github-smart-http-v1.json"), preset("pypi-v1.json")]),
  );
  assert.equal(Object.isFrozen(plan), true);
  assert.equal(plan.routeCount, 9);
  assert.deepEqual(
    plan.integrations.map((integration) => integration.id),
    ["github-smart-http", "npm", "pypi"],
  );
  const rendered = JSON.stringify(plan);
  assert.doesNotMatch(rendered, /fixture|real-value|Bearer [A-Za-z0-9]|Basic [A-Za-z0-9+/]/);
  assert.match(rendered, /users\/preset-user\/integrations\/github/);
  assert.equal(
    rendered,
    JSON.stringify(
      lowerLaunchEgressRoutePlan(
        launch([preset("pypi-v1.json"), preset("github-smart-http-v1.json"), preset("npm-v1.json")]),
      ),
    ),
  );
});

test("Git fetch exact query and query denial compile into anchored path matches", () => {
  const routes =
    lowerLaunchEgressRoutePlan(launch([preset("github-smart-http-v1.json")])).integrations[0]?.routes ?? [];
  const refs = routes.find((route) => route.method === "GET");
  const pack = routes.find((route) => route.method === "POST");
  assert.deepEqual(refs?.queryPolicy, {
    mode: "exact",
    values: ["service=git-upload-pack"],
    canonical: "service=git-upload-pack",
  });
  assert.equal(refs?.pathMatch.kind, "safe_regex");
  assert.equal(refs?.pathMatch.value, "^/[^/?#]+/[^/?#]+\\.git/info/refs\\?service=git-upload-pack$");
  assert.equal(pack?.queryPolicy.mode, "deny");
  assert.equal(pack?.pathMatch.value.includes("\\?"), false);
  assert.match(pack?.pathMatch.value ?? "", /^\^/);
  assert.match(pack?.pathMatch.value ?? "", /\$$/);
  const denyMatcher = new RegExp(pack?.pathMatch.value ?? "");
  assert.equal(denyMatcher.test("/owner/repo.git/git-upload-pack"), true);
  assert.equal(denyMatcher.test("/owner/repo.git/git-upload-pack?x=1"), false);
  assert.equal(denyMatcher.test("/owner/repo.git/git-upload-pack#fragment"), false);
});

test("partial segment globs and prefix boundaries are deterministic and bounded", () => {
  const npm = lowerLaunchEgressRoutePlan(launch([preset("npm-v1.json")])).integrations[0]?.routes ?? [];
  assert.ok(npm.some((route) => route.pathPattern === "/@*/*" && route.pathMatch.value.includes("@[^/?#]+")));
  assert.ok(npm.some((route) => route.pathPattern === "/*/-/*.tgz" && route.pathMatch.value.includes("[^/?#]+\\.tgz")));
  const pypi = lowerLaunchEgressRoutePlan(launch([preset("pypi-v1.json")])).integrations[0]?.routes ?? [];
  const files = pypi.find((route) => route.ruleName === "pypi-files");
  assert.equal(files?.pathStrategy, "prefix");
  assert.equal(files?.pathMatch.value, "^/packages(?:/[^?#]*)?$");
  assert.ok(pypi.some((route) => route.pathPattern === "/simple/*/" && route.pathMatch.value === "^/simple/[^/?#]+/$"));
});

test("hostile query, redirect, path, method, duplicate, and budget policies fail generically", () => {
  const reject = (integration: Record<string, unknown>) => {
    assert.throws(
      () => lowerLaunchEgressRoutePlan({ user_id: "preset-user", integrations: [bindRevision(integration)] } as never),
      EgressRoutePolicyError,
    );
  };
  reject(sampleIntegration((integration) => (firstRule(integration).query_policy = { mode: "bounded-redacted" })));
  reject(
    sampleIntegration(
      (integration) =>
        (firstRule(integration).query_policy = {
          mode: "exact",
          values: ["b=2", "a=1"],
        }),
    ),
  );
  reject(
    sampleIntegration(
      (integration) =>
        (firstRule(integration).query_policy = {
          mode: "exact",
          values: ["a=1", "a=2"],
        }),
    ),
  );
  reject(
    sampleIntegration(
      (integration) =>
        (firstRule(integration).redirects = {
          mode: "allow-declared",
          max_hops: 1,
          allowed_hosts: ["github.com"],
        }),
    ),
  );
  for (const bad of ["/%2f", "/**/x", "/../x", "/a//b", "/bad\u0001"]) {
    reject(sampleIntegration((integration) => (firstRule(integration).path_patterns = [bad])));
  }
  reject(sampleIntegration((integration) => (firstRule(integration).methods = ["GET", "PUT"])));
  reject(sampleIntegration((integration) => (integration.unbounded_extra = "reject")));
  reject(sampleIntegration((integration) => ((integration.dns as Record<string, unknown>).extra = "reject")));
  reject(sampleIntegration((integration) => (firstRule(integration).extra = "reject")));
  reject(
    sampleIntegration(
      (integration) => ((firstRule(integration).path_policy as Record<string, unknown>).extra = "reject"),
    ),
  );
  reject(
    sampleIntegration(
      (integration) => ((firstRule(integration).query_policy as Record<string, unknown>).extra = "reject"),
    ),
  );
  reject(
    sampleIntegration(
      (integration) => ((firstRule(integration).redirects as Record<string, unknown>).extra = "reject"),
    ),
  );
  reject(sampleIntegration((integration) => ((integration.auth as Record<string, unknown>).extra = "reject")));
  reject(
    sampleIntegration(
      (integration) =>
        ((integration.auth as Record<string, unknown>).secret_handle = "sessions/session-1/integrations/github"),
    ),
  );
  assert.throws(() => lowerLaunchEgressRoutePlan(launch([sampleIntegration()], "other-user")), EgressRoutePolicyError);
  reject(
    sampleIntegration((integration) => (integration.rules as unknown[]).push((integration.rules as unknown[])[0])),
  );
  reject(
    sampleIntegration((integration) => {
      const [first] = integration.rules as Array<Record<string, unknown>>;
      const duplicate = structuredClone(first) as Record<string, unknown>;
      duplicate.name = "same-matcher-no-auth";
      duplicate.inject_auth = false;
      (integration.rules as Array<Record<string, unknown>>).push(duplicate);
    }),
  );
  const longNames = sampleIntegration((integration) => {
    integration.id = "i".repeat(128);
    firstRule(integration).name = "r".repeat(128);
  });
  const longPlan = lowerLaunchEgressRoutePlan(launch([longNames]));
  assert.ok(longPlan.integrations[0]?.routes.every((route) => route.routeId.length <= 128));
  reject(
    sampleIntegration((integration) => {
      const rule = firstRule(integration);
      rule.path_policy = { strategy: "prefix", normalization: "reject-ambiguous" };
      rule.path_patterns = ["/repo"];
      (integration.rules as Array<Record<string, unknown>>).push({
        ...structuredClone(rule),
        name: "overlapping-exact",
        path_policy: { strategy: "exact", normalization: "reject-ambiguous" },
        path_patterns: ["/repo/pkg"],
      });
    }),
  );
  reject(
    sampleIntegration((integration) => {
      const rule = firstRule(integration);
      rule.path_policy = { strategy: "prefix", normalization: "reject-ambiguous" };
      rule.path_patterns = ["/foo"];
      (integration.rules as Array<Record<string, unknown>>).push({
        ...structuredClone(rule),
        name: "overlapping-leading-wildcard",
        path_policy: { strategy: "segment-glob", normalization: "reject-ambiguous" },
        path_patterns: ["/*"],
      });
    }),
  );
  reject(
    sampleIntegration((integration) => {
      const rule = firstRule(integration);
      rule.path_policy = { strategy: "prefix", normalization: "reject-ambiguous" };
      rule.path_patterns = ["/@scope"];
      (integration.rules as Array<Record<string, unknown>>).push({
        ...structuredClone(rule),
        name: "overlapping-partial-glob",
        path_policy: { strategy: "segment-glob", normalization: "reject-ambiguous" },
        path_patterns: ["/@*/*"],
      });
    }),
  );
  let integrationGetterReads = 0;
  const tooManyIntegrations = Array.from({ length: 17 }, () => ({}));
  Object.defineProperty(tooManyIntegrations[16], "id", {
    get() {
      integrationGetterReads += 1;
      return "must-not-read";
    },
  });
  assert.throws(
    () => lowerLaunchEgressRoutePlan({ user_id: "preset-user", integrations: tooManyIntegrations } as never),
    EgressRoutePolicyError,
  );
  assert.equal(integrationGetterReads, 0);
  let ruleGetterReads = 0;
  const manyRules = structuredClone(preset("github-smart-http-v1.json")) as Record<string, unknown>;
  const rules = Array.from({ length: 65 }, () => firstRule(manyRules));
  Object.defineProperty(rules[64], "name", {
    get() {
      ruleGetterReads += 1;
      return "must-not-read";
    },
  });
  manyRules.rules = rules;
  assert.throws(
    () => lowerLaunchEgressRoutePlan({ user_id: "preset-user", integrations: [manyRules] } as never),
    EgressRoutePolicyError,
  );
  assert.equal(ruleGetterReads, 0);
  let extraGetterReads = 0;
  const extra = structuredClone(preset("github-smart-http-v1.json")) as Record<string, unknown>;
  Object.defineProperty(extra, "extra", {
    enumerable: true,
    get() {
      extraGetterReads += 1;
      return "must-not-read";
    },
  });
  assert.throws(
    () => lowerLaunchEgressRoutePlan({ user_id: "preset-user", integrations: [extra] } as never),
    EgressRoutePolicyError,
  );
  assert.equal(extraGetterReads, 0);
  const many = sampleIntegration((integration) => {
    const rule = firstRule(integration);
    rule.path_patterns = Array.from({ length: 128 }, (_, index) => `/repo${index}/*.git/info/refs`);
    rule.methods = ["GET", "POST"];
    (integration.rules as Array<Record<string, unknown>>).push({
      ...structuredClone(rule),
      name: "github-smart-http-refs-more",
      path_patterns: Array.from({ length: 128 }, (_, index) => `/more${index}/*.git/info/refs`),
    });
  });
  assert.throws(() => lowerLaunchEgressRoutePlan(launch([many])), EgressRoutePolicyError);
});

test("preset revisions exclude only deployment-specific secret handles", () => {
  const userScoped = structuredClone(preset("github-smart-http-v1.json")) as Record<string, unknown>;
  (userScoped.auth as Record<string, unknown>).secret_handle = "users/alice/integrations/github";
  const userPlan = lowerLaunchEgressRoutePlan(launch([userScoped], "alice"));
  assert.equal(userPlan.integrations[0]?.auth.secretHandle, "users/alice/integrations/github");

  const organizationScoped = structuredClone(preset("github-smart-http-v1.json")) as Record<string, unknown>;
  (organizationScoped.auth as Record<string, unknown>).secret_handle = "organizations/org-1/integrations/github";
  assert.equal(lowerLaunchEgressRoutePlan(launch([organizationScoped], "alice")).routeCount, 2);

  for (const mutate of [
    (integration: Record<string, unknown>) => ((integration.auth as Record<string, unknown>).header = "X-Token"),
    (integration: Record<string, unknown>) => ((integration.auth as Record<string, unknown>).prefix = "Token "),
    (integration: Record<string, unknown>) => (firstRule(integration).path_patterns = ["/*/*.git/git-upload-pack"]),
    (integration: Record<string, unknown>) => (firstRule(integration).query_policy = { mode: "deny" }),
  ]) {
    const changed = structuredClone(preset("github-smart-http-v1.json")) as Record<string, unknown>;
    mutate(changed);
    assert.throws(
      () => lowerLaunchEgressRoutePlan({ user_id: "preset-user", integrations: [changed] } as never),
      EgressRoutePolicyError,
    );
  }
});

test("forged launch objects and stale revisions fail with generic redaction", () => {
  assert.throws(
    () => lowerLaunchEgressRoutePlan({ user_id: "bad/user", integrations: [] } as never),
    EgressRoutePolicyError,
  );
  assert.throws(
    () => lowerLaunchEgressRoutePlan({ integrations: [Object.create(sampleIntegration())] } as never),
    (error) => {
      assert.equal(error instanceof EgressRoutePolicyError, true);
      assert.equal((error as Error).message.includes("github"), false);
      return true;
    },
  );
  const stale = sampleIntegration();
  firstRule(stale).methods = ["GET", "POST"];
  assert.throws(() => lowerLaunchEgressRoutePlan(launch([stale])), EgressRoutePolicyError);
});
