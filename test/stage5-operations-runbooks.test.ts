import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, extname, resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const runbookDirectory = resolve(root, "docs/operations/runbooks");
const schema = JSON.parse(
  readFileSync(resolve(root, "schemas/stage5-operations-runbook-index-v1.json"), "utf8"),
) as object;
const index = JSON.parse(readFileSync(resolve(runbookDirectory, "index.json"), "utf8")) as RunbookIndex;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true });
const validate = ajv.compile(schema) as ValidateFunction;

const EXPECTED_RUNBOOKS = [
  ["installation", "Draft installation guide"],
  ["prerequisites", "Draft prerequisites guide"],
  ["nic-configuration", "Draft NIC configuration guide"],
  ["platform-matrix", "Draft NIC and platform matrix"],
  ["upgrade", "Draft runtime and proxy upgrade runbook"],
  ["openbao", "Draft OpenBao policy and revocation runbook"],
  ["incident-response", "Draft credential incident-response runbook"],
  ["cve-response", "Draft node and runtime CVE response runbook"],
  ["retention-deletion", "Draft backup, retention, export, and deletion guide"],
  ["capacity", "Draft capacity and cost planning guide"],
  ["observability", "Draft observability dashboard field reference"],
  ["limitations", "Draft known limitations and residual risks"],
  ["teardown", "Draft teardown and orphan-resource verification guide"],
] as const;

const FACT_HEADINGS = [
  "Assumptions",
  "Static contract facts",
  "Authoritative-local facts",
  "Future cloud evidence",
] as const;

const SAFE_LOCAL_COMMANDS = new Set([
  "npm ci --ignore-scripts",
  "npm run check",
  "helm lint deploy/helm/cogs",
  "helm template cogs deploy/helm/cogs",
]);

type JsonObject = Record<string, unknown>;
type RunbookRow = {
  id: string;
  path: string;
  title: string;
  content_sha256: string;
  status: string;
  evidence_contract: string;
};
type RunbookIndex = JsonObject & {
  subscription_oauth: JsonObject;
  fact_classes: JsonObject[];
  runbooks: RunbookRow[];
};

const markdownFiles = (): string[] => [
  resolve(runbookDirectory, "README.md"),
  ...index.runbooks.map((row) => resolve(root, row.path)),
];
const digest = (bytes: Buffer | string): string => createHash("sha256").update(bytes).digest("hex");
const accepted = (value: unknown): boolean => validate(value) as boolean;
const mutation = (mutator: (value: RunbookIndex) => void): RunbookIndex => {
  const value = structuredClone(index);
  mutator(value);
  return value;
};

function headingAnchor(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[`*_~]/gu, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .replace(/\s+/gu, "-")
    .replace(/-+/gu, "-");
}

function documentAnchors(text: string): Set<string> {
  const anchors = new Set<string>();
  const counts = new Map<string, number>();
  for (const match of text.matchAll(/^#{1,6}\s+(.+?)\s*$/gmu)) {
    const heading = match[1];
    assert.ok(heading);
    const base = headingAnchor(heading);
    const count = counts.get(base) ?? 0;
    counts.set(base, count + 1);
    anchors.add(count === 0 ? base : `${base}-${count}`);
  }
  return anchors;
}

function localLinks(path: string, text: string): Array<{ target: string; fragment: string | null }> {
  const links: Array<{ target: string; fragment: string | null }> = [];
  for (const match of text.matchAll(/\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/gu)) {
    const href = match[1];
    assert.ok(href);
    if (/^(?:https?:|mailto:)/u.test(href)) continue;
    const [rawTarget, rawFragment] = href.split("#", 2);
    links.push({
      target: resolve(dirname(path), rawTarget === "" ? path : decodeURIComponent(rawTarget ?? "")),
      fragment: rawFragment === undefined ? null : decodeURIComponent(rawFragment),
    });
  }
  return links;
}

function fencedCommands(text: string): string[] {
  const commands: string[] = [];
  for (const match of text.matchAll(/```(?:bash|sh)\n([\s\S]*?)```/gu)) {
    for (const line of (match[1] ?? "").split("\n")) {
      const command = line.trim();
      if (command !== "" && !command.startsWith("#")) commands.push(command);
    }
  }
  return commands;
}

test("the machine index is strict, bounded, provisional, and authority-negative", () => {
  assert.equal(accepted(index), true, JSON.stringify(validate.errors));
  for (const field of [
    "qualified",
    "campaign_authorized",
    "cloud_execution_observed",
    "provider_truth_observed",
    "operations_evidence_observed",
    "stage4_exit_satisfied",
    "release_eligible",
    "production_ready",
    "general_availability",
    "compliance_certified",
  ]) {
    assert.equal(index[field], false, field);
  }
  assert.equal(index.draft, true);
  assert.equal(index.go_no_go, "not-available");
  assert.deepEqual(index.subscription_oauth, {
    status: "disabled-unadvertised",
    deferred_issue: 13,
    future_post_mvp_only: true,
    worker_refresh_tokens: "forbidden",
  });
});

test("the index has the exact complete inventory and binds every document by digest", () => {
  assert.deepEqual(
    index.runbooks.map(({ id, title }) => [id, title]),
    EXPECTED_RUNBOOKS,
  );
  assert.equal(new Set(index.runbooks.map(({ id }) => id)).size, EXPECTED_RUNBOOKS.length);
  for (const row of index.runbooks) {
    assert.equal(row.path, `docs/operations/runbooks/${row.id}.md`);
    assert.equal(row.status, "draft-local-static-only");
    assert.equal(row.evidence_contract, "future-operations-reference-v1");
    const bytes = readFileSync(resolve(root, row.path));
    assert.equal(digest(bytes), row.content_sha256, row.path);
    assert.equal(bytes.toString("utf8").split("\n", 1)[0], `# ${row.title}`);
  }
});

test("schema and inventory reject omission, reordering, authority promotion, OAuth promotion, and unknown fields", () => {
  const hostile = [
    mutation((value) => value.runbooks.pop()),
    mutation((value) => value.runbooks.reverse()),
    mutation((value) => {
      value.runbooks[0] = structuredClone(value.runbooks[1] as RunbookRow);
    }),
    mutation((value) => {
      value.release_eligible = true;
    }),
    mutation((value) => {
      value.cloud_execution_observed = true;
    }),
    mutation((value) => {
      value.subscription_oauth.status = "enabled";
    }),
    mutation((value) => {
      value.provider_target = "forbidden";
    }),
    mutation((value) => {
      const first = value.runbooks[0];
      assert.ok(first);
      (first as unknown as JsonObject).command = "forbidden";
    }),
  ];
  for (const value of hostile) assert.equal(accepted(value), false);
});

test("every runbook separates assumptions, static facts, authoritative-local facts, and future evidence", () => {
  assert.deepEqual(
    index.fact_classes.map((row) => row.heading),
    FACT_HEADINGS,
  );
  for (const row of index.fact_classes) assert.equal(row.can_satisfy_gate, false);

  for (const row of index.runbooks) {
    const text = readFileSync(resolve(root, row.path), "utf8");
    const headings = Array.from(text.matchAll(/^##\s+(.+)$/gmu), (match) => match[1]);
    const positions = FACT_HEADINGS.map((heading) => headings.indexOf(heading));
    assert.ok(
      positions.every((position) => position >= 0),
      `${row.id}: missing fact class`,
    );
    assert.deepEqual(
      [...positions].sort((left, right) => left - right),
      positions,
      `${row.id}: fact class order`,
    );
    assert.match(text, /future|Future/u, `${row.id}: planned evidence must remain explicit`);
    assert.match(text, /\[[^\]]+\]\([^)]+\)/u, `${row.id}: claims must link to authority or planned evidence`);
  }
});

test("all local runbook links resolve and every markdown fragment names a real heading", () => {
  for (const path of markdownFiles()) {
    const text = readFileSync(path, "utf8");
    for (const { target, fragment } of localLinks(path, text)) {
      assert.equal(existsSync(target), true, `${path}: missing ${target}`);
      assert.equal(statSync(target).isFile(), true, `${path}: non-file link ${target}`);
      if (fragment !== null && extname(target) === ".md") {
        const anchors = documentAnchors(readFileSync(target, "utf8"));
        assert.equal(anchors.has(fragment), true, `${path}: missing #${fragment} in ${target}`);
      }
    }
  }
});

test("runbooks contain only the four reviewed local commands and no executable provider or unsafe cleanup surface", () => {
  const commands = markdownFiles().flatMap((path) => fencedCommands(readFileSync(path, "utf8")));
  assert.deepEqual(commands, [...SAFE_LOCAL_COMMANDS]);
  for (const command of commands) {
    assert.equal(SAFE_LOCAL_COMMANDS.has(command), true);
    assert.doesNotMatch(command, /\b(?:aws|kubectl|terraform|tofu|gcloud|az|hcloud)\b/iu);
  }

  const corpus = markdownFiles()
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
  assert.doesNotMatch(corpus, /\brm\s+-rf\b|\bdelete\s+--all\b|\bxargs\b[^\n]*\bdelete\b/iu);
  assert.doesNotMatch(
    corpus,
    /\b(?:helm\s+(?:install|upgrade|uninstall)|terraform\s+(?:apply|destroy)|tofu\s+(?:apply|destroy))\b/iu,
  );
});

test("hostile wording cannot advertise OAuth, providers, release, production, GA, or compliance", () => {
  const corpus = markdownFiles()
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
  assert.doesNotMatch(corpus, /subscription OAuth (?:is|remains) (?:enabled|supported|available)/iu);
  assert.doesNotMatch(
    corpus,
    /\b(?:is|are|now|fully) (?:production[- ]ready|release[- ]ready|generally available|GA|compliant|compliance[- ]certified)\b/iu,
  );
  assert.match(corpus, /Subscription OAuth is disabled and unadvertised/u);
  assert.match(corpus, /Issue #13 is future post-MVP work only/u);
  assert.match(corpus, /no provider command, resource target, credential, or cluster operation/iu);
});

test("static contract values and Stage 5 support posture remain consistent with their machine authorities", () => {
  const nic = JSON.parse(
    readFileSync(resolve(root, "deploy/nic/stage4-sandbox-node-group-contract.json"), "utf8"),
  ) as JsonObject;
  const matrix = JSON.parse(
    readFileSync(resolve(root, "docs/security-evidence/stage5-api-key-release-matrix.draft.json"), "utf8"),
  ) as JsonObject;
  const corpus = markdownFiles()
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
  assert.equal((nic.nic_capability_assessment as JsonObject).outcome, "blocking-capability-gap");
  assert.match(corpus, /NIC `v0\.11\.0`/u);
  assert.match(corpus, /EKS node image is unresolved/u);
  assert.match(corpus, /Kata `3\.32\.0`/u);
  assert.match(corpus, /containerd `2\.2\.1`/u);
  assert.match(corpus, /QEMU `8\.2\.2`/u);
  assert.deepEqual(matrix.subscription_oauth, {
    status: "disabled-unadvertised",
    advertised: false,
    release_gate: false,
    deferred_issue: 13,
    worker_refresh_tokens: "forbidden",
  });
  const posture = (matrix.support_claims as JsonObject).posture as JsonObject;
  assert.deepEqual(posture, {
    production_ready: false,
    general_availability: false,
    compliance_certified: false,
    advertised_release: false,
  });
});

test("teardown preserves exact fail-closed ownership and orphan escalation without broad deletion", () => {
  const text = readFileSync(resolve(runbookDirectory, "teardown.md"), "utf8");
  for (const phrase of [
    "Exact ownership gate before any future mutation",
    "exact account binding and region match the approved attempt",
    "Tags may corroborate but never establish ownership by themselves",
    "do not mutate or delete the candidate",
    "Exact orphan escalation",
    "separately approved recovery authority",
    "original campaign approval is exhausted",
    "one proven generation",
    "Any uncertain item blocks zero, campaign success, Stage 4 exit, and retry",
    "Never use wildcard, recursive, account-wide, region-wide, prefix-wide, tag-only, label-only, namespace-wide",
  ]) {
    assert.match(text, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "u"), phrase);
  }
  assert.doesNotMatch(text, /not[- ]found[^.]*\b(?:means|proves|establishes) absence/iu);
  assert.doesNotMatch(text, /tags? (?:alone )?(?:prove|establish) ownership/iu);
});
