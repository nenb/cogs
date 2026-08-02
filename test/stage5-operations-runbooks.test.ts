import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
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
type PolicyDocument = {
  id: string;
  path: string;
  title: string;
  content_sha256: string;
  status: string;
};
type RunbookIndex = JsonObject & {
  subscription_oauth: JsonObject;
  policy_documents: PolicyDocument[];
  fact_classes: JsonObject[];
  runbooks: RunbookRow[];
};

type CodeSegment = Readonly<{ kind: "fence" | "inline"; info: string; body: string }>;

const markdownFiles = (): string[] => [
  ...index.policy_documents.map((row) => resolve(root, row.path)),
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

function codeSegments(text: string): CodeSegment[] {
  const segments: CodeSegment[] = [];
  const lines = text.split("\n");
  let fence: { marker: string; info: string; body: string[] } | null = null;
  for (const line of lines) {
    if (fence === null) {
      const opening = line.match(/^\s*(`{3,}|~{3,})\s*([^\s]*)[^\n]*$/u);
      if (opening !== null) {
        fence = { marker: opening[1] ?? "", info: (opening[2] ?? "").toLowerCase(), body: [] };
      }
      continue;
    }
    const closing = line.match(/^\s*(`{3,}|~{3,})\s*$/u);
    if (closing !== null && closing[1]?.[0] === fence.marker[0] && (closing[1]?.length ?? 0) >= fence.marker.length) {
      segments.push({ kind: "fence", info: fence.info, body: fence.body.join("\n") });
      fence = null;
    } else {
      fence.body.push(line);
    }
  }
  if (fence !== null) segments.push({ kind: "fence", info: fence.info, body: fence.body.join("\n") });

  for (const match of text.matchAll(/(`+)([^`\n]+?)\1/gu)) {
    segments.push({ kind: "inline", info: "inline", body: match[2] ?? "" });
  }
  for (const match of text.matchAll(/<code(?:\s[^>]*)?>([\s\S]*?)<\/code>/giu)) {
    segments.push({ kind: "inline", info: "html-code", body: match[1] ?? "" });
  }
  for (const line of lines) {
    if (/^(?: {4}|\t)\S/u.test(line)) segments.push({ kind: "inline", info: "indented-code", body: line.trim() });
  }
  return segments;
}

const EXECUTABLE_CLI =
  /\b(?:aws|kubectl|oc|eksctl|helm|kustomize|crossplane|terraform|tofu|gcloud|az|bicep|hcloud|doctl|linode-cli|oci|ibmcloud|openstack|scw|flyctl|pulumi|cdk|cfn|sam|serverless|curl|wget|http|https|Invoke-WebRequest|Invoke-RestMethod)(?:\.exe)?\s+(?:--?[A-Za-z]|[A-Za-z0-9_./:'"-])/iu;
const SHELL_WRAPPER =
  /\b(?:bash|sh|zsh|fish)\s+-c\b|\b(?:powershell|pwsh)\b\s+(?:-Command|-c)\b|\bcmd(?:\.exe)?\s+\/c\b/iu;
const HTTP_API_OPERATION = /\b(?:GET|POST|PUT|PATCH|DELETE)\s+(?:https?:\/\/|\/[A-Za-z0-9])/u;

function executablePolicyErrors(text: string, path: string): string[] {
  const errors: string[] = [];
  for (const segment of codeSegments(text)) {
    const normalizedBody = segment.body.replace(/(?:\\|`)\r?\n\s*/gu, " ");
    for (const originalLine of normalizedBody.split("\n")) {
      const line = originalLine.trim().replace(/^(?:\$|PS>)\s*/u, "");
      if (line === "" || line.startsWith("#") || SAFE_LOCAL_COMMANDS.has(line)) continue;
      if (EXECUTABLE_CLI.test(line) || SHELL_WRAPPER.test(line) || HTTP_API_OPERATION.test(line)) {
        errors.push(`${path}:${segment.kind}:${segment.info || "unlabeled"}:${line}`);
      }
    }
  }
  return errors;
}

const POSITIVE_CLAIM_PATTERNS = [
  /\bCogs\s+(?:is|has become|is now)\s+(?:production[- ]ready|release[- ]ready|GA|generally available|compliance[- ]certified|compliant)\b/iu,
  /\b(?:this|the platform|the service)\s+(?:is|has become|is now)\s+(?:production[- ]ready|release[- ]ready|GA|generally available|compliance[- ]certified|compliant)\b/iu,
  /\b(?:Cogs|we|the platform|the service)\s+(?:supports|support|is supported on|is qualified for|is validated on|is ready for)\s+AWS\s+EKS\b/iu,
  /\bAWS\s+EKS\s+(?:is\s+)?(?:supported|qualified|validated|ready|available)\b/iu,
  /\b(?:ready|approved|suitable|safe)\s+for\s+production\b/iu,
  /\bsubscription\s+OAuth\s+(?:is|remains|is now)?\s*(?:enabled|supported|available|advertised|permitted)\b/iu,
  /\bsubscription\s+OAuth\s+(?:works|can be used)\b/iu,
  /^(?:#{1,6}\s*)?(?:production|release)[- ]ready[.!]?$/imu,
  /^(?:#{1,6}\s*)?(?:GA|generally available|compliance[- ]certified|compliant)[.!]?$/imu,
  /^(?:#{1,6}\s*)?(?:supported|qualified|validated|ready|available)\s+(?:on|for)\s+AWS\s+EKS[.!]?$/imu,
  /\bworkers?\s+(?:own|handle|manage)\s+(?:subscription\s+)?refresh\s+tokens?\b/iu,
  /\bworker\s+refresh[- ]token\s+(?:support|persistence)\s+(?:is\s+)?enabled\b/iu,
  /\bworkers?\s+(?:receive|persist|store|refresh|write)\s+(?:subscription\s+)?refresh\s+tokens?\b/iu,
  /\bworkers?\s+(?:may|can|will|do|must|should)\s+(?:receive|persist|store|refresh|write)\s+(?:subscription\s+)?refresh\s+tokens?\b/iu,
  /\brefresh\s+tokens?\s+(?:are|can be|will be|may be)\s+(?:received|persisted|stored|refreshed|written)\s+by\s+workers?\b/iu,
] as const;

function positiveClaimErrors(text: string): string[] {
  return POSITIVE_CLAIM_PATTERNS.filter((pattern) => pattern.test(text)).map((pattern) => pattern.source);
}

function h2Sections(text: string): Array<{ heading: string; body: string }> {
  const matches = [...text.matchAll(/^##\s+(.+)$/gmu)];
  return matches.map((match, index) => ({
    heading: match[1] ?? "",
    body: text.slice((match.index ?? 0) + match[0].length, matches[index + 1]?.index ?? text.length).trim(),
  }));
}

function tableDataRows(body: string): string[] {
  return body
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("|") && !/^\|(?:\s*:?-+:?\s*\|)+$/u.test(line))
    .slice(1);
}

function readmeInventoryRows(text: string): Array<[string, string, string]> {
  const inventory = h2Sections(text).find(({ heading }) => heading === "Inventory");
  assert.ok(inventory);
  return tableDataRows(inventory.body).map((line) => {
    const cells = line
      .slice(1, -1)
      .split("|")
      .map((cell) => cell.trim());
    assert.equal(cells.length, 3, line);
    const id = cells[0]?.match(/^`([^`]+)`$/u)?.[1];
    const path = cells[2]?.match(/^\[`([^`]+)`\]\([^)]+\)$/u)?.[1];
    assert.ok(id && cells[1] && path, line);
    return [id, cells[1], path];
  });
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
  assert.deepEqual(
    index.policy_documents.map(({ id, path, title, status }) => ({ id, path, title, status })),
    [
      {
        id: "runbook-policy",
        path: "docs/operations/runbooks/README.md",
        title: "Stage 5 draft operations runbooks",
        status: "policy-local-static-only",
      },
    ],
  );
});

test("the index has the exact complete inventory and binds every policy/runbook document by digest", () => {
  assert.deepEqual(
    index.runbooks.map(({ id, title }) => [id, title]),
    EXPECTED_RUNBOOKS,
  );
  assert.equal(new Set(index.runbooks.map(({ id }) => id)).size, EXPECTED_RUNBOOKS.length);
  const indexed = [...index.policy_documents, ...index.runbooks];
  for (const row of indexed) {
    const bytes = readFileSync(resolve(root, row.path));
    assert.equal(digest(bytes), row.content_sha256, row.path);
    assert.equal(bytes.toString("utf8").split("\n", 1)[0], `# ${row.title}`);
  }
  for (const row of index.runbooks) {
    assert.equal(row.path, `docs/operations/runbooks/${row.id}.md`);
    assert.equal(row.status, "draft-local-static-only");
    assert.equal(row.evidence_contract, "future-operations-reference-v1");
  }

  const markdownInventory = readdirSync(runbookDirectory)
    .filter((name) => name.endsWith(".md"))
    .map((name) => `docs/operations/runbooks/${name}`)
    .sort();
  assert.deepEqual(
    indexed.map(({ path }) => path).sort(),
    markdownInventory,
    "every markdown policy/runbook document must be digest-indexed",
  );
});

test("schema and inventory reject omission, reordering, authority promotion, OAuth promotion, and unknown fields", () => {
  const hostile = [
    mutation((value) => value.policy_documents.pop()),
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

test("every substantive fact and future requirement has per-row specific traceability", () => {
  assert.deepEqual(
    index.fact_classes.map((row) => row.heading),
    FACT_HEADINGS,
  );
  for (const row of index.fact_classes) assert.equal(row.can_satisfy_gate, false);

  for (const row of index.runbooks) {
    const text = readFileSync(resolve(root, row.path), "utf8");
    const sections = h2Sections(text);
    const headings = sections.map(({ heading }) => heading);
    const positions = FACT_HEADINGS.map((heading) => headings.indexOf(heading));
    assert.ok(
      positions.every((position) => position >= 0),
      `${row.id}: missing fact class`,
    );
    assert.deepEqual(
      [...positions].sort((left, right) => left - right),
      positions,
      `${row.id}: fact order`,
    );

    for (const heading of FACT_HEADINGS) {
      const section = sections.find((candidate) => candidate.heading === heading);
      assert.ok(section, `${row.id}:${heading}`);
      const nonempty = section.body
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
      assert.ok(
        nonempty.every((line) => line.startsWith("|")),
        `${row.id}:${heading}: table-only claims`,
      );
      const rows = tableDataRows(section.body);
      assert.ok(rows.length > 0, `${row.id}:${heading}: claims required`);
      const statements = new Set<string>();
      for (const claim of rows) {
        const cells = claim
          .slice(1, -1)
          .split("|")
          .map((cell) => cell.trim());
        assert.ok(cells.length >= 2, `${row.id}:${heading}:${claim}`);
        const statement = cells.slice(0, -1).join(" | ");
        const trace = cells.at(-1) ?? "";
        assert.ok(statement && !statements.has(statement), `${row.id}:${heading}: unique statement`);
        statements.add(statement);
        assert.match(trace, /\[[^\]]+\]\([^)]+\)/u, `${row.id}:${heading}: direct trace`);
        const traceTargets = localLinks(resolve(root, row.path), trace).map(({ target }) => target);
        assert.ok(traceTargets.length > 0, `${row.id}:${heading}: local trace target`);
        assert.equal(
          traceTargets.includes(resolve(runbookDirectory, "README.md")),
          false,
          `${row.id}:${heading}: no boilerplate policy link`,
        );
        if (heading === "Future cloud evidence" && !/^\[Authority:/u.test(trace)) {
          assert.match(trace, /^\[Planned /u, `${row.id}:${heading}: planned criterion`);
          assert.match(trace, /`future-[a-z-]+-reference-v1`/u, `${row.id}:${heading}: evidence contract`);
          assert.match(
            trace,
            /stage-5-api-key-release-acceptance-matrix\.md#/u,
            `${row.id}:${heading}: planned matrix location`,
          );
        } else {
          assert.match(trace, /\[Authority:/u, `${row.id}:${heading}: specific authority`);
        }
      }
    }

    for (const section of sections.filter(({ heading }) => !FACT_HEADINGS.includes(heading as never))) {
      assert.match(
        section.body,
        /\[[^\]]+\]\([^)]+\)/u,
        `${row.id}:${section.heading}: substantive section requires direct authority/planned link`,
      );
    }
  }
});

test("README inventory table is an exact deterministic rendering of the machine runbook index", () => {
  const readme = readFileSync(resolve(runbookDirectory, "README.md"), "utf8");
  assert.deepEqual(
    readmeInventoryRows(readme),
    index.runbooks.map(({ id, title, path }) => [id, title, path]),
  );
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

test("all indexed documents reject executable provider, cluster, API, shell, and PowerShell surfaces", () => {
  for (const path of markdownFiles()) {
    assert.deepEqual(executablePolicyErrors(readFileSync(path, "utf8"), path), [], path);
  }

  const hostile = [
    "Use `aws s3 ls`.",
    "Use ``aws s3 ls``.",
    "Use <code>aws s3 ls</code>.",
    "    aws s3 ls",
    "```\nkubectl get pods\n```",
    "~~~shell\neksctl create cluster\n~~~",
    "```sh\nsh -c 'terraform apply'\n```",
    "```powershell\nInvoke-RestMethod https://example.invalid/api\n```",
    "```pwsh\npwsh -Command 'az group list'\n```",
    "```text\ncurl https://example.invalid/api\n```",
    "```shell\naws \\\n  s3 ls\n```",
    "`POST /v1/resources`",
    "`cdk deploy`",
    "`npx cdk deploy`",
    "`pulumi up`",
    "`helm install cogs ./chart`",
    "`bicep build main.bicep`",
    "`cfn submit`",
    "`gcloud projects list`",
    "`aws.exe s3 ls`",
    "`kubectl.exe get pods`",
    "`hcloud server list`",
    "`doctl compute droplet list`",
    "`oci iam region list`",
    "`ibmcloud resource groups`",
    "`openstack server list`",
    "`scw instance server list`",
    "`linode-cli linodes list`",
  ];
  for (const [position, text] of hostile.entries()) {
    assert.notDeepEqual(executablePolicyErrors(text, `hostile-${position}`), [], text);
  }
  for (const command of SAFE_LOCAL_COMMANDS) {
    assert.deepEqual(executablePolicyErrors(`\`\`\`bash\n${command}\n\`\`\``, "safe-local"), []);
  }

  const corpus = markdownFiles()
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
  assert.doesNotMatch(corpus, /\brm\s+-rf\b|\bdelete\s+--all\b|\bxargs\b[^\n]*\bdelete\b/iu);
});

test("hostile wording rejects positive production, GA, compliance, AWS EKS, OAuth, and refresh-token claims", () => {
  for (const path of markdownFiles()) {
    assert.deepEqual(positiveClaimErrors(readFileSync(path, "utf8")), [], path);
  }
  for (const text of [
    "Cogs is production ready.",
    "This is release-ready.",
    "Cogs is GA.",
    "The platform is generally available.",
    "The service is compliance-certified.",
    "Cogs supports AWS EKS.",
    "We support AWS EKS.",
    "AWS EKS is validated.",
    "The service is ready for production.",
    "Production-ready.",
    "Generally available.",
    "Supported on AWS EKS.",
    "Subscription OAuth is enabled.",
    "Subscription OAuth works.",
    "Subscription OAuth remains supported.",
    "Workers may persist refresh tokens.",
    "Workers store refresh tokens.",
    "Workers manage refresh tokens.",
    "Worker refresh-token persistence is enabled.",
    "Refresh tokens are stored by workers.",
  ]) {
    assert.notDeepEqual(positiveClaimErrors(text), [], text);
  }

  const corpus = markdownFiles()
    .map((path) => readFileSync(path, "utf8"))
    .join("\n");
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
  assert.match(corpus, /EKS (?:node )?image (?:is )?unresolved/u);
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
