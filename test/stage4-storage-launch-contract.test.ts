import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { resolve } from "node:path";
import test from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";
import * as contractModule from "../scripts/stage4-storage-launch-contract.ts";
import {
  canonicalStage4StorageLaunchBytes,
  evaluateStage4StorageLaunchGraph,
  STAGE4_STORAGE_LAUNCH_LIMITS,
  STAGE4_STORAGE_LAUNCH_REASON_CODES,
  STAGE4_STORAGE_ROLES,
  type Stage4StorageLaunchVerdict,
  validateStage4StorageLaunchBytes,
} from "../scripts/stage4-storage-launch-contract.ts";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
const root = resolve(import.meta.dirname, "..");
const fixturePath = resolve(root, "test/fixtures/stage4-storage-launch/valid-active-v1.json");
const contractSchema = require("../schemas/stage4-storage-launch-contract-v1.json") as object;
const verdictSchema = require("../schemas/stage4-storage-launch-verdict-v1.json") as object;
const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false });
const validateContract = ajv.compile(contractSchema) as ValidateFunction;
const validateVerdict = ajv.compile(verdictSchema) as ValidateFunction;

type Json = Record<string, unknown>;
type Graph = Json & {
  storage: Json & { workspace: Json; trusted_session_state: Json };
  workspace_lease: Json;
  launch_document: Json & { ssh_host_key: Json };
  runtime_class: Json;
  resources: Json & { trusted_worker_proxy: Json[]; kata_sandbox: Json[] };
  lifecycle: Json;
  bounded_io: Json;
};

function graph(): Graph {
  return JSON.parse(readFileSync(fixturePath, "utf8")) as Graph;
}

function verdict(value: unknown): Stage4StorageLaunchVerdict {
  const result = evaluateStage4StorageLaunchGraph(value);
  assert.equal(validateVerdict(result), true, JSON.stringify(validateVerdict.errors));
  assert.equal(result.qualified, false);
  assert.equal(result.campaign_authorized, false);
  assert.equal(result.cloud_execution_observed, false);
  assert.equal(result.kubernetes_execution_observed, false);
  assert.equal(result.provider_truth_observed, false);
  assert.equal(result.stage4_exit_satisfied, false);
  assert.equal(result.release_eligible, false);
  return result;
}

function expectResult(
  result: Stage4StorageLaunchVerdict,
  status: Stage4StorageLaunchVerdict["status"],
  reason: string,
): void {
  assert.equal(validateVerdict(result), true, JSON.stringify(validateVerdict.errors));
  assert.equal(result.status, status);
  assert.equal(result.reason_code, reason);
}

function expect(value: unknown, status: Stage4StorageLaunchVerdict["status"], reason: string): void {
  expectResult(verdict(value), status, reason);
}

function trusted(value: Graph): Json {
  const resource = value.resources.trusted_worker_proxy[0];
  assert.ok(resource);
  return resource;
}

function sandbox(value: Graph): Json {
  const resource = value.resources.kata_sandbox[0];
  assert.ok(resource);
  return resource;
}

function cleanup(value: Graph, state: "cleanup-requested" | "complete"): Graph {
  value.lifecycle.state = state;
  if (state === "cleanup-requested") {
    value.lifecycle.trusted_worker_proxy = "removal-requested";
    value.lifecycle.kata_sandbox = "removal-requested";
    value.lifecycle.workspace_attachment = "detach-requested";
    value.lifecycle.session_state_attachment = "detach-requested";
    value.lifecycle.lease = "release-requested";
    value.workspace_lease.state = "release-requested";
  } else {
    value.lifecycle.trusted_worker_proxy = "removed";
    value.lifecycle.kata_sandbox = "removed";
    value.lifecycle.workspace_attachment = "detached";
    value.lifecycle.session_state_attachment = "detached";
    value.lifecycle.lease = "released";
    value.workspace_lease.state = "released";
    value.workspace_lease.writer_count = 0;
    value.workspace_lease.holder_launch_document_sha256 = null;
  }
  return value;
}

test("strict schemas accept one bounded active graph and its non-authoritative verdict", () => {
  const value = graph();
  assert.equal(validateContract(value), true, JSON.stringify(validateContract.errors));
  assert.deepEqual(value.storage.workspace, STAGE4_STORAGE_ROLES.workspace);
  assert.deepEqual(value.storage.trusted_session_state, STAGE4_STORAGE_ROLES.trustedSessionState);
  assert.deepEqual(STAGE4_STORAGE_ROLES.workspace, {
    role: "untrusted-project-workspace",
    size_bytes: 21474836480,
    access_mode: "ReadWriteOncePod",
    volume_mode: "Filesystem",
    volume_binding_mode: "WaitForFirstConsumer",
    reclaim_policy: "Retain",
    medium: "csi-block",
    mount_owner: "kata-sandbox-only",
    retention: "retain-until-explicit-workspace-deletion",
    reclaim_on_session_end: false,
  });
  assert.equal(STAGE4_STORAGE_ROLES.trustedSessionState.retention_seconds, 2592000);

  const first = verdict(value);
  const second = verdict(value);
  assert.deepEqual(first, second);
  assert.equal(first.status, "admissible-static-graph");
  assert.equal(first.reason_code, "STAGE4_STORAGE_LAUNCH_GRAPH_VALID");
  assert.match(first.graph_sha256 ?? "", /^[0-9a-f]{64}$/u);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(STAGE4_STORAGE_ROLES.workspace), true);
});

test("exactly one trusted worker/proxy and one Kata sandbox bind to one immutable document", () => {
  const value = graph();
  assert.equal(value.resources.trusted_worker_proxy.length, 1);
  assert.equal(value.resources.kata_sandbox.length, 1);
  assert.deepEqual(trusted(value).containers, ["worker", "proxy"]);
  assert.deepEqual(sandbox(value).containers, ["sandbox"]);
  assert.equal(trusted(value).launch_document_sha256, value.launch_document.document_sha256);
  assert.equal(sandbox(value).launch_document_sha256, value.launch_document.document_sha256);
  assert.equal(value.launch_document.immutable, true);
  assert.equal(value.launch_document.state, "admitted-once");
  assert.equal(value.launch_document.admission_count, 1);

  for (const collection of ["trusted_worker_proxy", "kata_sandbox"] as const) {
    const missing = graph();
    missing.resources[collection] = [];
    expect(missing, "reject", "STAGE4_RESOURCE_CARDINALITY_INVALID");

    const duplicate = graph();
    duplicate.resources[collection].push(structuredClone(duplicate.resources[collection][0] as Json));
    expect(duplicate, "reject", "STAGE4_RESOURCE_CARDINALITY_INVALID");
  }

  const mismatched = graph();
  sandbox(mismatched).launch_document_sha256 = "c".repeat(64);
  expect(mismatched, "reject", "STAGE4_LAUNCH_BINDING_INVALID");

  const otherSession = graph();
  sandbox(otherSession).session_id = "session-static-2";
  expect(otherSession, "reject", "STAGE4_LAUNCH_BINDING_INVALID");
});

test("wrong workspace or trusted session-state mode, size, owner, or retention fails closed", () => {
  const modeMutations: Array<(value: Graph) => void> = [
    (value) => (value.storage.workspace.access_mode = "ReadWriteMany"),
    (value) => (value.storage.workspace.access_mode = "ReadWriteOnce"),
    (value) => (value.storage.workspace.volume_mode = "Block"),
    (value) => (value.storage.workspace.volume_binding_mode = "Immediate"),
    (value) => (value.storage.workspace.reclaim_policy = "Delete"),
    (value) => (value.storage.workspace.medium = "shared-filesystem"),
    (value) => (value.storage.trusted_session_state.access_mode = "ReadWriteMany"),
    (value) => (value.storage.trusted_session_state.volume_mode = "Block"),
    (value) => (value.storage.trusted_session_state.volume_binding_mode = "Immediate"),
    (value) => (value.storage.trusted_session_state.reclaim_policy = "Delete"),
  ];
  for (const mutate of modeMutations) {
    const value = graph();
    mutate(value);
    expect(value, "reject", "STAGE4_STORAGE_MODE_INVALID");
  }

  const roleMutations: Array<(value: Graph) => void> = [
    (value) => (value.storage.workspace.size_bytes = 1),
    (value) => (value.storage.workspace.mount_owner = "shared"),
    (value) => (value.storage.workspace.retention = "delete-on-session-end"),
    (value) => (value.storage.workspace.reclaim_on_session_end = true),
    (value) => (value.storage.trusted_session_state.size_bytes = 1),
    (value) => (value.storage.trusted_session_state.mount_owner = "shared"),
    (value) => (value.storage.trusted_session_state.retention_seconds = 0),
    (value) => (value.storage.trusted_session_state.sandbox_visible = true),
  ];
  for (const mutate of roleMutations) {
    const value = graph();
    mutate(value);
    expect(value, "reject", "STAGE4_STORAGE_ROLE_DRIFT");
  }
});

test("exclusive-writer fencing denies concurrency and never treats expiry as takeover authority", () => {
  const concurrent = graph();
  concurrent.workspace_lease.writer_count = 2;
  expect(concurrent, "preserve-uncertain", "STAGE4_WORKSPACE_CONCURRENT_WRITER");

  const wrongHolder = graph();
  wrongHolder.workspace_lease.holder_launch_document_sha256 = "c".repeat(64);
  expect(wrongHolder, "preserve-uncertain", "STAGE4_WORKSPACE_LEASE_INVALID");

  for (const mutate of [
    (value: Graph) => (value.workspace_lease.expiry_allows_takeover = true),
    (value: Graph) => (value.workspace_lease.fencing = "none"),
    (value: Graph) => (value.workspace_lease.writer_limit = 2),
  ]) {
    const value = graph();
    mutate(value);
    expect(value, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  }
});

test("missing RuntimeClass, host-key mismatch, stale documents, and replay all deny", () => {
  for (const resolution of ["missing", "wrong"]) {
    const value = graph();
    value.runtime_class.resolution = resolution;
    value.runtime_class.resolved_name = resolution === "missing" ? null : "runc";
    expect(value, "reject", "STAGE4_RUNTIMECLASS_MISSING_OR_WRONG");
  }
  for (const verification of ["mismatch", "missing"]) {
    const value = graph();
    value.launch_document.ssh_host_key.verification = verification;
    expect(value, "reject", "STAGE4_SSH_HOST_KEY_MISMATCH");
  }

  const stale = graph();
  stale.launch_document.state = "stale";
  expect(stale, "reject", "STAGE4_LAUNCH_DOCUMENT_STALE");

  const replayed = graph();
  replayed.launch_document.state = "replayed";
  replayed.launch_document.admission_count = 2;
  expect(replayed, "reject", "STAGE4_LAUNCH_DOCUMENT_REPLAY");

  const secondAdmission = graph();
  secondAdmission.launch_document.admission_count = 2;
  expect(secondAdmission, "reject", "STAGE4_LAUNCH_DOCUMENT_REPLAY");
});

test("ephemeral SSH/proxy identity values cannot enter durable or sandbox handle surfaces", () => {
  assert.equal(graph().launch_document.ephemeral_ssh_identity, "out-of-band-memory-or-tmpfs-only");
  assert.equal(graph().launch_document.ephemeral_proxy_identity, "out-of-band-memory-or-tmpfs-only");
  for (const target of ["helm-values", "configmap", "report", "sandbox-secret-store-handle"]) {
    const value = graph();
    trusted(value).ephemeral_identity_persistence = target;
    expect(value, "reject", "STAGE4_EPHEMERAL_IDENTITY_PERSISTENCE_FORBIDDEN");
  }

  for (const mutate of [
    (value: Graph) => (value.launch_document.durable_identity_material = true),
    (value: Graph) => (value.launch_document.sandbox_secret_store_handles = true),
    (value: Graph) => (sandbox(value).secret_store_handles = true),
  ]) {
    const value = graph();
    mutate(value);
    expect(value, "reject", "STAGE4_EPHEMERAL_IDENTITY_PERSISTENCE_FORBIDDEN");
  }

  const fixture = readFileSync(fixturePath, "utf8");
  assert.doesNotMatch(fixture, /BEGIN [^\n]*PRIVATE KEY|Proxy-Authorization|ssh-ed25519\s+[A-Za-z0-9+/]/u);
});

test("cleanup lifecycle is deterministic and every ambiguity preserves state and lease", () => {
  expect(cleanup(graph(), "cleanup-requested"), "cleanup-in-progress", "STAGE4_STORAGE_LAUNCH_CLEANUP_IN_PROGRESS");
  expect(cleanup(graph(), "complete"), "cleanup-order-complete", "STAGE4_STORAGE_LAUNCH_CLEANUP_ORDER_COMPLETE");

  const mismatch = cleanup(graph(), "complete");
  mismatch.lifecycle.workspace_attachment = "attached";
  expect(mismatch, "preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS");

  const uncertainty = graph();
  uncertainty.lifecycle.state = "uncertain";
  uncertainty.lifecycle.kata_sandbox = "uncertain";
  uncertainty.lifecycle.uncertainty_artifact_sha256 = "f".repeat(64);
  uncertainty.workspace_lease.state = "uncertain";
  expect(uncertainty, "preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS");

  const prematureRelease = graph();
  prematureRelease.workspace_lease.state = "released";
  prematureRelease.workspace_lease.writer_count = 0;
  prematureRelease.workspace_lease.holder_launch_document_sha256 = null;
  expect(prematureRelease, "preserve-uncertain", "STAGE4_WORKSPACE_LEASE_INVALID");
});

test("canonical byte input is bounded and rejects malformed or noncanonical I/O", () => {
  const value = graph();
  const canonical = canonicalStage4StorageLaunchBytes(value);
  assert.ok(canonical.byteLength < STAGE4_STORAGE_LAUNCH_LIMITS.maxContractBytes);
  assert.equal(validateStage4StorageLaunchBytes(canonical).status, "admissible-static-graph");
  expectResult(
    validateStage4StorageLaunchBytes(new Uint8Array(STAGE4_STORAGE_LAUNCH_LIMITS.maxContractBytes + 1)),
    "preserve-uncertain",
    "STAGE4_BOUNDED_IO_VIOLATION",
  );
  expectResult(validateStage4StorageLaunchBytes(new Uint8Array()), "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");
  expectResult(
    validateStage4StorageLaunchBytes(new TextEncoder().encode(`${JSON.stringify(value)}\n`)),
    "reject",
    "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE",
  );
  expectResult(
    validateStage4StorageLaunchBytes(new TextEncoder().encode("{not-json}\n")),
    "reject",
    "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE",
  );

  const longString = graph();
  longString.workspace_lease.workspace_id = "x".repeat(STAGE4_STORAGE_LAUNCH_LIMITS.maxStringBytes + 1);
  expect(longString, "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");

  const oversizedCanonical = graph();
  oversizedCanonical.oversized = Object.fromEntries(
    Array.from({ length: 64 }, (_, index) => [
      `field-${index}`,
      "x".repeat(STAGE4_STORAGE_LAUNCH_LIMITS.maxStringBytes),
    ]),
  );
  assert.throws(() => canonicalStage4StorageLaunchBytes(oversizedCanonical), /byte bound/u);
});

test("getter, proxy, sparse-array, symbol, and prototype inputs fail closed without trap escape", () => {
  let getterInvoked = false;
  const getter = graph();
  Object.defineProperty(getter, "hostile", {
    enumerable: true,
    get() {
      getterInvoked = true;
      throw new Error("must not execute");
    },
  });
  expect(getter, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  assert.equal(getterInvoked, false);

  const hostileProxy = new Proxy(graph(), {
    ownKeys() {
      throw new Error("must not escape");
    },
  });
  assert.doesNotThrow(() => evaluateStage4StorageLaunchGraph(hostileProxy));
  expect(hostileProxy, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");

  const prototype = graph();
  Object.setPrototypeOf(prototype, new Date());
  expect(prototype, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");

  const sparse = graph();
  sparse.resources.kata_sandbox.length = 2;
  expect(sparse, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");

  const symbol = graph() as Graph & { [key: symbol]: boolean };
  symbol[Symbol("hostile")] = true;
  expect(symbol, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
});

test("unknown fields and authority promotion are rejected by both schema and classifier", () => {
  const unknown = graph();
  unknown.provider = "aws";
  assert.equal(validateContract(unknown), false);
  expect(unknown, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");

  const promoted = graph();
  promoted.authority = "authoritative-production-profile";
  expect(promoted, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");

  const wrongVersion = graph();
  wrongVersion.version = "cogs.stage4-storage-launch-contract/v2";
  expect(wrongVersion, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_VERSION");

  const output = verdict(graph()) as Stage4StorageLaunchVerdict & { release_eligible: boolean };
  assert.equal(validateVerdict({ ...output, release_eligible: true }), false);
  assert.equal(validateVerdict({ ...output, provider_truth_observed: true }), false);
});

test("module has no launcher, process, filesystem, network, Kubernetes, or provider surface", () => {
  assert.deepEqual(Object.keys(contractModule).sort(), [
    "STAGE4_STORAGE_LAUNCH_LIMITS",
    "STAGE4_STORAGE_LAUNCH_REASON_CODES",
    "STAGE4_STORAGE_ROLES",
    "canonicalStage4StorageLaunchBytes",
    "evaluateStage4StorageLaunchGraph",
    "validateStage4StorageLaunchBytes",
  ]);
  assert.equal(STAGE4_STORAGE_LAUNCH_REASON_CODES.length, 18);
  const source = readFileSync(resolve(root, "scripts/stage4-storage-launch-contract.ts"), "utf8");
  assert.doesNotMatch(
    source,
    /from\s+["']node:(?:child_process|fs|http|https|http2|net|tls|dns|dgram|os|worker_threads)["']|@aws|@kubernetes|aws-sdk|kubernetes-client/iu,
  );
  assert.doesNotMatch(source, /\bprocess(?:\.|\[)|\bfetch\s*\(|\b(?:helm|kubectl|opentofu|terraform)\b/iu);
  assert.doesNotMatch(source, /\b(?:spawn|exec|fork|writeFile|appendFile|createServer)\b/u);
});
