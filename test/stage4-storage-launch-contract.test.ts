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
  launch_document: Json & { metadata: Json; ssh_host_key: Json };
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
  if (status === "preserve-uncertain") {
    assert.deepEqual(result.preservation, {
      state: "preserve",
      resources: "preserve",
      attachments: "preserve",
      workspace_lease: "preserve",
    });
  } else {
    assert.equal(result.preservation, null);
  }
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

function markUncertain(value: Graph): Graph {
  value.lifecycle.state = "uncertain";
  value.lifecycle.kata_sandbox = "uncertain";
  value.lifecycle.uncertainty_artifact_sha256 = "f".repeat(64);
  value.workspace_lease.state = "uncertain";
  return value;
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
  assert.equal(trusted(value).session_id, value.launch_document.metadata.session_id);
  assert.equal(sandbox(value).session_id, value.launch_document.metadata.session_id);
  assert.equal(trusted(value).workspace_id, value.launch_document.metadata.workspace_id);
  assert.equal(sandbox(value).workspace_id, value.launch_document.metadata.workspace_id);
  assert.equal(value.workspace_lease.workspace_id, value.launch_document.metadata.workspace_id);
  assert.equal(trusted(value).resource_id, value.launch_document.metadata.trusted_worker_proxy_resource_id);
  assert.equal(sandbox(value).resource_id, value.launch_document.metadata.kata_sandbox_resource_id);

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
  sandbox(otherSession).session_id = `cogs.session/v1:sha256:${"9".repeat(64)}`;
  expect(otherSession, "reject", "STAGE4_LAUNCH_BINDING_INVALID");
});

test("domain-separated immutable launch metadata is derived and binds every session, workspace, and resource reference", () => {
  const metadataMutations: Array<(value: Graph) => void> = [
    (value) => (value.launch_document.metadata.session_id = `cogs.session/v1:sha256:${"9".repeat(64)}`),
    (value) => (value.launch_document.metadata.workspace_id = `cogs.workspace/v1:sha256:${"9".repeat(64)}`),
    (value) =>
      (value.launch_document.metadata.trusted_worker_proxy_resource_id = `cogs.resource.trusted-worker-proxy/v1:sha256:${"9".repeat(64)}`),
    (value) =>
      (value.launch_document.metadata.kata_sandbox_resource_id = `cogs.resource.kata-sandbox/v1:sha256:${"9".repeat(64)}`),
    (value) => (value.launch_document.metadata.source_revision_sha256 = "9".repeat(64)),
    (value) => (value.launch_document.metadata.launch_nonce_sha256 = "9".repeat(64)),
  ];
  for (const mutate of metadataMutations) {
    const value = graph();
    const retainedDigest = value.launch_document.document_sha256;
    mutate(value);
    assert.equal(value.launch_document.document_sha256, retainedDigest);
    expect(value, "reject", "STAGE4_LAUNCH_DOCUMENT_DIGEST_MISMATCH");
  }

  const forgedDigest = graph();
  forgedDigest.launch_document.document_sha256 = "9".repeat(64);
  expect(forgedDigest, "reject", "STAGE4_LAUNCH_DOCUMENT_DIGEST_MISMATCH");

  const boundMutations: Array<(value: Graph) => void> = [
    (value) => (trusted(value).session_id = `cogs.session/v1:sha256:${"8".repeat(64)}`),
    (value) => (sandbox(value).workspace_id = `cogs.workspace/v1:sha256:${"8".repeat(64)}`),
    (value) => (trusted(value).resource_id = `cogs.resource.trusted-worker-proxy/v1:sha256:${"8".repeat(64)}`),
    (value) => (sandbox(value).resource_id = `cogs.resource.kata-sandbox/v1:sha256:${"8".repeat(64)}`),
    (value) => (value.workspace_lease.workspace_id = `cogs.workspace/v1:sha256:${"8".repeat(64)}`),
  ];
  for (const mutate of boundMutations) {
    const value = graph();
    mutate(value);
    expect(value, "reject", "STAGE4_LAUNCH_BINDING_INVALID");
  }

  for (const mutate of [
    (value: Graph) => (value.launch_document.metadata.session_id = "session-token-shaped"),
    (value: Graph) => (value.workspace_lease.workspace_id = "workspace-secret-shaped"),
    (value: Graph) => (trusted(value).resource_id = "resource-credential-shaped"),
  ]) {
    const value = graph();
    mutate(value);
    expect(value, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  }
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
  const concurrentVerdict = verdict(concurrent);
  expectResult(concurrentVerdict, "preserve-uncertain", "STAGE4_WORKSPACE_CONCURRENT_WRITER");
  assert.equal(Object.isFrozen(concurrentVerdict.preservation), true);
  assert.equal(validateVerdict({ ...concurrentVerdict, preservation: null }), false);

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

  expect(markUncertain(graph()), "preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS");

  const stickyAdmissionErrors: Array<(value: Graph) => void> = [
    (value) => (value.launch_document.ssh_host_key.verification = "mismatch"),
    (value) => {
      value.runtime_class.resolution = "missing";
      value.runtime_class.resolved_name = null;
    },
    (value) => value.resources.kata_sandbox.push(structuredClone(sandbox(value))),
    (value) => (trusted(value).ephemeral_identity_persistence = "report"),
    (value) => (value.storage.workspace.access_mode = "ReadWriteMany"),
    (value) => (value.launch_document.state = "stale"),
    (value) => (value.launch_document.metadata.session_id = `cogs.session/v1:sha256:${"9".repeat(64)}`),
    (value) => (sandbox(value).launch_document_sha256 = "9".repeat(64)),
    (value) => (value.workspace_lease.writer_count = 2),
    (value) => (trusted(value).resource_id = "token-shaped-invalid-resource-id"),
    (value) => (value.workspace_lease.workspace_id = "credential-shaped-invalid-workspace-id"),
    (value) => (value.unreviewedAdmissionField = true),
    (value) => (value.version = "cogs.stage4-storage-launch-contract/v2"),
  ];
  for (const mutate of stickyAdmissionErrors) {
    const value = markUncertain(graph());
    mutate(value);
    expect(value, "preserve-uncertain", "STAGE4_CLEANUP_AMBIGUOUS");
  }

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

  let byteProxyTraps = 0;
  const proxiedBytes = new Proxy(canonical, {
    get() {
      byteProxyTraps += 1;
      throw new Error("byte proxy get trap must not execute");
    },
    getPrototypeOf() {
      byteProxyTraps += 1;
      throw new Error("byte proxy prototype trap must not execute");
    },
    ownKeys() {
      byteProxyTraps += 1;
      throw new Error("byte proxy ownKeys trap must not execute");
    },
    getOwnPropertyDescriptor() {
      byteProxyTraps += 1;
      throw new Error("byte proxy descriptor trap must not execute");
    },
  });
  expectResult(validateStage4StorageLaunchBytes(proxiedBytes), "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  assert.equal(byteProxyTraps, 0, "proxied Uint8Array must be rejected before byteLength or index access");

  expectResult(
    validateStage4StorageLaunchBytes(new Uint8Array(STAGE4_STORAGE_LAUNCH_LIMITS.maxContractBytes + 1)),
    "preserve-uncertain",
    "STAGE4_BOUNDED_IO_VIOLATION",
  );
  expectResult(validateStage4StorageLaunchBytes(new Uint8Array()), "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");
  const noncanonical = [
    new TextEncoder().encode(`${JSON.stringify(value)}\n`),
    canonical.slice(0, -1),
    new TextEncoder().encode(`${new TextDecoder().decode(canonical).replace(/\n$/u, "\r\n")}`),
    new TextEncoder().encode(`${new TextDecoder().decode(canonical)}\n`),
    new Uint8Array([0xef, 0xbb, 0xbf, ...canonical]),
  ];
  for (const bytes of noncanonical) {
    expectResult(validateStage4StorageLaunchBytes(bytes), "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  }
  expectResult(
    validateStage4StorageLaunchBytes(new TextEncoder().encode("{not-json}\n")),
    "reject",
    "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE",
  );

  const longString = graph();
  longString.workspace_lease.workspace_id = "x".repeat(STAGE4_STORAGE_LAUNCH_LIMITS.maxStringBytes + 1);
  expect(longString, "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");

  const oversizedKey = graph();
  oversizedKey["k".repeat(STAGE4_STORAGE_LAUNCH_LIMITS.maxPropertyKeyBytes + 1)] = true;
  const oversizedKeyVerdict = evaluateStage4StorageLaunchGraph(oversizedKey);
  expectResult(oversizedKeyVerdict, "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");
  assert.equal(oversizedKeyVerdict.graph_sha256, null, "oversized keys are rejected before hashing");

  const tooManyKeys = graph();
  tooManyKeys.oversized = Object.fromEntries(
    Array.from({ length: STAGE4_STORAGE_LAUNCH_LIMITS.maxPropertiesPerObject + 1 }, (_, index) => [
      `field-${index}`,
      true,
    ]),
  );
  const tooManyKeysVerdict = evaluateStage4StorageLaunchGraph(tooManyKeys);
  expectResult(tooManyKeysVerdict, "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");
  assert.equal(tooManyKeysVerdict.graph_sha256, null);

  const tooDeep = graph();
  let cursor: Json = {};
  tooDeep.tooDeep = cursor;
  for (let depth = 0; depth <= STAGE4_STORAGE_LAUNCH_LIMITS.maxDepth; depth += 1) {
    const next: Json = {};
    cursor.next = next;
    cursor = next;
  }
  const depthVerdict = evaluateStage4StorageLaunchGraph(tooDeep);
  expectResult(depthVerdict, "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");
  assert.equal(depthVerdict.graph_sha256, null);

  const oversizedCanonical = graph();
  oversizedCanonical.oversized = Object.fromEntries(
    Array.from({ length: 64 }, (_, index) => [
      `field-${index}`,
      "x".repeat(STAGE4_STORAGE_LAUNCH_LIMITS.maxStringBytes),
    ]),
  );
  const aggregateVerdict = evaluateStage4StorageLaunchGraph(oversizedCanonical);
  expectResult(aggregateVerdict, "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");
  assert.equal(aggregateVerdict.graph_sha256, null, "aggregate overflow is rejected before hashing");
  assert.throws(() => canonicalStage4StorageLaunchBytes(oversizedCanonical), /bound/u);
});

test("intrinsic byte capture rejects hostile typed-array storage without getters or oversized processing", () => {
  const canonical = canonicalStage4StorageLaunchBytes(graph());
  let getterReads = 0;
  for (const key of ["byteLength", "buffer"] as const) {
    Object.defineProperty(canonical, key, {
      configurable: true,
      get() {
        getterReads += 1;
        throw new Error("must not execute");
      },
    });
  }
  assert.equal(validateStage4StorageLaunchBytes(canonical).status, "admissible-static-graph");
  assert.equal(getterReads, 0);

  const oversized = new Uint8Array(STAGE4_STORAGE_LAUNCH_LIMITS.maxContractBytes + 1);
  Object.defineProperty(oversized, "byteLength", {
    get() {
      getterReads += 1;
      return 1;
    },
  });
  expectResult(validateStage4StorageLaunchBytes(oversized), "preserve-uncertain", "STAGE4_BOUNDED_IO_VIOLATION");
  assert.equal(getterReads, 0);

  const impostor = Object.create(Uint8Array.prototype) as Uint8Array;
  Object.defineProperty(impostor, "byteLength", {
    get() {
      getterReads += 1;
      throw new Error("must not execute");
    },
  });
  expectResult(validateStage4StorageLaunchBytes(impostor), "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  assert.equal(validateStage4StorageLaunchBytes(Buffer.from(canonical)).status, "reject");
  assert.equal(getterReads, 0);

  if (typeof SharedArrayBuffer !== "undefined") {
    const shared = new Uint8Array(new SharedArrayBuffer(Uint8Array.prototype.slice.call(canonical).length));
    shared.set(canonical);
    assert.equal(validateStage4StorageLaunchBytes(shared).status, "reject");
  }
  const resizableBuffer = new ArrayBuffer(Uint8Array.prototype.slice.call(canonical).length, {
    maxByteLength: Uint8Array.prototype.slice.call(canonical).length + 1,
  });
  if (resizableBuffer.resizable) {
    const resizable = new Uint8Array(resizableBuffer);
    resizable.set(canonical);
    assert.equal(validateStage4StorageLaunchBytes(resizable).status, "reject");
  }
  const detachedBuffer = new ArrayBuffer(Uint8Array.prototype.slice.call(canonical).length);
  const detached = new Uint8Array(detachedBuffer);
  detached.set(canonical);
  structuredClone(detachedBuffer, { transfer: [detachedBuffer] });
  assert.notEqual(validateStage4StorageLaunchBytes(detached).status, "admissible-static-graph");
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

  let proxyTraps = 0;
  const traps = {
    getPrototypeOf() {
      proxyTraps += 1;
      return Object.prototype;
    },
    ownKeys() {
      proxyTraps += 1;
      return [];
    },
    getOwnPropertyDescriptor() {
      proxyTraps += 1;
      return undefined;
    },
    get() {
      proxyTraps += 1;
      return undefined;
    },
  };
  const hostileProxy = new Proxy(graph(), traps);
  assert.doesNotThrow(() => evaluateStage4StorageLaunchGraph(hostileProxy));
  expect(hostileProxy, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  assert.equal(proxyTraps, 0, "root transparent proxy traps must never execute");

  const functionProxy = new Proxy(() => undefined, traps);
  expect(functionProxy, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  assert.equal(proxyTraps, 0, "callable proxy traps must never execute");

  const nestedProxy = graph();
  nestedProxy.runtime_class = new Proxy(nestedProxy.runtime_class, traps);
  expect(nestedProxy, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  assert.equal(proxyTraps, 0, "nested transparent proxy traps must never execute");

  const arrayProxy = graph();
  arrayProxy.resources.kata_sandbox = new Proxy(arrayProxy.resources.kata_sandbox, traps);
  expect(arrayProxy, "reject", "STAGE4_STORAGE_LAUNCH_INVALID_SHAPE");
  assert.equal(proxyTraps, 0, "array proxy traps must never execute");

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
  assert.equal(STAGE4_STORAGE_LAUNCH_REASON_CODES.length, 19);
  const source = readFileSync(resolve(root, "scripts/stage4-storage-launch-contract.ts"), "utf8");
  assert.doesNotMatch(
    source,
    /from\s+["']node:(?:child_process|fs|http|https|http2|net|tls|dns|dgram|os|worker_threads)["']|@aws|@kubernetes|aws-sdk|kubernetes-client/iu,
  );
  assert.doesNotMatch(source, /\bprocess(?:\.|\[)|\bfetch\s*\(|\b(?:helm|kubectl|opentofu|terraform)\b/iu);
  assert.match(source, /utilTypes\.isProxy\(candidate\)/u);
  assert.doesNotMatch(source, /\b(?:spawn|exec|fork|writeFile|appendFile|createServer)\b/u);
});
