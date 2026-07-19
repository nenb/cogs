import assert from "node:assert/strict";
import type { randomBytes } from "node:crypto";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  beginWorkerStartup,
  bindWorkerChild,
  cleanupControlFiles,
  createApiToken,
  promoteWorkerReady,
  readApiToken,
  readReadyWorkerDescriptor,
  readWorkerDescriptor,
  verifyWorkerIdentity,
} from "../dev/launcher/control.ts";
import { startOtlpFixture } from "../dev/launcher/otlp-fixture.ts";
import { createState, readManifest, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";
import {
  createParentChallenge,
  createSupervisorAdmit,
  createSupervisorReadyAck,
  parseChildIdentityHello,
  parseChildReady,
  parseWorkerProtocolMessage,
} from "../dev/launcher/worker-protocol.ts";
import { createCogsEgressTelemetrySink } from "../src/egress/otlp-telemetry.ts";
import { createCogsWorkerTelemetrySink } from "../src/telemetry/worker-telemetry.ts";

const sourceRevision = "a".repeat(40);
async function state() {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-control-"));
  const root = join(await realpath(dir), "launcher");
  await mkdir(root, { mode: 0o700 });
  const s = await resolveLauncherState({ root, name: "s1", sourceRevision });
  const m = await createState(s, "linux-kvm");
  await writePhase(s, m, "sandbox-ready");
  return { dir, state: s };
}
const digest = `sha256:${"1".repeat(64)}`;
const digest2 = `sha256:${"2".repeat(64)}`;
function seams(...args: [identity?: string | null | undefined, random?: () => Buffer, parentPid?: number]): Readonly<{
  randomBytes: typeof randomBytes;
  identity: () => string | null | undefined;
  parentPid?: number;
}> {
  const value = args.length >= 1 ? args[0] : digest;
  const random = args.length >= 2 && args[1] ? args[1] : () => Buffer.alloc(32, 7);
  return Object.freeze({
    randomBytes: Object.freeze(random as typeof randomBytes),
    identity: Object.freeze(() => value),
    ...(args[2] === undefined ? {} : { parentPid: args[2] }),
  });
}

async function readyWorker(s: Awaited<ReturnType<typeof state>>["state"], childIdentity = digest): Promise<void> {
  const parentPid = 111;
  const childPid = 222;
  const startup = await beginWorkerStartup(s, seams(digest, () => Buffer.alloc(32, 7), parentPid) as never);
  await bindWorkerChild(
    s,
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-identity",
      startupDigest: startup.startup.digest(),
      pid: childPid,
      pidIdentity: childIdentity,
    }),
    seams(childIdentity) as never,
  );
  await promoteWorkerReady(
    s,
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-ready",
      startupDigest: startup.startup.digest(),
      pid: childPid,
      pidIdentity: childIdentity,
      apiPort: 1234,
    }),
    seams(childIdentity) as never,
  );
  startup.startup.dispose();
}

test("control writes 0600 token and worker descriptor without exposing token in metadata", async () => {
  const { dir, state: s } = await state();
  try {
    await createApiToken(s, seams());
    const holder = await readApiToken(s);
    const token = holder.read();
    assert.match(token, /^[A-Za-z0-9_-]{43}$/u);
    assert.equal(JSON.stringify(holder).includes(token), false);
    await readyWorker(s);
    const descriptor = await readWorkerDescriptor(s);
    assert.equal(JSON.stringify(descriptor).includes(token), false);
    assert.equal(await verifyWorkerIdentity(s, seams(digest)), true);
    holder.dispose();
    assert.throws(() => holder.read());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control rejects malformed token descriptor races links extras and identity changes", async () => {
  const { dir, state: s } = await state();
  try {
    await assert.rejects(() =>
      createApiToken(
        s,
        seams("pid:one", () => Buffer.alloc(32)),
      ),
    );
    await createApiToken(s, seams());
    await assert.rejects(() => createApiToken(s, seams()));
    await readyWorker(s);
    await assert.rejects(() => verifyWorkerIdentity(s, seams(digest2)));
    assert.equal(await verifyWorkerIdentity(s, seams(null as never)), false);
    await assert.rejects(() => cleanupControlFiles(s, seams(digest)));
    await writeFile(join(s.controlDir, "extra"), "x", { mode: 0o600 });
    await assert.rejects(() => cleanupControlFiles(s, seams(null as never)));
    await readApiToken(s);
    await rm(join(s.controlDir, "extra"), { force: true });
    await cleanupControlFiles(s, seams(null as never));
    await assert.rejects(() => cleanupControlFiles(s, seams(null as never)));
    await assert.rejects(() => readApiToken(s));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control rejects symlink hardlink replacement and noncanonical worker", async () => {
  const { dir, state: s } = await state();
  try {
    await symlink("/tmp/nope", join(s.controlDir, "api-token"));
    await assert.rejects(() => readApiToken(s));
    await rm(join(s.controlDir, "api-token"), { force: true });
    await createApiToken(s, seams());
    await link(join(s.controlDir, "api-token"), join(s.controlDir, "api-token-link"));
    await assert.rejects(() => readApiToken(s));
    await rm(join(s.controlDir, "api-token-link"), { force: true });
    await chmod(join(s.controlDir, "api-token"), 0o644);
    await assert.rejects(() => readApiToken(s));
    await rm(join(s.controlDir, "api-token"), { force: true });
    await writeFile(join(s.controlDir, "worker.json"), '{"version":"cogs.dev-launcher-worker/v1alpha1"}\n', {
      mode: 0o600,
    });
    await assert.rejects(() => readWorkerDescriptor(s));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control binds worker descriptor to manifest source and profile across source revisions", async () => {
  const { dir, state: oldState } = await state();
  try {
    const newer = await resolveLauncherState({
      root: oldState.root,
      name: oldState.name,
      sourceRevision: "b".repeat(40),
    });
    await readyWorker(newer);
    const descriptor = await readWorkerDescriptor(newer);
    assert.equal(descriptor.sourceRevision, sourceRevision);
    assert.equal(descriptor.profile, "linux-kvm");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control rejects bad startup random lengths and disposes nonce on write failure", async () => {
  const { dir, state: s } = await state();
  try {
    await assert.rejects(() => beginWorkerStartup(s, seams(digest, () => Buffer.alloc(31)) as never));
    await assert.rejects(() => beginWorkerStartup(s, seams(digest, () => Buffer.alloc(33)) as never));
    await assert.rejects(() => beginWorkerStartup(s, seams(digest, () => Buffer.alloc(32)) as never));
    await assert.rejects(() =>
      beginWorkerStartup(
        s,
        Object.freeze({
          randomBytes: Object.freeze(() => Buffer.alloc(32, 6)) as never,
          identity: Object.freeze(() => digest),
          afterExclusiveWrite: Object.freeze(async () => {
            throw new Error("write failed");
          }),
        }) as never,
      ),
    );
    await assert.rejects(() => readWorkerDescriptor(s));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control partial token create removes exact owned file", async () => {
  const { dir, state: s } = await state();
  try {
    await assert.rejects(() =>
      createApiToken(
        s,
        Object.freeze({
          randomBytes: seams().randomBytes,
          identity: seams().identity,
          afterExclusiveOpen: Object.freeze(async () => {
            throw new Error("boom");
          }),
        }),
      ),
    );
    await assert.rejects(() => readFile(join(s.controlDir, "api-token")));
    await createApiToken(s, seams());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control rejects sandbox symlink or unsafe mode without deleting controls", async () => {
  const { dir, state: s } = await state();
  try {
    await createApiToken(s, seams());
    await rm(s.sandboxDir, { recursive: true, force: true });
    await symlink("/tmp", s.sandboxDir);
    await assert.rejects(() => cleanupControlFiles(s, seams(null)));
    await readApiToken(s);
    await rm(s.sandboxDir, { force: true });
    await mkdir(s.sandboxDir, { mode: 0o700 });
    await chmod(s.sandboxDir, 0o755);
    await assert.rejects(() => cleanupControlFiles(s, seams(null)));
    await readApiToken(s);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control cleanup preserves files on identity seam throw", async () => {
  const { dir, state: s } = await state();
  try {
    await createApiToken(s, seams());
    await readyWorker(s);
    await assert.rejects(() =>
      cleanupControlFiles(
        s,
        Object.freeze({
          randomBytes: seams().randomBytes,
          identity: Object.freeze(() => {
            throw new Error("boom");
          }),
        }),
      ),
    );
    await readApiToken(s);
    await readWorkerDescriptor(s);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control cleanup preserves files on unavailable pid identity and removes on definite absence", async () => {
  const { dir, state: s } = await state();
  try {
    await createApiToken(s, seams());
    await readyWorker(s);
    await assert.rejects(() => cleanupControlFiles(s, seams(undefined)));
    await assert.rejects(() => verifyWorkerIdentity(s, seams(undefined)));
    await readApiToken(s);
    await readWorkerDescriptor(s);
    await cleanupControlFiles(s, seams(null));
    await assert.rejects(() => readApiToken(s));
    await assert.rejects(() => readWorkerDescriptor(s));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control cleanup preserves files on malformed observed pid identity", async () => {
  const { dir, state: s } = await state();
  try {
    await createApiToken(s, seams());
    await readyWorker(s);
    await assert.rejects(() => cleanupControlFiles(s, seams("pid:malformed")));
    await assert.rejects(() => verifyWorkerIdentity(s, seams("pid:malformed")));
    await readApiToken(s);
    await readWorkerDescriptor(s);
    await cleanupControlFiles(s, seams(digest2));
    await assert.rejects(() => readApiToken(s));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control performs pre-spawn child-bound and ready descriptor promotion canonically", async () => {
  const { dir, state: s } = await state();
  try {
    const parentPid = 111;
    const childPid = 222;
    const started = await beginWorkerStartup(s, seams(digest, () => Buffer.alloc(32, 9), parentPid) as never);
    const preSpawn = await readWorkerDescriptor(s);
    assert.equal(preSpawn.readiness, "starting");
    assert.equal(preSpawn.stage, "pre-spawn");
    assert.equal(preSpawn.parentPid, parentPid);
    assert.match(started.startup.digest(), /^sha256:[a-f0-9]{64}$/u);
    assert.equal(JSON.stringify(started.startup).includes("CQk"), false);
    const descriptorBytes = await readFile(join(s.controlDir, "worker.json"), "utf8");
    assert.equal(
      descriptorBytes,
      `${JSON.stringify(JSON.parse(descriptorBytes), Object.keys(JSON.parse(descriptorBytes)).sort())}\n`,
    );
    assert.equal((await lstat(join(s.controlDir, "worker.json"))).mode & 0o777, 0o600);

    const bound = await bindWorkerChild(
      s,
      Object.freeze({
        version: "cogs.dev-launcher-worker-protocol/v1alpha1",
        type: "child-identity",
        startupDigest: started.startup.digest(),
        pid: childPid,
        pidIdentity: digest2,
      }),
      seams(digest2) as never,
    );
    assert.equal(bound.stage, "child-bound");
    assert.equal(bound.childPid, childPid);

    const ready = await promoteWorkerReady(
      s,
      Object.freeze({
        version: "cogs.dev-launcher-worker-protocol/v1alpha1",
        type: "child-ready",
        startupDigest: started.startup.digest(),
        pid: childPid,
        pidIdentity: digest2,
        apiPort: 4321,
      }),
      seams(digest2) as never,
    );
    assert.equal(ready.stage, "ready");
    assert.equal(ready.apiPort, 4321);
    assert.equal((await readReadyWorkerDescriptor(s)).childPidIdentity, digest2);
    started.startup.dispose();
    assert.throws(() => started.startup.digest());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control rejects descriptor mutation identity mismatch unavailable and malformed ready state", async () => {
  const { dir, state: s } = await state();
  try {
    const startup = await beginWorkerStartup(s, seams(digest, () => Buffer.alloc(32, 10)) as never);
    await assert.rejects(() =>
      bindWorkerChild(
        s,
        Object.freeze({
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: "child-identity",
          startupDigest: startup.startup.digest(),
          pid: 333,
          pidIdentity: digest2,
        }),
        seams(undefined) as never,
      ),
    );
    await assert.rejects(() =>
      bindWorkerChild(
        s,
        Object.freeze({
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: "child-identity",
          startupDigest: `sha256:${"3".repeat(64)}`,
          pid: 333,
          pidIdentity: digest2,
        }),
        seams(digest2) as never,
      ),
    );
    const bound = await bindWorkerChild(
      s,
      Object.freeze({
        version: "cogs.dev-launcher-worker-protocol/v1alpha1",
        type: "child-identity",
        startupDigest: startup.startup.digest(),
        pid: 333,
        pidIdentity: digest2,
      }),
      seams(digest2) as never,
    );
    assert.equal(bound.stage, "child-bound");
    await assert.rejects(() =>
      promoteWorkerReady(
        s,
        Object.freeze({
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: "child-ready",
          startupDigest: startup.startup.digest(),
          pid: 333,
          pidIdentity: digest,
          apiPort: 4321,
        }),
        seams(digest) as never,
      ),
    );
    await assert.rejects(() => readReadyWorkerDescriptor(s));
    await writePhase(s, await import("../dev/launcher/state.ts").then((m) => m.readManifest(s)), "worker-ready");
    await assert.rejects(() => cleanupControlFiles(s, seams(null)));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control replacement preserves uncertain temp and rejects live cleanup", async () => {
  const { dir, state: s } = await state();
  try {
    const startup = await beginWorkerStartup(s, seams(digest, () => Buffer.alloc(32, 11)) as never);
    await assert.rejects(() =>
      bindWorkerChild(
        s,
        Object.freeze({
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: "child-identity",
          startupDigest: startup.startup.digest(),
          pid: 444,
          pidIdentity: digest2,
        }),
        Object.freeze({
          randomBytes: seams().randomBytes,
          identity: Object.freeze(() => digest2),
          tempName: Object.freeze(() => `.worker-${s.stateId}-fixed.tmp`),
          afterExclusiveWrite: Object.freeze(async () => {
            throw new Error("fsync uncertain");
          }),
        }) as never,
      ),
    );
    await lstat(join(s.controlDir, `.worker-${s.stateId}-fixed.tmp`));
    await assert.rejects(() => cleanupControlFiles(s, seams(null)));
    await rm(join(s.controlDir, `.worker-${s.stateId}-fixed.tmp`), { force: true });
    await assert.rejects(() => cleanupControlFiles(s, seams(digest)));
    await cleanupControlFiles(s, seams(digest2));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control enforces admission ordering and repeated transitions", async () => {
  const { dir, state: s } = await state();
  try {
    const startup = await beginWorkerStartup(s, seams(digest, () => Buffer.alloc(32, 12), 555) as never);
    const readyMessage = Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-ready",
      startupDigest: startup.startup.digest(),
      pid: 666,
      pidIdentity: digest2,
      apiPort: 4321,
    });
    await assert.rejects(() => promoteWorkerReady(s, readyMessage, seams(digest2) as never));
    await assert.rejects(() =>
      bindWorkerChild(
        s,
        Object.freeze({
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: "child-identity",
          startupDigest: startup.startup.digest(),
          pid: 555,
          pidIdentity: digest2,
        }),
        seams(digest2) as never,
      ),
    );
    await bindWorkerChild(
      s,
      Object.freeze({
        version: "cogs.dev-launcher-worker-protocol/v1alpha1",
        type: "child-identity",
        startupDigest: startup.startup.digest(),
        pid: 666,
        pidIdentity: digest2,
      }),
      seams(digest2) as never,
    );
    await assert.rejects(() =>
      bindWorkerChild(
        s,
        Object.freeze({
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: "child-identity",
          startupDigest: startup.startup.digest(),
          pid: 666,
          pidIdentity: digest2,
        }),
        seams(digest2) as never,
      ),
    );
    await promoteWorkerReady(s, readyMessage, seams(digest2) as never);
    await assert.rejects(() => promoteWorkerReady(s, readyMessage, seams(digest2) as never));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("control cleanup keys pre-spawn to parent and child-bound to child only", async () => {
  const first = await state();
  try {
    await createApiToken(first.state, seams());
    await beginWorkerStartup(first.state, seams(digest, () => Buffer.alloc(32, 13), 777) as never);
    await assert.rejects(() => cleanupControlFiles(first.state, seams(digest)));
    await assert.rejects(() => cleanupControlFiles(first.state, seams(undefined)));
    await cleanupControlFiles(first.state, seams(null));
    await assert.rejects(() => readWorkerDescriptor(first.state));
  } finally {
    await rm(first.dir, { recursive: true, force: true });
  }

  const second = await state();
  try {
    const startup = await beginWorkerStartup(second.state, seams(digest, () => Buffer.alloc(32, 14), 888) as never);
    await bindWorkerChild(
      second.state,
      Object.freeze({
        version: "cogs.dev-launcher-worker-protocol/v1alpha1",
        type: "child-identity",
        startupDigest: startup.startup.digest(),
        pid: 999,
        pidIdentity: digest2,
      }),
      seams(digest2) as never,
    );
    const childOnlySeams = Object.freeze({
      randomBytes: seams().randomBytes,
      identity: Object.freeze((pid: number) => {
        if (pid === 888) throw new Error("parent identity must not be observed");
        return pid === 999 ? digest2 : null;
      }),
    });
    await assert.rejects(() => cleanupControlFiles(second.state, childOnlySeams as never));
    await assert.rejects(() => verifyWorkerIdentity(second.state, seams(digest)));
    await cleanupControlFiles(
      second.state,
      Object.freeze({
        randomBytes: seams().randomBytes,
        identity: Object.freeze((pid: number) => {
          if (pid === 888) throw new Error("parent identity must not be observed");
          return pid === 999 ? digest : null;
        }),
      }) as never,
    );
  } finally {
    await rm(second.dir, { recursive: true, force: true });
  }
});

test("control preserves worker-ready manifest with child-bound descriptor", async () => {
  const { dir, state: s } = await state();
  try {
    const startup = await beginWorkerStartup(s, seams(digest, () => Buffer.alloc(32, 15), 555) as never);
    await bindWorkerChild(
      s,
      Object.freeze({
        version: "cogs.dev-launcher-worker-protocol/v1alpha1",
        type: "child-identity",
        startupDigest: startup.startup.digest(),
        pid: 666,
        pidIdentity: digest2,
      }),
      seams(digest2) as never,
    );
    await writePhase(s, await readManifest(s), "worker-ready");
    await assert.rejects(() => cleanupControlFiles(s, seams(null)));
    assert.equal((await readWorkerDescriptor(s)).stage, "child-bound");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("worker protocol schemas are exact frozen and redact challenge holder metadata", () => {
  const canonicalNonce = Buffer.alloc(32, 1).toString("base64url");
  const startup = {
    withNonce: <T>(operation: (nonce: string) => T) => operation(canonicalNonce),
  };
  const challenge = createParentChallenge(startup);
  assert.equal(Object.isFrozen(challenge), true);
  assert.equal(challenge.type, "parent-challenge");
  assert.equal(JSON.stringify(startup).includes("A".repeat(20)), false);
  const hello = parseChildIdentityHello(
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-identity",
      startupDigest: digest,
      pid: 123,
      pidIdentity: digest2,
    }),
  );
  assert.equal(hello.pidIdentity, digest2);
  assert.equal(createSupervisorAdmit(digest).type, "supervisor-admit");
  const ready = parseChildReady(
    Object.freeze({
      version: "cogs.dev-launcher-worker-protocol/v1alpha1",
      type: "child-ready",
      startupDigest: digest,
      pid: 123,
      pidIdentity: digest2,
      apiPort: 1234,
    }),
  );
  assert.equal(ready.apiPort, 1234);
  assert.equal(createSupervisorReadyAck(digest).type, "supervisor-ready-ack");
  const zeroNonce = Buffer.alloc(32).toString("base64url");
  const noncanonicalNonce = `${Buffer.alloc(32, 1).toString("base64url").slice(0, -1)}=`;
  for (const bad of ["A".repeat(42), "A".repeat(44), "!".repeat(43), zeroNonce, noncanonicalNonce]) {
    assert.throws(() => createParentChallenge({ withNonce: (operation) => operation(bad) }));
    assert.throws(() => parseWorkerProtocolMessage(Object.freeze({ ...challenge, startupNonce: bad })));
  }
  assert.throws(() => parseWorkerProtocolMessage(Object.freeze({ ...hello, extra: true })));
  assert.throws(() =>
    parseChildIdentityHello(
      Object.defineProperty(
        {
          version: "cogs.dev-launcher-worker-protocol/v1alpha1",
          type: "child-identity",
          startupDigest: digest,
          pid: 1,
        },
        "pidIdentity",
        { get: () => digest2, enumerable: true },
      ),
    ),
  );
});

test("otlp fixture accepts worker and egress sinks and snapshots metadata only", async () => {
  const fixture = await startOtlpFixture();
  try {
    const worker = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: fixture.endpoint("traces"),
      metricsEndpoint: fixture.endpoint("metrics"),
      allowLoopbackHttpDevelopment: true,
      timeoutMs: 1000,
      batchSize: 1,
      capacity: 4,
      fetch: Object.freeze(fetch),
      clock: Object.freeze({ nowMs: Object.freeze(() => 1234) }),
      random: Object.freeze({ bytes: Object.freeze((length: number) => new Uint8Array(length).fill(0xab)) }),
    });
    assert.equal(
      worker.span({
        name: "tool.dispatch",
        attributes: {
          outcome: "ok",
          tool: "bash",
          operation: "run",
          duration_ms: 7,
          credential_required: false,
          timed_out: false,
          cancelled: false,
        },
      }),
      true,
    );
    assert.equal(
      worker.metric({ name: "tool.count", attributes: { tool: "bash", count: 1, value: 1, outcome: "ok" } }),
      true,
    );
    await worker.close();
    const egress = createCogsEgressTelemetrySink({
      mode: "otlp",
      endpoint: fixture.endpoint("logs"),
      allowLoopbackHttpDevelopment: true,
      timeoutMs: 100,
      capacity: 4,
    });
    egress.enqueue({
      intent: {
        sequence: 1,
        intent_id: "intent-1",
        timestamp_ms: 1,
        session_id: "session-1",
        integration_id: "integration-1",
        route_id: "route-1",
        method: "GET",
        credential_required: true,
      },
      completion: {
        sequence: 1,
        intentId: "intent-1",
        routeId: "route-1",
        responseCode: 200,
        durationMs: 1,
        completedAtMs: 2,
      },
    });
    await egress.close();
    const snap = fixture.snapshot();
    assert.equal(snap.ready, true);
    assert.ok(snap.traces >= 1);
    assert.ok(snap.metrics >= 1);
    assert.ok(snap.logs >= 1);
    assert.equal(JSON.stringify(snap).includes("intent-1"), false);
    fixture.reset();
    assert.equal(fixture.snapshot().logs, 0);
  } finally {
    await fixture.close();
  }
});

function validTrace(name = "lifecycle.ready", attributes: unknown[] = []): string {
  return JSON.stringify({
    resourceSpans: [
      {
        resource: { attributes: [{ key: "service.name", value: { stringValue: "cogs-worker" } }] },
        scopeSpans: [
          {
            scope: { name: "cogs.worker.telemetry", version: "v1alpha1" },
            spans: [
              {
                traceId: "a".repeat(32),
                spanId: "b".repeat(16),
                name,
                kind: 1,
                startTimeUnixNano: "1",
                endTimeUnixNano: "2",
                attributes,
              },
            ],
          },
        ],
      },
    ],
  });
}

function validMetric(name = "tool.count", both = false): string {
  const body = {
    resourceMetrics: [
      {
        resource: { attributes: [{ key: "service.name", value: { stringValue: "cogs-worker" } }] },
        scopeMetrics: [
          {
            scope: { name: "cogs.worker.telemetry", version: "v1alpha1" },
            metrics: [
              {
                name,
                sum: {
                  aggregationTemporality: 1,
                  isMonotonic: true,
                  dataPoints: [{ timeUnixNano: "1", asInt: "1", attributes: [] }],
                },
                ...(both ? { gauge: { dataPoints: [{ timeUnixNano: "1", asInt: "1", attributes: [] }] } } : {}),
              },
            ],
          },
        ],
      },
    ],
  };
  return JSON.stringify(body);
}

async function post(endpoint: string, body: string, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(endpoint, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
}
async function rejected(endpoint: string, body: string): Promise<void> {
  try {
    const response = await post(endpoint, body);
    assert.notEqual(response.status, 200);
  } catch (error) {
    assert.match(String(error), /fetch failed/u);
  }
}

test("otlp fixture rejects malformed forbidden oversize and closes sockets", async () => {
  const fixture = await startOtlpFixture({ deadlineMs: 80, maxBytes: 256, maxInflight: 1 });
  try {
    const malformed = await fetch(fixture.endpoint("traces"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "lifecycle.ready" }),
    });
    assert.notEqual(malformed.status, 200);
    for (const body of ['{"secret":"x"}', JSON.stringify({ name: "prompt" }), "x".repeat(300), '{"a":1,"a":2}']) {
      await rejected(fixture.endpoint("traces"), body);
    }
  } finally {
    await fixture.close();
  }
  await assert.rejects(() => fetch(fixture.endpoint("traces"), { method: "POST", body: "{}" }));
});

test("otlp fixture enforces strict trace attribute value types and enums atomically", async () => {
  const fixture = await startOtlpFixture();
  try {
    assert.equal((await post(fixture.endpoint("traces"), validTrace("lifecycle.ready"))).status, 200);
    const before = fixture.snapshot().traces;
    const badBodies = [
      validTrace("lifecycle.ready", [{ key: "cogs.duration_ms", value: { stringValue: "7" } }]),
      validTrace("lifecycle.ready", [{ key: "cogs.credential_required", value: { intValue: "1" } }]),
      validTrace("lifecycle.ready", [{ key: "cogs.outcome", value: { stringValue: "evil" } }]),
      validTrace("lifecycle.ready", [{ key: "evil", value: { stringValue: "ok" } }]),
      JSON.stringify(JSON.parse(validTrace("lifecycle.ready"), (k, v) => (k === "endTimeUnixNano" ? "0" : v))),
    ];
    for (const body of badBodies) assert.notEqual((await post(fixture.endpoint("traces"), body)).status, 200);
    assert.equal(fixture.snapshot().traces, before);
  } finally {
    await fixture.close();
  }
});

test("otlp fixture rejects cross-kind names unprefixed attrs and both gauge plus sum", async () => {
  const fixture = await startOtlpFixture();
  try {
    assert.notEqual((await post(fixture.endpoint("traces"), validTrace("tool.count"))).status, 200);
    assert.notEqual((await post(fixture.endpoint("metrics"), validMetric("lifecycle.ready"))).status, 200);
    assert.notEqual(
      (
        await post(
          fixture.endpoint("traces"),
          validTrace("lifecycle.ready", [{ key: "duration_ms", value: { intValue: "1" } }]),
        )
      ).status,
      200,
    );
    assert.notEqual((await post(fixture.endpoint("metrics"), validMetric("tool.count", true))).status, 200);
    assert.equal(fixture.snapshot().traces, 0);
    assert.equal(fixture.snapshot().metrics, 0);
  } finally {
    await fixture.close();
  }
});

test("otlp fixture enforces cumulative accepted records and reset clears the counter", async () => {
  const fixture = await startOtlpFixture({ maxRecords: 1 });
  try {
    assert.equal((await post(fixture.endpoint("traces"), validTrace())).status, 200);
    assert.equal((await post(fixture.endpoint("traces"), validTrace())).status, 400);
    assert.equal(fixture.snapshot().traces, 1);
    fixture.reset();
    assert.equal((await post(fixture.endpoint("traces"), validTrace())).status, 200);
  } finally {
    await fixture.close();
  }
});

test("otlp fixture rejects duplicate critical raw headers", async () => {
  const fixture = await startOtlpFixture();
  try {
    const socket = new Socket();
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.connect(fixture.snapshot().port, "127.0.0.1", resolve);
    });
    socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    const body = validTrace();
    socket.end(
      `POST /v1/traces HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
    await new Promise((resolve) => socket.once("close", resolve));
    assert.match(Buffer.concat(chunks).toString("utf8"), / 400 /u);
    assert.equal(fixture.snapshot().traces, 0);
  } finally {
    await fixture.close();
  }
});

test("otlp fixture reset rejects inflight trickle and close is idempotent bounded", async () => {
  const fixture = await startOtlpFixture({ deadlineMs: 60 });
  const socket = new Socket();
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.connect(fixture.snapshot().port, "127.0.0.1", resolve);
    });
    socket.write(
      "POST /v1/traces HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{",
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    assert.throws(() => fixture.reset());
    const started = Date.now();
    await Promise.all([fixture.close(), fixture.close()]);
    assert.ok(Date.now() - started < 1000);
    assert.equal(fixture.snapshot().traces, 0);
  } finally {
    socket.destroy();
    await fixture.close().catch(() => undefined);
  }
});

test("otlp fixture validates options endpoint and success headers", async () => {
  await assert.rejects(() => startOtlpFixture(Object.freeze({ maxRecords: 1, extra: 1 }) as never));
  const fixture = await startOtlpFixture();
  try {
    assert.throws(() => fixture.endpoint("bad" as never));
    const res = await post(fixture.endpoint("traces"), validTrace());
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.match(res.headers.get("content-type") ?? "", /^application\/json/u);
    assert.equal(await res.text(), "{}");
  } finally {
    await fixture.close();
  }
});
