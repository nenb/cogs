import assert from "node:assert/strict";
import { createServer, Socket } from "node:net";
import { test } from "node:test";
import { createLinuxKvmRelay, createLoopbackFunctionalRelay } from "../dev/launcher/kvm-relay.ts";

async function echoServer() {
  const server = createServer((socket) => socket.pipe(socket));
  await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const a = server.address();
  const port = typeof a === "object" && a ? a.port : 0;
  return { port, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
}
async function socketTo(port: number) {
  const s = new Socket();
  await new Promise<void>((resolve, reject) => s.connect(port, "127.0.0.1", resolve).once("error", reject));
  return s;
}
async function reservedClosedPort() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const a = server.address();
  const port = typeof a === "object" && a ? a.port : 0;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}
async function roundTrip(port: number, body = "ping") {
  const s = await socketTo(port);
  const chunks: Buffer[] = [];
  s.on("data", (c) => chunks.push(Buffer.from(c)));
  s.write(body);
  await new Promise((resolve) => setTimeout(resolve, 25));
  s.destroy();
  return Buffer.concat(chunks).toString("utf8");
}

test("kvm relay exposes exact linux-kvm factory without binding during unit tests", () => {
  const r = createLinuxKvmRelay();
  const s = r.snapshot();
  assert.equal(s.profile, "linux-kvm");
  assert.equal(s.bindHost, "192.0.2.1");
  assert.equal(s.bindPort, 18080);
  assert.equal(s.ready, false);
});

test("loopback functional relay denies no-target and unregistered switch", async () => {
  const r = createLoopbackFunctionalRelay();
  await r.start();
  try {
    assert.equal(r.snapshot().bindHost, "127.0.0.1");
    const s = await socketTo(r.snapshot().bindPort);
    await new Promise((resolve) => s.once("close", resolve));
    assert.equal(r.snapshot().deniedConnections, 1);
    await assert.rejects(() => r.switchTo(9), /launcher relay failed/);
  } finally {
    await r.close();
  }
});

test("loopback functional relay allows registered echo and metadata-only snapshot", async () => {
  const upstream = await echoServer();
  const r = createLoopbackFunctionalRelay();
  await r.start();
  try {
    r.registerTarget(upstream.port);
    await r.switchTo(upstream.port);
    assert.equal(await roundTrip(r.snapshot().bindPort, "hello"), "hello");
    const snap = r.snapshot();
    assert.equal(snap.activeTarget, upstream.port);
    assert.equal(JSON.stringify(snap).includes("hello"), false);
  } finally {
    await r.close();
    await upstream.close();
  }
});

test("switch and clear destroy active sockets and prove zero", async () => {
  const a = await echoServer();
  const b = await echoServer();
  const r = createLoopbackFunctionalRelay();
  await r.start();
  try {
    r.registerTarget(a.port);
    r.registerTarget(b.port);
    await r.switchTo(a.port);
    const s = await socketTo(r.snapshot().bindPort);
    await new Promise((resolve) => setTimeout(resolve, 20));
    await r.switchTo(b.port);
    assert.equal(s.destroyed, true);
    assert.equal(r.snapshot().activeSockets, 0);
    await r.clear();
    assert.equal(r.snapshot().activeTarget, null);
    r.registerTarget(a.port);
    await r.switchTo(a.port);
    const raw = await socketTo(r.snapshot().bindPort);
    await r.close();
    assert.equal(raw.destroyed, true);
    assert.equal(r.snapshot().activeSockets, 0);
    assert.deepEqual(r.snapshot().registeredTargets, []);
  } finally {
    await r.close();
    await a.close();
    await b.close();
  }
});

test("relay enforces target and active socket bounds", async () => {
  const upstream = await echoServer();
  const r = createLoopbackFunctionalRelay(0, 2);
  await r.start();
  try {
    r.registerTarget(upstream.port);
    for (let i = 0; i < 15; i++) r.registerTarget(1000 + i);
    assert.throws(() => r.registerTarget(2000), /launcher relay failed/);
    await r.switchTo(upstream.port);
    const s = await socketTo(r.snapshot().bindPort);
    await new Promise((resolve) => setTimeout(resolve, 20));
    const denied = await socketTo(r.snapshot().bindPort);
    await new Promise((resolve) => denied.once("close", resolve));
    const snap = r.snapshot();
    assert.equal(snap.deniedConnections, 1);
    assert.ok(snap.activeSockets <= snap.maxActiveSockets);
    s.destroy();
  } finally {
    await r.close();
    await upstream.close();
  }
});

test("target connect failure poisons and close remains idempotent", async () => {
  const r = createLoopbackFunctionalRelay();
  await r.start();
  const target = await reservedClosedPort();
  r.registerTarget(target);
  await r.switchTo(target);
  const s = await socketTo(r.snapshot().bindPort);
  await new Promise((resolve) => s.once("close", resolve));
  assert.equal(r.snapshot().poisoned, true);
  await assert.rejects(() => r.clear(), /launcher relay failed/);
  await r.close();
  await r.close();
  assert.equal(r.snapshot().closed, true);
  assert.equal(r.snapshot().activeTarget, null);
  assert.deepEqual(r.snapshot().registeredTargets, []);
});
