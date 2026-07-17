import assert from "node:assert/strict";
import { createServer, Socket } from "node:net";
import { test } from "node:test";
import { createKvmStage3RuntimeRelay, Stage3RuntimeRelay } from "./egress-conformance/stage3-real-runtime/relay.ts";

test("stage3 relay only switches to registered loopback targets and clears sockets", async () => {
  const targetA = await echoServer("A");
  const targetB = await echoServer("B");
  const relay = new Stage3RuntimeRelay("127.0.0.1", await reservePort());
  await relay.start();
  try {
    assert.throws(() => relay.switchTo(targetA.port));
    relay.registerTarget(targetA.port);
    relay.registerTarget(targetB.port);
    relay.switchTo(targetA.port);
    assert.equal(await roundTrip(relay.snapshot().bindPort, "x"), "Ax");
    const hanging = new Socket();
    await new Promise<void>((resolve) => hanging.connect(relay.snapshot().bindPort, "127.0.0.1", resolve));
    relay.switchTo(targetB.port);
    assert.equal(await roundTrip(relay.snapshot().bindPort, "y"), "By");
    hanging.destroy();
    relay.clear();
    await assert.rejects(roundTrip(relay.snapshot().bindPort, "z"));
    const closed = await relay.close();
    assert.equal(closed.closed, true);
    await assert.rejects(roundTrip(relay.snapshot().bindPort, "after"));
  } finally {
    await relay.close().catch(() => undefined);
    await Promise.all([targetA.close(), targetB.close()]);
  }
});

test("stage3 relay denies no-target and saturated connections and closes idempotently", async () => {
  const target = await hangingServer();
  const relay = new Stage3RuntimeRelay("127.0.0.1", await reservePort(), 2);
  await relay.start();
  try {
    await assert.rejects(roundTrip(relay.snapshot().bindPort, "no-target"));
    relay.registerTarget(target.port);
    relay.switchTo(target.port);
    const held = new Socket();
    await new Promise<void>((resolve) => held.connect(relay.snapshot().bindPort, "127.0.0.1", resolve));
    await assert.rejects(roundTrip(relay.snapshot().bindPort, "saturated"));
    const saturated = relay.snapshot();
    assert.equal(saturated.deniedConnections >= 2, true);
    assert.equal(saturated.activeSockets <= saturated.maxActiveSockets, true);
    held.destroy();
    relay.clear();
    const first = await relay.close();
    const second = await relay.close();
    assert.deepEqual(second, first);
  } finally {
    await relay.close().catch(() => undefined);
    await target.close();
  }
});

test("stage3 relay poisons readiness when listen fails", async () => {
  const port = await reservePort();
  const blocker = createServer();
  await new Promise<void>((resolve, reject) => {
    blocker.once("error", reject);
    blocker.listen(port, "127.0.0.1", resolve);
  });
  const relay = new Stage3RuntimeRelay("127.0.0.1", port);
  await assert.rejects(relay.start());
  assert.equal(relay.snapshot().poisoned, true);
  assert.equal(relay.snapshot().ready, false);
  await new Promise<void>((resolve) => blocker.close(() => resolve()));
  await relay.close().catch(() => undefined);
});

test("stage3 relay validates hostile binds, targets, and exposes exact KVM factory identity", async () => {
  assert.throws(() => new Stage3RuntimeRelay("0.0.0.0", 18080));
  assert.throws(() => new Stage3RuntimeRelay("192.0.2.2", 18080));
  assert.throws(() => new Stage3RuntimeRelay("127.0.0.1", 0));
  assert.throws(() => new Stage3RuntimeRelay("127.0.0.1", 18080, 1));
  const relay = createKvmStage3RuntimeRelay();
  assert.deepEqual(relay.snapshot(), {
    bindHost: "192.0.2.1",
    bindPort: 18080,
    activeTarget: null,
    registeredTargets: [],
    acceptedConnections: 0,
    deniedConnections: 0,
    switchedTargets: 0,
    activeSockets: 0,
    maxActiveSockets: 32,
    ready: false,
    poisoned: false,
    closed: false,
  });
  assert.throws(() => relay.registerTarget(0));
  assert.throws(() => relay.registerTarget(65536));
  await relay.close();
});

async function hangingServer(): Promise<{ port: number; close(): Promise<void> }> {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address !== "string");
  return {
    port: address.port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

async function echoServer(prefix: string): Promise<{ port: number; close(): Promise<void> }> {
  const server = createServer((socket) => {
    socket.once("data", (chunk) => {
      socket.end(`${prefix}${chunk.toString("utf8")}`);
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address !== "string");
  return {
    port: address.port,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address !== null && typeof address !== "string");
  const port = address.port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

async function roundTrip(port: number, value: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const socket = new Socket();
    let data = "";
    socket.setTimeout(1000, () => {
      socket.destroy();
      reject(new Error("timeout"));
    });
    socket.once("error", reject);
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
    });
    socket.once("end", () => (data === "" ? reject(new Error("empty")) : resolve(data)));
    socket.connect(port, "127.0.0.1", () => socket.write(value));
  });
}
