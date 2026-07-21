import assert from "node:assert/strict";
import { createServer, Socket } from "node:net";
import { test } from "node:test";
import {
  createLinuxKvmRelay,
  createLinuxKvmRelayForTests,
  createLoopbackFunctionalRelay,
} from "../dev/launcher/kvm-relay.ts";

function holder(secret = "abcdefghijklmnopqrstuvwxyz012345"): {
  withSecret<T>(op: (secret: string) => T): T;
  dispose(): void;
} {
  return Object.freeze({
    withSecret: Object.freeze(<T>(op: (secret: string) => T) => op(secret)),
    dispose: Object.freeze(() => {}),
  });
}
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
async function readOnce(socket: Socket) {
  const chunks: Buffer[] = [];
  socket.on("data", (c) => chunks.push(Buffer.from(c)));
  await new Promise((resolve) => setTimeout(resolve, 50));
  return Buffer.concat(chunks).toString("latin1");
}
async function captureServer() {
  let captured = "";
  const server = createServer((socket) => {
    socket.once("data", (c) => {
      captured = c.toString("latin1");
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\nup");
    });
  });
  await new Promise<void>((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const a = server.address();
  const port = typeof a === "object" && a ? a.port : 0;
  return { port, captured: () => captured, close: () => new Promise<void>((resolve) => server.close(() => resolve())) };
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

test("relay injects callback-scoped proxy capability into fragmented CONNECT only", async () => {
  const upstream = await captureServer();
  const r = createLinuxKvmRelayForTests();
  r.configureProxyCapability(holder());
  await r.start();
  try {
    r.registerTarget(upstream.port);
    await r.switchTo(upstream.port);
    const s = await socketTo(r.snapshot().bindPort);
    s.write("CONNECT localhost:3210 HTTP/1.1\r\nHost: localhost:3210\r\n");
    await new Promise((resolve) => setTimeout(resolve, 10));
    s.write("User-Agent: curl\r\n\r\nbody");
    assert.match(await readOnce(s), /200 Connection Established/u);
    assert.match(upstream.captured(), /\r\nProxy-Authorization: abcdefghijklmnopqrstuvwxyz012345\r\n/u);
    assert.doesNotMatch(upstream.captured(), /Proxy-Authorization: Bearer/u);
    assert.equal((upstream.captured().match(/Proxy-Authorization/gu) ?? []).length, 1);
    assert.match(upstream.captured(), /\r\n\r\nbody$/u);
    assert.equal(JSON.stringify(r.snapshot()).includes("abcdefghijklmnopqrstuvwxyz"), false);
    s.destroy();
  } finally {
    await r.close();
    await upstream.close();
  }
});

test("relay rejects ambiguous proxy CONNECT without leaking capability", async () => {
  for (const bad of [
    "GET / HTTP/1.1\r\nHost: localhost:3210\r\n\r\n",
    "CONNECT localhost:3210 HTTP/1.1\r\nHost: localhost:3210\r\nProxy-Authorization: Bearer guest\r\n\r\n",
    "CONNECT localhost:3210 HTTP/1.1\r\nHost: localhost:3210\r\nHost: localhost:3210\r\n\r\n",
    "CONNECT localhost:3210 HTTP/1.1\nHost: localhost:3210\n\n",
  ]) {
    const upstream = await captureServer();
    const r = createLinuxKvmRelayForTests();
    r.configureProxyCapability(holder());
    await r.start();
    try {
      r.registerTarget(upstream.port);
      await r.switchTo(upstream.port);
      const s = await socketTo(r.snapshot().bindPort);
      s.end(bad);
      await new Promise((resolve) => s.once("close", resolve));
      assert.equal(r.snapshot().poisoned, true);
      assert.equal(upstream.captured().includes("abcdefghijklmnopqrstuvwxyz"), false);
    } finally {
      await r.close();
      await upstream.close();
    }
  }
});

test("relay fails closed when capability is disposed before handshake", async () => {
  let secret = "abcdefghijklmnopqrstuvwxyz012345";
  const h = Object.freeze({
    withSecret: Object.freeze(<T>(op: (secret: string) => T) => op(secret)),
    dispose: Object.freeze(() => {
      secret = "";
    }),
  });
  const upstream = await captureServer();
  const r = createLinuxKvmRelayForTests();
  r.configureProxyCapability(h);
  await r.start();
  try {
    r.registerTarget(upstream.port);
    await r.switchTo(upstream.port);
    h.dispose();
    const s = await socketTo(r.snapshot().bindPort);
    s.end("CONNECT localhost:3210 HTTP/1.1\r\nHost: localhost:3210\r\n\r\n");
    await new Promise((resolve) => s.once("close", resolve));
    assert.equal(r.snapshot().poisoned, true);
    assert.equal(upstream.captured(), "");
  } finally {
    await r.close();
    await upstream.close();
  }
});

test("relay rejects loopback proxy configuration, missing linux holder, and hostile holders", async () => {
  assert.throws(() => createLoopbackFunctionalRelay().configureProxyCapability(holder()), /launcher relay failed/);
  await assert.rejects(() => createLinuxKvmRelayForTests().start(), /launcher relay failed/);
  assert.throws(
    () =>
      createLinuxKvmRelayForTests().configureProxyCapability(
        Object.freeze({ withSecret: () => "x", dispose: () => {} }) as never,
      ),
    /launcher relay failed/,
  );
  assert.throws(
    () =>
      createLinuxKvmRelayForTests().configureProxyCapability(
        Object.freeze({
          withSecret: (op: (secret: string) => symbol) => {
            op("abcdefghijklmnopqrstuvwxyz012345");
            return op("abcdefghijklmnopqrstuvwxyz012345");
          },
          dispose: () => undefined,
        }) as never,
      ),
    /launcher relay failed/,
  );
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

test("relay cooperative preabort and abort during start leave no listener", async () => {
  const pre = createLoopbackFunctionalRelay();
  const preController = new AbortController();
  preController.abort();
  await assert.rejects(() => pre.start({ signal: preController.signal }), /launcher relay failed/);
  assert.equal(pre.snapshot().closed, true);

  const r = createLoopbackFunctionalRelay();
  const controller = new AbortController();
  const starting = r.start({ signal: controller.signal });
  controller.abort();
  await assert.rejects(starting, /launcher relay failed/);
  const port = r.snapshot().bindPort;
  assert.equal(r.snapshot().closed, true);
  if (port > 0) await assert.rejects(() => socketTo(port));
});

test("relay close is idempotent under raw sockets and expired deadline still cleans", async () => {
  const upstream = await echoServer();
  const r = createLoopbackFunctionalRelay();
  await r.start();
  try {
    r.registerTarget(upstream.port);
    await r.switchTo(upstream.port);
    const raw = await socketTo(r.snapshot().bindPort);
    const first = r.close({ deadlineAt: Date.now() - 1 });
    assert.equal(r.close(), first);
    await first;
    assert.equal(raw.destroyed, true);
    assert.equal(r.snapshot().activeSockets, 0);
    await assert.rejects(() => socketTo(r.snapshot().bindPort));
  } finally {
    await upstream.close();
  }
});

test("relay rejects hostile cooperative option bags without getters", async () => {
  const r = createLoopbackFunctionalRelay();
  let invoked = false;
  assert.throws(
    () =>
      r.close(
        Object.defineProperty({}, "deadlineAt", {
          enumerable: true,
          get: () => {
            invoked = true;
            return Date.now();
          },
        }) as never,
      ),
    /launcher relay failed/,
  );
  assert.equal(invoked, false);
  await r.close();
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
