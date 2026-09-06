import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer, Socket } from "node:net";
import { test } from "node:test";
import {
  createLinuxKvmRelay,
  createLinuxKvmRelayForTests,
  createLoopbackFunctionalRelay,
  relayPeerMatches,
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

test("real linux-kvm relay rejects wildcard loopback listeners before bind", async () => {
  const original = Socket.prototype.connect;
  let probes = 0;
  try {
    Socket.prototype.connect = function patchedConnect(this: Socket, ..._args: unknown[]) {
      probes++;
      queueMicrotask(() => this.emit("connect"));
      return this;
    } as never;
    const r = createLinuxKvmRelay();
    r.configureProxyCapability(holder());
    await assert.rejects(() => r.start(), /launcher relay failed/);
    assert.equal(probes, 1);
    assert.equal(r.snapshot().closed, true);
    assert.equal(r.snapshot().ready, false);
  } finally {
    Socket.prototype.connect = original;
  }
});

test("real linux-kvm relay fails closed when wildcard probe errors ambiguously", async () => {
  const original = Socket.prototype.connect;
  let probes = 0;
  try {
    Socket.prototype.connect = function patchedConnect(this: Socket, ..._args: unknown[]) {
      probes++;
      const error = Object.assign(new Error("ambiguous"), { code: "EACCES" });
      queueMicrotask(() => this.emit("error", error));
      return this;
    } as never;
    const r = createLinuxKvmRelay();
    r.configureProxyCapability(holder());
    await assert.rejects(() => r.start(), /launcher relay failed/);
    assert.equal(probes, 1);
    assert.equal(r.snapshot().closed, true);
    assert.equal(r.snapshot().poisoned, true);
  } finally {
    Socket.prototype.connect = original;
  }
});

test("linux-kvm loopback test relay does not use wildcard preflight", async () => {
  const original = Socket.prototype.connect;
  try {
    Socket.prototype.connect = function patchedConnect(this: Socket, ..._args: unknown[]) {
      throw new Error("unexpected wildcard probe");
    } as never;
    const r = createLinuxKvmRelayForTests();
    r.configureProxyCapability(holder());
    await r.start();
    assert.equal(r.snapshot().bindHost, "127.0.0.1");
    Socket.prototype.connect = original;
    await r.close();
  } finally {
    Socket.prototype.connect = original;
  }
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

test("relay forwards existing proxy capability in fragmented CONNECT without fabrication", async () => {
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
    s.write(
      "Proxy-Authorization: Basic Y29nczphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==\r\nUser-Agent: curl\r\n\r\nbody",
    );
    assert.match(await readOnce(s), /200 Connection Established/u);
    assert.match(
      upstream.captured(),
      /\r\nProxy-Authorization: Basic Y29nczphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==\r\n/u,
    );
    assert.doesNotMatch(upstream.captured(), /Proxy-Authorization: (?:Bearer|abcdefghijklmnopqrstuvwxyz)/u);
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
      assert.equal(r.snapshot().poisoned, false);
      assert.equal(upstream.captured(), "");
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

const capabilityHeader = "Proxy-Authorization: Basic Y29nczphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NQ==\r\n";
const connectPrefix = "CONNECT localhost:3210 HTTP/1.1\r\nHost: localhost:3210\r\n";

function receiveBytes(socket: Socket, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error("test receive timeout"));
    }, 4000);
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("data", data);
    };
    const data = (chunk: Buffer) => {
      chunks.push(Buffer.from(chunk));
      size += chunk.length;
      if (size >= length) {
        cleanup();
        resolve(Buffer.concat(chunks));
      }
    };
    socket.on("data", data);
  });
}

test("missing/wrong/duplicate capability and bounded framing never poison a parallel healthy client", async () => {
  const upstream = await echoServer();
  const r = createLinuxKvmRelayForTests();
  r.configureProxyCapability(holder());
  await r.start();
  const healthy = await socketTo(r.snapshot().bindPort);
  try {
    r.registerTarget(upstream.port);
    await r.switchTo(upstream.port);
    // Connect after switching, which deliberately retires existing sockets.
    healthy.destroy();
    const good = await socketTo(r.snapshot().bindPort);
    try {
      const request = connectPrefix + capabilityHeader + "\r\n";
      const response = receiveBytes(good, request.length);
      good.write(request);
      assert.equal((await response).toString(), request);
      for (const bad of [
        connectPrefix + "\r\n",
        connectPrefix +
          "Proxy-Authorization: Basic " +
          Buffer.from("cogs:" + "z".repeat(32)).toString("base64") +
          "\r\n\r\n",
        connectPrefix + capabilityHeader + capabilityHeader + "\r\n",
        connectPrefix + capabilityHeader + "Content-Length: 1\r\n\r\nx",
        connectPrefix + capabilityHeader + "Transfer-Encoding: chunked\r\n\r\n",
        connectPrefix + capabilityHeader + "X-Large: " + "x".repeat(8192),
        connectPrefix, // absolute header deadline, not an idle timeout reset by chunks
      ]) {
        const client = await socketTo(r.snapshot().bindPort);
        let reflected = 0;
        client.on("data", (chunk) => {
          reflected += chunk.length;
        });
        const closed = new Promise<void>((resolve) => client.once("close", () => resolve()));
        client.on("error", () => {});
        client.write(bad);
        await closed;
        assert.equal(reflected, 0);
        assert.equal(r.snapshot().poisoned, false);
        const ping = receiveBytes(good, 4);
        good.write("ping");
        assert.equal((await ping).toString(), "ping");
      }
      const diagnostics = JSON.stringify(r.snapshot());
      assert.ok(!diagnostics.includes(capabilityHeader.trim()));
      assert.ok(!diagnostics.includes("abcdefghijklmnopqrstuvwxyz"));
    } finally {
      good.destroy();
    }
  } finally {
    healthy.destroy();
    await r.close();
    await upstream.close();
  }
});

test("peer binding rejects wrong source and local tuple; headers cannot supply interface identity", () => {
  const peer = { remoteAddress: "192.0.2.2", localAddress: "192.0.2.1", localPort: 18080 };
  assert.equal(relayPeerMatches(peer, "192.0.2.1", 18080), true);
  for (const remoteAddress of [undefined, "127.0.0.1", "192.0.2.3", "::ffff:192.0.2.2"]) {
    assert.equal(relayPeerMatches({ ...peer, remoteAddress }, "192.0.2.1", 18080), false);
  }
  assert.equal(relayPeerMatches({ ...peer, localPort: 18081 }, "192.0.2.1", 18080), false);
  assert.equal(relayPeerMatches({ ...peer, localAddress: "127.0.0.1" }, "192.0.2.1", 18080), false);
  const policy = execFileSync("bash", ["dev/linux-kvm/driver.sh", "print-network-policy"], { encoding: "utf8" });
  assert.match(policy, /-i cgfixture -s 192\.0\.2\.2 -d 192\.0\.2\.1 -p tcp --dport 18080 .*relay-allow -j ACCEPT/);
  assert.match(policy, /-I INPUT 1 -d 192\.0\.2\.1 -p tcp --dport 18080 -j CGFIXI/);
  assert.ok(policy.indexOf("relay-exclusion") < policy.indexOf("ESTABLISHED"));
  assert.doesNotMatch(policy, /ESTABLISHED,RELATED/);
});

test("authenticated stream survives receiver backpressure and close retires both sides", async () => {
  const upstream = await echoServer();
  const r = createLinuxKvmRelayForTests();
  r.configureProxyCapability(holder());
  await r.start();
  try {
    r.registerTarget(upstream.port);
    await r.switchTo(upstream.port);
    const s = await socketTo(r.snapshot().bindPort);
    const request = connectPrefix + capabilityHeader + "\r\n";
    const handshake = receiveBytes(s, request.length);
    s.write(request);
    await handshake;
    const payload = Buffer.alloc(1024 * 1024, 0x5a);
    s.pause();
    const received = receiveBytes(s, payload.length);
    s.write(payload);
    await new Promise((resolve) => setTimeout(resolve, 30));
    s.resume();
    assert.deepEqual(await received, payload);
    s.destroy();
    await r.close();
    assert.equal(r.snapshot().activeSockets, 0);
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
