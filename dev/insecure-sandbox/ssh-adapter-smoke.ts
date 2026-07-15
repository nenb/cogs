import assert from "node:assert/strict";
import { SshConnectionManager } from "../../src/ssh/connection.ts";

const [endpoint, clientKeyPath, hostKeySha256] = process.argv.slice(2);
if (!endpoint || !clientKeyPath || !hostKeySha256) {
  throw new Error("usage: ssh-adapter-smoke.ts <endpoint> <client-key-path> <host-key-sha256>");
}
if (!/^127\.0\.0\.1:[0-9]{1,5}$/.test(endpoint)) throw new Error("smoke endpoint must be loopback host:port");
if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(hostKeySha256)) throw new Error("smoke host fingerprint must be OpenSSH SHA256");

function wrongPin(pin: string): string {
  const prefix = "SHA256:";
  const body = pin.slice(prefix.length);
  const replacement = body[0] === "A" ? "B" : "A";
  return `${prefix}${replacement}${body.slice(1)}`;
}

async function start(pin: string): Promise<SshConnectionManager> {
  const manager = new SshConnectionManager({
    config: {
      endpoint,
      username: "root",
      hostKeySha256: pin,
      clientKeyPath,
      connectTimeoutMs: 5000,
      handshakeTimeoutMs: 5000,
      permitAcquireTimeoutMs: 1000,
      shutdownTimeoutMs: 2000,
      maxPermits: 1,
      maxQueue: 0,
    },
  });
  await manager.start();
  return manager;
}

const manager = await start(hostKeySha256);
assert.equal(manager.ready, true, "correct OpenSSH host fingerprint must authenticate");
await manager.shutdown();

await assert.rejects(
  start(wrongPin(hostKeySha256)),
  /ssh start failed|ssh connection failed/,
  "wrong host pin must fail closed",
);
console.log("production ssh adapter smoke passed: correct pin authenticated; wrong pin failed closed");
