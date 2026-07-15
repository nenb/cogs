import assert from "node:assert/strict";
import { SshConnectionManager } from "../../src/ssh/connection.ts";
import { createSftpFileToolPorts } from "../../src/ssh/file-tools.ts";

const [endpoint, clientKeyPath, hostKeySha256] = process.argv.slice(2);
if (!endpoint || !clientKeyPath || !hostKeySha256)
  throw new Error("usage: ssh-adapter-smoke.ts <endpoint> <client-key-path> <host-key-sha256>");
if (!/^127\.0\.0\.1:[0-9]{1,5}$/.test(endpoint)) throw new Error("smoke endpoint must be loopback host:port");
if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(hostKeySha256)) throw new Error("smoke host fingerprint must be OpenSSH SHA256");

function wrongPin(pin: string): string {
  const prefix = "SHA256:";
  const body = pin.slice(prefix.length);
  return `${prefix}${body[0] === "A" ? "B" : "A"}${body.slice(1)}`;
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
      sftpOpenTimeoutMs: 5000,
      shutdownTimeoutMs: 2000,
      maxPermits: 1,
      maxQueue: 4,
    },
  });
  await manager.start();
  return manager;
}

let manager: SshConnectionManager | undefined;
const smokePath = `/workspace/cogs-sftp-smoke-${process.pid}.txt`;
try {
  manager = await start(hostKeySha256);
  assert.equal(manager.ready, true, "correct OpenSSH host fingerprint must authenticate");
  const ports = createSftpFileToolPorts({
    manager,
    operationTimeoutMs: 5000,
    idleTimeoutMs: 5000,
    openTimeoutMs: 5000,
  });
  const writeResult = (await ports.write({ path: smokePath, content: "alpha\nbeta\ngamma\n" })) as {
    bytesWritten: number;
  };
  assert.equal(writeResult.bytesWritten, 17);
  const readResult = (await ports.read({ path: smokePath, offset: 1, limit: 1 })) as {
    content: string;
    truncated: boolean;
  };
  assert.equal(readResult.content, "beta");
  assert.equal(readResult.truncated, true);
  const editResult = (await ports.edit({ path: smokePath, oldText: "beta", newText: "BETA" })) as {
    occurrences: number;
  };
  assert.equal(editResult.occurrences, 1);
  const afterEdit = (await ports.read({ path: smokePath })) as { content: string };
  assert.equal(afterEdit.content, "alpha\nBETA\ngamma\n");
  await assert.rejects(ports.edit({ path: smokePath, oldText: "missing", newText: "x" }), /not unique/);
  const unchanged = (await ports.read({ path: smokePath })) as { content: string };
  assert.equal(unchanged.content, "alpha\nBETA\ngamma\n");
  await ports.write({ path: smokePath, content: "dup dup\n" });
  await assert.rejects(ports.edit({ path: smokePath, oldText: "dup", newText: "x" }), /not unique/);
  const duplicateUnchanged = (await ports.read({ path: smokePath })) as { content: string };
  assert.equal(duplicateUnchanged.content, "dup dup\n");
} finally {
  if (manager !== undefined) {
    let cleanupTimer: NodeJS.Timeout | undefined;
    try {
      await Promise.race([
        manager.withSftp({ operationTimeoutMs: 2000, closeTimeoutMs: 2000 }, async (port, signal) => {
          await port.unlink(smokePath, signal).catch(() => undefined);
        }),
        new Promise((resolve) => {
          cleanupTimer = setTimeout(resolve, 2500);
        }),
      ]).catch(() => undefined);
    } finally {
      if (cleanupTimer !== undefined) clearTimeout(cleanupTimer);
    }
    await manager.shutdown().catch(() => undefined);
  }
}

await assert.rejects(
  start(wrongPin(hostKeySha256)),
  /ssh start failed|ssh connection failed/,
  "wrong host pin must fail closed",
);
console.log(
  "production ssh/sftp adapter smoke passed: correct pin authenticated; read/write/edit worked; wrong pin failed closed",
);
