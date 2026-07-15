import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import ssh2 from "ssh2";
import { buildRemoteBashCommandForTest, createSshBashToolPort } from "../src/ssh/bash-tool.ts";
import {
  type CogsExecPort,
  type CogsExecTerminal,
  SshConnectionManager,
  type SshExecChannel,
  type SshSftpChannel,
  type SshTransport,
  type SshTransportConnection,
  type SshTransportConnectOptions,
} from "../src/ssh/connection.ts";

const keyPair = ssh2.utils.generateKeyPairSync("ed25519", { comment: "cogs-bash-test" });
const validPin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

class FakeExecPort implements CogsExecPort {
  public stdout = new Set<(chunk: Buffer) => void>();
  public stderr = new Set<(chunk: Buffer) => void>();
  public signals: string[] = [];
  public signalFailure: "TERM" | "INT" | undefined;
  #resolve!: (terminal: CogsExecTerminal) => void;
  #reject!: (error: Error) => void;
  #terminal = new Promise<CogsExecTerminal>((resolve, reject) => {
    this.#resolve = resolve;
    this.#reject = reject;
  });
  public onStdout(listener: (chunk: Buffer) => void): void {
    this.stdout.add(listener);
  }
  public onStderr(listener: (chunk: Buffer) => void): void {
    this.stderr.add(listener);
  }
  public terminal(): Promise<CogsExecTerminal> {
    return this.#terminal;
  }
  public signal(name: "TERM" | "INT"): Promise<void> {
    this.signals.push(name);
    return name === this.signalFailure ? Promise.reject(new Error("signal failed")) : Promise.resolve();
  }
  public emitStdout(chunk: Buffer | string): void {
    for (const listener of this.stdout) listener(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  public emitStderr(chunk: Buffer | string): void {
    for (const listener of this.stderr) listener(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  public exit(code: number): void {
    this.#resolve({ code, signal: null });
  }
  public signaled(signal: string): void {
    this.#resolve({ code: null, signal });
  }
  public fail(): void {
    this.#reject(new Error("exec channel failed"));
  }
}

class FakeExecChannel implements SshExecChannel {
  public readonly port = new FakeExecPort();
  public closeCalls = 0;
  public destroyCalls = 0;
  public close(): Promise<void> {
    this.closeCalls += 1;
    return Promise.resolve();
  }
  public destroy(): void {
    this.destroyCalls += 1;
    this.port.fail();
  }
}

class FakeConnection extends EventEmitter implements SshTransportConnection {
  public commands: string[] = [];
  public readonly channels: FakeExecChannel[] = [];
  public openSignals: AbortSignal[] = [];
  public constructor(private readonly openDelayMs = 0) {
    super();
  }
  public openSftp(): Promise<SshSftpChannel> {
    return Promise.reject(new Error("sftp not implemented in bash tests"));
  }
  public openExec(command: string, signal: AbortSignal): Promise<SshExecChannel> {
    this.commands.push(command);
    this.openSignals.push(signal);
    const channel = new FakeExecChannel();
    this.channels.push(channel);
    if (this.openDelayMs === 0) return Promise.resolve(channel);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => resolve(channel), this.openDelayMs);
      signal.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          reject(new Error("open aborted"));
        },
        { once: true },
      );
    });
  }
  public close(): Promise<void> {
    return Promise.resolve();
  }
  public destroy(): void {
    this.emit("close");
  }
}

class FakeTransport implements SshTransport {
  public readonly connection: FakeConnection;
  public constructor(openDelayMs = 0) {
    this.connection = new FakeConnection(openDelayMs);
  }
  public connect(_options: SshTransportConnectOptions): Promise<SshTransportConnection> {
    return Promise.resolve(this.connection);
  }
}

async function keyFile(root: string): Promise<string> {
  const path = resolve(root, "id_key");
  await writeFile(path, keyPair.private, { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

async function waitForChannel(transport: FakeTransport): Promise<FakeExecChannel> {
  for (let i = 0; i < 50; i++) {
    const channel = transport.connection.channels[0];
    if (channel !== undefined) return channel;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  throw new Error("missing exec channel");
}

async function started(openDelayMs = 0): Promise<{ manager: SshConnectionManager; transport: FakeTransport }> {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-bash-test-"));
  const transport = new FakeTransport(openDelayMs);
  const manager = new SshConnectionManager({
    config: {
      endpoint: "sandbox.local:2222",
      username: "cogs",
      hostKeySha256: validPin,
      clientKeyPath: await keyFile(root),
      connectTimeoutMs: 25,
      handshakeTimeoutMs: 25,
      permitAcquireTimeoutMs: 25,
      execOpenTimeoutMs: 25,
      shutdownTimeoutMs: 25,
      maxPermits: 1,
      maxQueue: 2,
    },
    transport,
  });
  await manager.start();
  return { manager, transport };
}

test("bash wrapper stays outside child group and command validation rejects lossy text", async () => {
  const command = buildRemoteBashCommandForTest("printf '%s\\n' \"a'b\"");
  assert.match(command, /^cd \/workspace && exec \/bin\/bash --noprofile --norc -c /);
  assert.match(command, /setsid --wait \/bin\/bash --noprofile --norc -c "\$1" &/);
  assert.match(command, /child=\$!/);
  assert.doesNotMatch(command, /^cd \/workspace && exec setsid /);
  assert.match(command, /kill -TERM -"\$child"/);
  assert.match(command, /kill -KILL -"\$child"/);

  const { manager } = await started();
  const ports = createSshBashToolPort({ manager });
  await assert.rejects(ports.bash({ command: "bad\0cmd" }), /invalid command/);
  await assert.rejects(ports.bash({ command: "\uD800" }), /invalid command/);
});

test("bash returns separated bounded output, nonzero status, and full update results", async () => {
  const { manager, transport } = await started();
  const updates: unknown[] = [];
  const ports = createSshBashToolPort({ manager, maxStreamBytes: 5, maxUpdates: 8 });
  const running = ports.bash({
    command: "printf hello",
    onUpdate: (update) => {
      updates.push(update);
    },
  });
  const channel = await waitForChannel(transport);
  channel.port.emitStdout(Buffer.from("he"));
  channel.port.emitStdout(Buffer.from([0xc3]));
  channel.port.emitStdout(Buffer.from([0xa9, 0x21, 0x21, 0x21]));
  channel.port.emitStderr(Buffer.from([0xff, 0x41]));
  channel.port.exit(7);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.ok, false);
  assert.equal(result.stdout, "heé!");
  assert.equal(result.stdoutTruncated, true);
  assert.equal(result.stderrLossyUtf8, true);
  assert.equal(result.exitCode, 7);
  assert.ok(
    updates.every((entry) => typeof entry === "object" && entry !== null && "content" in entry && "details" in entry),
  );
  assert.match(transport.connection.commands[0] ?? "", /\/workspace/);
});

test("bash total timeout cancels confirmed command without poisoning readiness", async () => {
  const { manager, transport } = await started();
  const ports = createSshBashToolPort({ manager, timeoutMs: 10, idleTimeoutMs: 100, cancelGraceMs: 20 });
  const running = ports.bash({ command: "sleep 99" });
  const channel = await waitForChannel(transport);
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.deepEqual(channel.port.signals, ["TERM"]);
  channel.port.exit(143);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.ok, false);
  assert.equal(result.timedOut, true);
  assert.equal(result.cancelled, false);
  assert.equal(manager.ready, true);
});

test("bash publisher failure cancels command and poisons SSH readiness", async () => {
  const { manager, transport } = await started();
  const ports = createSshBashToolPort({ manager, updateTimeoutMs: 10, cancelGraceMs: 20 });
  const running = ports.bash({ command: "printf x", onUpdate: () => Promise.reject(new Error("nope")) });
  const channel = await waitForChannel(transport);
  channel.port.emitStdout("x");
  await new Promise((resolve) => setTimeout(resolve, 5));
  channel.port.exit(143);
  await assert.rejects(running, /bash update failed/);
  assert.equal(manager.ready, false);
});

test("bash hard timeout aborts acquire/open before channel starts", async () => {
  const { manager, transport } = await started(50);
  const ports = createSshBashToolPort({ manager, timeoutMs: 5, idleTimeoutMs: 100 });
  await assert.rejects(ports.bash({ command: "printf late" }), /ssh exec operation failed|ssh exec open aborted/);
  assert.equal(transport.connection.openSignals[0]?.aborted, true);
});

test("bash caller abort before open cancels promptly and confirmed caller abort is structured", async () => {
  const pre = new AbortController();
  pre.abort();
  const delayed = await started(50);
  const delayedPorts = createSshBashToolPort({ manager: delayed.manager, timeoutMs: 100, idleTimeoutMs: 100 });
  await assert.rejects(
    delayedPorts.bash({ command: "printf never", signal: pre.signal }),
    /ssh operation aborted|ssh exec operation failed|ssh exec open aborted/,
  );
  assert.equal(delayed.transport.connection.openSignals.length, 0);

  const { manager, transport } = await started();
  const controller = new AbortController();
  const ports = createSshBashToolPort({ manager, timeoutMs: 1000, idleTimeoutMs: 1000, cancelGraceMs: 20 });
  const running = ports.bash({ command: "sleep 99", signal: controller.signal });
  const channel = await waitForChannel(transport);
  controller.abort();
  await new Promise((resolve) => setTimeout(resolve, 5));
  channel.port.exit(143);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.cancelled, true);
  assert.equal(result.timedOut, false);
  assert.equal(manager.ready, true);
});

test("bash cancellation signal failures and unconfirmed escalation poison readiness", async () => {
  const term = await started();
  const termPorts = createSshBashToolPort({
    manager: term.manager,
    timeoutMs: 10,
    idleTimeoutMs: 100,
    cancelGraceMs: 20,
  });
  const termRun = termPorts.bash({ command: "sleep 99" });
  const termChannel = await waitForChannel(term.transport);
  termChannel.port.signalFailure = "TERM";
  await assert.rejects(termRun, /exec cancellation signal failed/);
  assert.equal(term.manager.ready, false);

  const escalation = await started();
  const ports = createSshBashToolPort({
    manager: escalation.manager,
    timeoutMs: 10,
    idleTimeoutMs: 100,
    cancelGraceMs: 5,
  });
  const escalationRun = ports.bash({ command: "sleep 99" });
  const escalationChannel = await waitForChannel(escalation.transport);
  await assert.rejects(escalationRun, /deadline/);
  assert.deepEqual(escalationChannel.port.signals, ["TERM", "INT"]);
  assert.equal(escalation.manager.ready, false);
});

test("bash update overflow drops without poisoning while callback hang/reject poisons", async () => {
  const burst = await started();
  const updates: unknown[] = [];
  const ports = createSshBashToolPort({ manager: burst.manager, maxUpdates: 1, maxUpdateBytes: 1024 });
  const running = ports.bash({
    command: "printf burst",
    onUpdate: (update) => {
      updates.push(update);
    },
  });
  const channel = await waitForChannel(burst.transport);
  channel.port.emitStdout("a");
  channel.port.emitStdout("b");
  channel.port.exit(0);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.ok, true);
  assert.equal(result.updateDropped, 1);
  assert.equal(burst.manager.ready, true);

  const hung = await started();
  const hungPorts = createSshBashToolPort({ manager: hung.manager, updateTimeoutMs: 5, cancelGraceMs: 5 });
  let hungCalls = 0;
  const hungRun = hungPorts.bash({
    command: "printf x",
    onUpdate: () => {
      hungCalls += 1;
      return new Promise(() => undefined);
    },
  });
  const hungChannel = await waitForChannel(hung.transport);
  hungChannel.port.emitStdout("x");
  hungChannel.port.emitStdout("y");
  await new Promise((resolve) => setTimeout(resolve, 10));
  hungChannel.port.exit(143);
  await assert.rejects(hungRun, /bash update failed/);
  assert.equal(hung.manager.ready, false);
  assert.equal(hungCalls, 1);
});

test("bash idle timeout returns ok false after confirmed cancellation", async () => {
  const { manager, transport } = await started();
  const ports = createSshBashToolPort({ manager, timeoutMs: 1000, idleTimeoutMs: 5, cancelGraceMs: 20 });
  const running = ports.bash({ command: "sleep idle" });
  const channel = await waitForChannel(transport);
  await new Promise((resolve) => setTimeout(resolve, 10));
  channel.port.exit(0);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.ok, false);
  assert.equal(result.idleTimedOut, true);
  assert.equal(manager.ready, true);
});

test("bash signaled terminal returns structured result and revokes readiness", async () => {
  const signaled = await started();
  const ports = createSshBashToolPort({ manager: signaled.manager });
  const running = ports.bash({ command: "kill -TERM $$" });
  const channel = await waitForChannel(signaled.transport);
  channel.port.signaled("SIGTERM");
  const signaledResult = (await running) as Record<string, unknown>;
  assert.equal(signaledResult.ok, false);
  assert.equal(signaledResult.signal, "SIGTERM");
  assert.equal(signaled.manager.ready, false);
});

test("bash terminal rejection fails closed", async () => {
  const malformed = await started();
  const bad = createSshBashToolPort({ manager: malformed.manager });
  const badRun = bad.bash({ command: "printf bad" });
  const badChannel = await waitForChannel(malformed.transport);
  badChannel.port.fail();
  await assert.rejects(badRun, /exec channel failed/);
  assert.equal(malformed.manager.ready, false);
});

test("bash result is bounded for JSON-heavy output", async () => {
  const { manager, transport } = await started();
  const ports = createSshBashToolPort({ manager, maxStreamBytes: 16_000, maxResultBytes: 4096 });
  const running = ports.bash({ command: "printf json" });
  const channel = await waitForChannel(transport);
  channel.port.emitStdout('"\\'.repeat(8000));
  channel.port.exit(0);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.ok, true);
  assert.equal(result.stdoutTruncated, true);
  assert.ok(Buffer.byteLength(JSON.stringify(result), "utf8") <= 4096);
});

test("bash distinguishes valid replacement char, invalid UTF-8, ANSI/C0 updates, and astral truncation", async () => {
  const { manager, transport } = await started();
  const updates: unknown[] = [];
  const ports = createSshBashToolPort({ manager, maxStreamBytes: 40, maxResultBytes: 1400 });
  const running = ports.bash({
    command: "printf utf",
    onUpdate: (update) => {
      updates.push(update);
    },
  });
  const channel = await waitForChannel(transport);
  channel.port.emitStdout(Buffer.from("ok � "));
  channel.port.emitStdout(Buffer.from([0xc3]));
  channel.port.emitStdout(Buffer.from([0xa9]));
  channel.port.emitStdout(Buffer.from([0xff, 0x1b, 0x5b, 0x33, 0x31, 0x6d, 0x00]));
  channel.port.emitStdout("😀".repeat(200));
  channel.port.exit(0);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.stdoutLossyUtf8, true);
  assert.equal(result.stdoutTruncated, true);
  assert.doesNotMatch(result.stdout as string, /\uD800|\uDFFF/);
  const typedUpdates = updates as Array<{ content: [{ text: string }]; details: { lossyUtf8?: boolean } }>;
  const payloads = typedUpdates.flatMap((entry) => entry.content.map((part) => part.text));
  assert.equal(typedUpdates[0]?.details.lossyUtf8, false, "valid literal U+FFFD must not mark update lossy");
  assert.ok(
    payloads.some((text) => JSON.parse(text).chunk === "é"),
    "split valid UTF-8 should publish one é update",
  );
  assert.ok(
    typedUpdates.some((entry) => entry.details.lossyUtf8 === true),
    "invalid UTF-8 must mark update lossy",
  );
  assert.ok(payloads.some((text) => text.includes("\\u001b") || text.includes("\\u0000")));
});

test("bash exec manager waits for terminal after early operation and ignores hostile result getters", async () => {
  const { manager, transport } = await started();
  let firstReturned = false;
  const hostileResult = Object.defineProperty({ ok: true }, "signal", {
    get() {
      throw new Error("result getter must not be inspected");
    },
  });
  const first = manager.withBashExec({ wrappedCommand: "fixed-one", operationTimeoutMs: 1000 }, async () => {
    firstReturned = true;
    return hostileResult;
  });
  const firstChannel = await waitForChannel(transport);
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(firstReturned, true);
  assert.equal(transport.connection.channels.length, 1, "first permit must remain held while manager waits terminal");

  const second = manager.withBashExec({ wrappedCommand: "fixed-two", operationTimeoutMs: 1000 }, async (port) => {
    const terminal = port.terminal();
    (transport.connection.channels[1]?.port ?? firstChannel.port).exit(0);
    await terminal;
    return { ok: true };
  });
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(transport.connection.channels.length, 1, "queued exec must not open while first terminal is pending");
  firstChannel.port.exit(0);
  assert.equal(await first, hostileResult);
  await waitForChannel(transport);
  await second;
  assert.equal(manager.ready, true);
});

test("bash sink handles many tiny chunks with raw drop invariants", async () => {
  const { manager, transport } = await started();
  const ports = createSshBashToolPort({ manager, maxStreamBytes: 1024, maxUpdates: 1 });
  const running = ports.bash({ command: "many" });
  const channel = await waitForChannel(transport);
  for (let i = 0; i < 5000; i++) channel.port.emitStdout("a");
  channel.port.exit(0);
  const result = (await running) as Record<string, unknown>;
  assert.equal(result.stdoutBytes, 5000);
  assert.equal(result.stdoutDroppedBytes, 3976);
  assert.ok((result.stdoutDroppedBytes as number) <= (result.stdoutBytes as number));
  assert.equal((result.stdout as string).length, 1024);
});
