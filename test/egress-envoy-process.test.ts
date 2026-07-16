import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { test } from "node:test";
import {
  CogsEnvoyProcessError,
  type CogsEnvoyProcessPorts,
  createNodeCogsEnvoyProcessPort,
} from "../src/egress/envoy-process.ts";

const bootstrap = "/run/cogs/egress/envoy/bootstrap.json";
const raw = "raw leaked /run/cogs/egress/envoy/bootstrap.json stderr-secret callback-secret";
const generic = (error: unknown) => {
  assert.ok(error instanceof CogsEnvoyProcessError);
  assert.equal(error.code, "COGS_ENVOY_PROCESS_FAILED");
  assert.equal(error.message, "egress Envoy process unavailable");
  assert.equal(String(error.stack ?? "").includes(raw), false);
  assert.equal(String(error).includes("stderr-secret"), false);
  assert.equal(String(error).includes("callback-secret"), false);
  return true;
};

test("spawns exact Envoy argv/env and waits for TCP readiness", async () => {
  const ports = new FakePorts([false, true]);
  const port = createNodeCogsEnvoyProcessPort({
    executablePath: "/opt/cogs/envoy",
    startupTimeoutMs: 1000,
    closeTimeoutMs: 100,
    ports,
  });
  const handle = await port.start({ bootstrapPath: bootstrap, listenerPort: 15001, onCompletionLine: async () => {} });
  assert.equal(handle.ready, true);
  assert.equal(ports.spawned?.exe, "/opt/cogs/envoy");
  assert.deepEqual(ports.spawned?.argv, [
    "--config-path",
    bootstrap,
    "--mode",
    "serve",
    "--log-level",
    "warning",
    "--disable-hot-restart",
    "--concurrency",
    "1",
  ]);
  assert.deepEqual(ports.spawned?.request, {
    executablePath: "/opt/cogs/envoy",
    argv: ports.spawned?.argv,
    cwd: "/",
    detached: true,
    env: {},
    stdio: ["ignore", "pipe", "pipe"],
  });
  assert.deepEqual(ports.connects, [
    { port: 15001, host: "127.0.0.1" },
    { port: 15001, host: "127.0.0.1" },
  ]);
  await handle.close();
});

test("rejects timeout, abort, early exit, and invalid constructor/input generically", async () => {
  assert.throws(
    () => createNodeCogsEnvoyProcessPort({ executablePath: "envoy", startupTimeoutMs: 100, closeTimeoutMs: 100 }),
    generic,
  );

  const timeout = new FakePorts([]);
  const timeoutPort = createNodeCogsEnvoyProcessPort({
    executablePath: "/envoy",
    startupTimeoutMs: 50,
    closeTimeoutMs: 50,
    ports: timeout,
  });
  await assert.rejects(
    timeoutPort.start({ bootstrapPath: bootstrap, listenerPort: 1, onCompletionLine: async () => {} }),
    generic,
  );
  assert.deepEqual(timeout.kills, ["SIGTERM"]);

  const abort = new AbortController();
  abort.abort();
  await assert.rejects(
    timeoutPort.start({
      bootstrapPath: bootstrap,
      listenerPort: 1,
      signal: abort.signal,
      onCompletionLine: async () => {},
    }),
    generic,
  );

  const early = new FakePorts([]);
  early.afterSpawn = (child) => queueMicrotask(() => child.emitExitClose());
  await assert.rejects(
    createNodeCogsEnvoyProcessPort({
      executablePath: "/envoy",
      startupTimeoutMs: 300,
      closeTimeoutMs: 50,
      ports: early,
    }).start({
      bootstrapPath: bootstrap,
      listenerPort: 1,
      onCompletionLine: async () => {},
    }),
    generic,
  );
});

test("serializes strict UTF-8 stdout lines and poisons callback failure, oversized lines, malformed UTF-8, and overflow", async () => {
  const ports = new FakePorts([false, true]);
  const lines: string[] = [];
  const handle = await createNodeCogsEnvoyProcessPort({
    executablePath: "/envoy",
    startupTimeoutMs: 500,
    closeTimeoutMs: 50,
    ports,
  }).start({
    bootstrapPath: bootstrap,
    listenerPort: 2,
    onCompletionLine: async (line) => {
      lines.push(line);
    },
  });
  ports.child.stdout.emit("data", new Uint8Array([0xe2, 0x82]));
  ports.child.stdout.emit("data", new Uint8Array([0xac, 0x0a]));
  await tick();
  assert.deepEqual(lines, ["€"]);
  assert.equal(handle.ready, true);

  const badCallback = new FakePorts([false, true]);
  const badHandle = await createNodeCogsEnvoyProcessPort({
    executablePath: "/envoy",
    startupTimeoutMs: 500,
    closeTimeoutMs: 50,
    ports: badCallback,
  }).start({
    bootstrapPath: bootstrap,
    listenerPort: 2,
    onCompletionLine: async () => {
      throw new Error(raw);
    },
  });
  badCallback.child.stdout.emit("data", Buffer.from("x\n"));
  await tick();
  assert.equal(badHandle.ready, false);
  assert.deepEqual(badCallback.kills, ["SIGTERM"]);

  for (const chunk of [new Uint8Array([0xff]), Buffer.from(`${"x".repeat(4097)}\n`)]) {
    const fake = new FakePorts([false, true]);
    const poisoned = await createNodeCogsEnvoyProcessPort({
      executablePath: "/envoy",
      startupTimeoutMs: 500,
      closeTimeoutMs: 50,
      ports: fake,
    }).start({
      bootstrapPath: bootstrap,
      listenerPort: 2,
      onCompletionLine: async () => {},
    });
    fake.child.stdout.emit("data", chunk);
    await tick();
    assert.equal(poisoned.ready, false);
  }

  const overflow = new FakePorts([false, true]);
  let release!: () => void;
  await createNodeCogsEnvoyProcessPort({
    executablePath: "/envoy",
    startupTimeoutMs: 500,
    closeTimeoutMs: 50,
    ports: overflow,
  }).start({
    bootstrapPath: bootstrap,
    listenerPort: 2,
    onCompletionLine: () =>
      new Promise<void>((resolve) => {
        release = resolve;
      }),
  });
  overflow.child.stdout.emit("data", Buffer.from(`${"x\n".repeat(258)}`));
  await tick();
  assert.deepEqual(overflow.kills, ["SIGTERM"]);
  release();
});

test("default adapter nonexistent executable rejects generically without uncaught error", () => {
  const code = `
    import { createNodeCogsEnvoyProcessPort } from "./src/egress/envoy-process.ts";
    try {
      await createNodeCogsEnvoyProcessPort({ executablePath: "/definitely/not/cogs-envoy", startupTimeoutMs: 1000, closeTimeoutMs: 50 }).start({
        bootstrapPath: "${bootstrap}",
        listenerPort: 1,
        onCompletionLine: async () => {},
      });
      process.exit(2);
    } catch (error) {
      if (error?.code === "COGS_ENVOY_PROCESS_FAILED" && error?.message === "egress Envoy process unavailable") process.exit(0);
      process.exit(3);
    }
  `;
  const child = spawnSync(process.execPath, ["--import", "tsx", "--eval", code], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 5000,
  });
  assert.equal(child.status, 0, `${child.stdout}\n${child.stderr}`);
});

test("preflight, startup probes, aborts, and pid validation fail closed", async () => {
  for (const ports of [new FakePorts([true]), Object.assign(new FakePorts([false]), { failConnect: true })]) {
    await assert.rejects(
      createNodeCogsEnvoyProcessPort({
        executablePath: "/envoy",
        startupTimeoutMs: 100,
        closeTimeoutMs: 50,
        ports,
      }).start({
        bootstrapPath: bootstrap,
        listenerPort: 2,
        onCompletionLine: async () => {},
      }),
      generic,
    );
    assert.equal(ports.spawned, undefined);
  }

  const hung = new FakePorts([false]);
  hung.hangAfter = 1;
  await assert.rejects(
    createNodeCogsEnvoyProcessPort({
      executablePath: "/envoy",
      startupTimeoutMs: 50,
      closeTimeoutMs: 50,
      ports: hung,
    }).start({
      bootstrapPath: bootstrap,
      listenerPort: 2,
      onCompletionLine: async () => {},
    }),
    generic,
  );
  assert.deepEqual(hung.kills, ["SIGTERM"]);

  const midAbort = new AbortController();
  const abortPorts = new FakePorts([false]);
  abortPorts.afterSpawn = () => midAbort.abort();
  await assert.rejects(
    createNodeCogsEnvoyProcessPort({
      executablePath: "/envoy",
      startupTimeoutMs: 500,
      closeTimeoutMs: 50,
      ports: abortPorts,
    }).start({
      bootstrapPath: bootstrap,
      listenerPort: 2,
      signal: midAbort.signal,
      onCompletionLine: async () => {},
    }),
    generic,
  );
  assert.equal(abortPorts.connects.length, 1);

  const badPid = new FakePorts([false]);
  badPid.child.pid = 0;
  await assert.rejects(
    createNodeCogsEnvoyProcessPort({
      executablePath: "/envoy",
      startupTimeoutMs: 100,
      closeTimeoutMs: 50,
      ports: badPid,
    }).start({
      bootstrapPath: bootstrap,
      listenerPort: 2,
      onCompletionLine: async () => {},
    }),
    generic,
  );
});

test("stderr overflow and close-finalized stdout fragments fail closed", async () => {
  for (const emit of [
    (child: FakeChild) => child.stderr.emit("data", Buffer.alloc(65_537, "s")),
    (child: FakeChild) => child.stdout.emit("data", Buffer.from("partial")),
    (child: FakeChild) => child.stdout.emit("data", new Uint8Array([0xe2])),
  ]) {
    const ports = new FakePorts([false, true]);
    const handle = await createNodeCogsEnvoyProcessPort({
      executablePath: "/envoy",
      startupTimeoutMs: 500,
      closeTimeoutMs: 50,
      ports,
    }).start({
      bootstrapPath: bootstrap,
      listenerPort: 2,
      onCompletionLine: async () => {},
    });
    emit(ports.child);
    await assert.rejects(handle.close(), generic);
  }
});

test("intentional TERM delivers and awaits final stdout line", async () => {
  const ports = new FakePorts([false, true]);
  let release!: () => void;
  const lines: string[] = [];
  ports.killBehavior = () => {
    ports.child.stdout.emit("data", Buffer.from("final\n"));
    ports.exitClose();
  };
  const handle = await createNodeCogsEnvoyProcessPort({
    executablePath: "/envoy",
    startupTimeoutMs: 500,
    closeTimeoutMs: 50,
    ports,
  }).start({
    bootstrapPath: bootstrap,
    listenerPort: 2,
    onCompletionLine: (line) =>
      new Promise<void>((resolve) => {
        lines.push(line);
        release = () => {
          resolve();
        };
      }),
  });
  let closed = false;
  const closing = handle.close().then(() => {
    closed = true;
  });
  await tick();
  assert.deepEqual(lines, ["final"]);
  assert.equal(closed, false);
  release();
  await closing;
  assert.equal(closed, true);
});

test("unexpected death, double close, signal failures, and missing terminal events fail closed", async () => {
  const exited = new FakePorts([false, true]);
  const exitedHandle = await createNodeCogsEnvoyProcessPort({
    executablePath: "/envoy",
    startupTimeoutMs: 500,
    closeTimeoutMs: 50,
    ports: exited,
  }).start({
    bootstrapPath: bootstrap,
    listenerPort: 2,
    onCompletionLine: async () => {},
  });
  exited.child.emit("exit", 0, null);
  assert.equal(exitedHandle.ready, false);
  exited.child.emit("close", 0, null);
  await assert.rejects(exitedHandle.close(), generic);
  assert.deepEqual(exited.kills, ["SIGTERM"]);

  const escalated = new FakePorts([false, true]);
  escalated.killBehavior = (signal) => {
    if (signal === "SIGKILL") escalated.exitClose();
  };
  const handle = await createNodeCogsEnvoyProcessPort({
    executablePath: "/envoy",
    startupTimeoutMs: 500,
    closeTimeoutMs: 50,
    ports: escalated,
  }).start({
    bootstrapPath: bootstrap,
    listenerPort: 2,
    onCompletionLine: async () => {},
  });
  await Promise.all([handle.close(), handle.close()]);
  assert.deepEqual(escalated.kills, ["SIGTERM", "SIGKILL"]);

  for (const fault of ["term", "kill", "missing-exit", "missing-close"] as const) {
    const ports = new FakePorts([false, true]);
    ports.killBehavior = (signal) => {
      if (fault === "term" && signal === "SIGTERM") throw new Error(raw);
      if (fault === "kill" && signal === "SIGKILL") throw new Error(raw);
      if (fault === "missing-exit") ports.child.emit("close", 0, null);
      else if (fault === "missing-close") ports.child.emit("exit", 0, null);
      else if (signal === "SIGKILL") ports.exitClose();
    };
    const unhealthy = await createNodeCogsEnvoyProcessPort({
      executablePath: "/envoy",
      startupTimeoutMs: 500,
      closeTimeoutMs: 50,
      ports,
    }).start({
      bootstrapPath: bootstrap,
      listenerPort: 2,
      onCompletionLine: async () => {},
    });
    await assert.rejects(unhealthy.close(), generic);
  }
});

class FakeStream extends EventEmitter {
  public resume(): void {}
}

class FakeChild extends EventEmitter {
  public pid = 4321;
  public readonly stdout = new FakeStream();
  public readonly stderr = new FakeStream();
  public emitExitClose(): void {
    this.emit("exit", 0, null);
    this.emit("close", 0, null);
  }
}

class FakePorts implements CogsEnvoyProcessPorts {
  public readonly child = new FakeChild();
  public spawned?: { exe: string; argv: string[]; request: unknown };
  public connects: Array<{ port: number; host: string }> = [];
  public kills: string[] = [];
  public afterSpawn?: (child: FakeChild) => void;
  public killBehavior?: (signal: "SIGTERM" | "SIGKILL") => void;
  public failConnect = false;
  public hangAfter = Number.MAX_SAFE_INTEGER;

  public constructor(private readonly connectPlan: boolean[]) {}

  public spawn(request: { executablePath: string; argv: readonly string[] }): FakeChild {
    this.spawned = { exe: request.executablePath, argv: [...request.argv], request };
    this.afterSpawn?.(this.child);
    return this.child;
  }

  public connect(port: number, host: string, signal?: AbortSignal): Promise<"connected" | "refused"> {
    this.connects.push({ port, host });
    if (this.failConnect) return Promise.reject(new Error(raw));
    if (this.connects.length > this.hangAfter)
      return new Promise((_, reject) =>
        signal?.addEventListener("abort", () => reject(new Error(raw)), { once: true }),
      );
    return Promise.resolve(this.connectPlan.shift() === true ? "connected" : "refused");
  }

  public async kill(_processGroupId: number, signal: "SIGTERM" | "SIGKILL"): Promise<void> {
    this.kills.push(signal);
    this.killBehavior ? this.killBehavior(signal) : this.exitClose();
  }

  public setTimeout(callback: () => void, ms: number): ReturnType<typeof setTimeout> {
    return setTimeout(callback, ms);
  }

  public clearTimeout(timer: ReturnType<typeof setTimeout>): void {
    clearTimeout(timer);
  }

  public exitClose(): void {
    this.child.emitExitClose();
  }
}

function tick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}
