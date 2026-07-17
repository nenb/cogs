import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import { commandDescriptor, type RunnerSeams, runCommand } from "../dev/launcher/runner.ts";

function command(code: string, timeoutMs = 5_000) {
  return commandDescriptor({
    executable: process.execPath,
    args: ["-e", code],
    cwd: process.cwd(),
    env: { PATH: "/usr/bin:/bin" },
    timeoutMs,
    maxOutputBytes: 256,
    killGraceMs: 100,
  });
}

test("launcher runner uses fixed absolute argv, no shell, bounded output, and captures nonzero", async () => {
  assert.throws(() => commandDescriptor({ ...command(""), executable: "node" }));
  const flood = await runCommand(command('process.stdout.write("a".repeat(300)); process.exit(7)'));
  assert.equal(flood.status, "failed");
  assert.equal(flood.exitCode, 7);
  assert.equal(flood.stdout.length, 256);
  assert.equal(flood.stdoutTruncated, true);
});

test("launcher runner terminates hung process on deadline and abort", async () => {
  const timed = await runCommand(command("setInterval(()=>{},1000)", 100));
  assert.equal(timed.status, "timeout");
  const controller = new AbortController();
  const running = runCommand(command("setInterval(()=>{},1000)", 5_000), { signal: controller.signal });
  controller.abort();
  const aborted = await running;
  assert.equal(aborted.status, "aborted");
});

test("launcher runner snapshots command descriptors without invoking getters", () => {
  const hostileArgs = ["-e", ""];
  Object.defineProperty(hostileArgs, "1", {
    get() {
      throw new Error("SECRET getter");
    },
    enumerable: true,
  });
  assert.throws(() => commandDescriptor({ ...command(""), args: hostileArgs }));
  const hostileEnv = { PATH: "/usr/bin:/bin" };
  Object.defineProperty(hostileEnv, "SECRET", {
    get() {
      throw new Error("SECRET getter");
    },
    enumerable: true,
  });
  assert.throws(() => commandDescriptor({ ...command(""), env: hostileEnv }));
});

test("launcher runner rejects hostile option descriptors without invoking getters", async () => {
  let invoked = false;
  const withGetter = {};
  Object.defineProperty(withGetter, "signal", {
    get() {
      invoked = true;
      throw new Error("SECRET signal getter");
    },
    enumerable: true,
  });
  await assert.rejects(() => runCommand(command(""), withGetter as { signal?: AbortSignal; seams?: RunnerSeams }));
  assert.equal(invoked, false);

  const nonEnumerable = {};
  Object.defineProperty(nonEnumerable, "seams", { value: undefined, enumerable: false });
  await assert.rejects(() => runCommand(command(""), nonEnumerable as { signal?: AbortSignal; seams?: RunnerSeams }));
});

test("launcher runner handles spawn throw and validates frozen seams", async () => {
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => {
      throw new Error("SECRET raw spawn");
    }) as never),
    setTimer: Object.freeze((ms: number, cb: () => void) => setTimeout(cb, ms)),
    clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    kill: Object.freeze(() => true),
    identity: Object.freeze((pid: number) => String(pid)),
  });
  const result = await runCommand(command(""), { seams });
  assert.equal(result.status, "failed");
  assert.doesNotMatch(result.stderr, /SECRET/);
  await assert.rejects(() => runCommand(command(""), { seams: { ...seams } as RunnerSeams }));
});

test("launcher runner reports cleanup uncertainty when child never closes and kill fails", async () => {
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => {
      const events = new EventTarget();
      return {
        pid: 54321,
        stdout: new PassThrough(),
        stderr: new PassThrough(),
        once: (event: string, cb: (...args: never[]) => void) => {
          events.addEventListener(event, () => cb());
        },
      };
    }) as never),
    setTimer: Object.freeze((_ms: number, cb: () => void) => {
      queueMicrotask(cb);
      return {};
    }),
    clearTimer: Object.freeze(() => undefined),
    kill: Object.freeze(() => false),
    identity: Object.freeze((pid: number) => String(pid)),
  });
  const out = await runCommand(command("", 1), { seams });
  assert.equal(out.status, "timeout");
  assert.equal(out.cleanupUncertain, true);
});

test("launcher runner waits bounded when initial PID identity is absent", async () => {
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => ({
      pid: 54324,
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      once: () => undefined,
    })) as never),
    setTimer: Object.freeze((_ms: number, cb: () => void) => {
      queueMicrotask(cb);
      return {};
    }),
    clearTimer: Object.freeze(() => undefined),
    kill: Object.freeze(() => {
      throw new Error("must not kill without identity");
    }),
    identity: Object.freeze(() => null),
  });
  const out = await runCommand(command("", 1), { seams });
  assert.equal(out.status, "failed");
  assert.equal(out.cleanupUncertain, true);
});

test("launcher runner refuses PID identity changes before signaling", async () => {
  const kills: unknown[] = [];
  let identityCalls = 0;
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => ({
      pid: 54323,
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      once: () => undefined,
    })) as never),
    setTimer: Object.freeze((_ms: number, cb: () => void) => {
      queueMicrotask(cb);
      return {};
    }),
    clearTimer: Object.freeze(() => undefined),
    kill: Object.freeze((pid: number, signal: NodeJS.Signals) => {
      kills.push({ pid, signal });
      return true;
    }),
    identity: Object.freeze(() => {
      identityCalls += 1;
      return identityCalls === 1 ? "old" : "new";
    }),
  });
  const out = await runCommand(command("", 1), { seams });
  assert.equal(out.cleanupUncertain, true);
  assert.deepEqual(kills, []);
});

test("launcher runner treats hostile child getters as cleanup-uncertain failure", async () => {
  const child = {};
  Object.defineProperty(child, "pid", {
    get() {
      throw new Error("SECRET pid");
    },
    enumerable: true,
  });
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => child) as never),
    setTimer: Object.freeze((ms: number, cb: () => void) => setTimeout(cb, ms)),
    clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    kill: Object.freeze(() => true),
    identity: Object.freeze((pid: number) => String(pid)),
  });
  const out = await runCommand(command(""), { seams });
  assert.equal(out.status, "failed");
  assert.equal(out.cleanupUncertain, true);
});

test("launcher runner marks cleanup uncertain when successful close cannot clear timer", async () => {
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => {
      const child = new EventEmitter() as EventEmitter & { pid: number; stdout: PassThrough; stderr: PassThrough };
      child.pid = 54325;
      child.stdout = new PassThrough();
      child.stderr = new PassThrough();
      queueMicrotask(() => child.emit("close", 0, null));
      return child;
    }) as never),
    setTimer: Object.freeze(() => ({})),
    clearTimer: Object.freeze(() => {
      throw new Error("SECRET clear");
    }),
    kill: Object.freeze(() => true),
    identity: Object.freeze((pid: number) => String(pid)),
  });
  const out = await runCommand(command("", 1), { seams });
  assert.equal(out.status, "ok");
  assert.equal(out.cleanupUncertain, true);
});

test("launcher runner settles safely when hostile timer and kill seams throw", async () => {
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => ({
      pid: 54322,
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      once: () => undefined,
    })) as never),
    setTimer: Object.freeze(() => {
      throw new Error("SECRET timer");
    }),
    clearTimer: Object.freeze(() => {
      throw new Error("SECRET clear");
    }),
    kill: Object.freeze(() => {
      throw new Error("SECRET kill");
    }),
    identity: Object.freeze((pid: number) => String(pid)),
  });
  const out = await runCommand(command("", 1), { seams });
  assert.equal(out.status, "timeout");
  assert.equal(out.cleanupUncertain, true);
});

test("launcher runner bounds many tiny and empty stdout chunks", async () => {
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => {
      const child = new EventEmitter() as EventEmitter & { pid: number; stdout: EventEmitter; stderr: EventEmitter };
      child.pid = 54326;
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      queueMicrotask(() => {
        for (let index = 0; index < 1500; index += 1) child.stdout.emit("data", Buffer.alloc(0));
        for (let index = 0; index < 1500; index += 1) child.stdout.emit("data", Buffer.from("x"));
        child.emit("close", 0, null);
      });
      return child;
    }) as never),
    setTimer: Object.freeze((ms: number, cb: () => void) => setTimeout(cb, ms)),
    clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    kill: Object.freeze(() => true),
    identity: Object.freeze((pid: number) => String(pid)),
  });
  const out = await runCommand({ ...command(""), maxOutputBytes: 4096 }, { seams });
  assert.equal(out.status, "ok");
  assert.equal(out.stdout.length, 1024);
  assert.equal(out.stdoutTruncated, true);
});

test("launcher runner truncates oversized string chunks before retaining output", async () => {
  const seams: RunnerSeams = Object.freeze({
    spawn: Object.freeze((() => {
      const child = new EventEmitter() as EventEmitter & { pid: number; stdout: EventEmitter; stderr: EventEmitter };
      child.pid = 54327;
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      queueMicrotask(() => {
        child.stdout.emit("data", "z".repeat(10_000));
        child.emit("close", 0, null);
      });
      return child;
    }) as never),
    setTimer: Object.freeze((ms: number, cb: () => void) => setTimeout(cb, ms)),
    clearTimer: Object.freeze((timer: unknown) => clearTimeout(timer as NodeJS.Timeout)),
    kill: Object.freeze(() => true),
    identity: Object.freeze((pid: number) => String(pid)),
  });
  const out = await runCommand({ ...command(""), maxOutputBytes: 64 }, { seams });
  assert.equal(out.status, "ok");
  assert.equal(out.stdout, "z".repeat(64));
  assert.equal(out.stdoutTruncated, true);
});

test("launcher runner ignores stdin and works from explicit cwd", async () => {
  const dir = await mkdtemp(join(tmpdir(), "cogs-launcher-runner-"));
  try {
    const result = await runCommand({ ...command("process.stdout.write(process.cwd())"), cwd: dir });
    assert.equal(result.status, "ok");
    assert.equal(result.stdout, await realpath(dir));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
