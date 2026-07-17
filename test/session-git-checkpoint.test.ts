import { strict as assert } from "node:assert";
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import {
  type CogsGitCheckpointCommandPort,
  type CogsGitCheckpointSftpPort,
  checkpointEvent,
  checkpointRecord,
  createGitCheckpointer,
} from "../src/session/git-checkpoint.ts";
import { CogsSftpStatusError } from "../src/ssh/connection.ts";

const execFileAsync = promisify(execFile);

const head = "a".repeat(40);
const blob = "b".repeat(40);
const tree = "c".repeat(40);
const commit = "d".repeat(40);

function ok(stdout = ""): unknown {
  return Object.freeze({ code: 0, signal: null, stdout: Buffer.from(stdout), stderrBytes: 0 });
}

function commandPort(commands: string[]): CogsGitCheckpointCommandPort {
  return Object.freeze({
    run: async ({ command }: { command: string }) => {
      commands.push(command);
      if (command.includes("status --porcelain")) return ok("?? a.txt\0 D gone.txt\0");
      if (command.includes("read-tree ")) return ok();
      if (command.includes(" add -A --")) return ok();
      if (command.includes("diff --cached --raw"))
        return ok(
          `:000000 100644 ${"0".repeat(40)} ${blob} A\0a.txt\0:100644 000000 ${blob} ${"0".repeat(40)} D\0gone.txt\0`,
        );
      if (command.includes("cat-file --batch-check")) return ok(`${blob} blob 5\n`);
      if (command.includes("write-tree")) return ok(`${tree}\n`);
      if (command.includes("commit-tree")) return ok(`${commit}\n`);
      if (command.includes("update-ref")) return ok();
      throw new Error(`unexpected command ${command}`);
    },
  });
}

function sftpPort(unlinked: string[] = []): CogsGitCheckpointSftpPort {
  return Object.freeze({
    lstat: async (path: string) => {
      if (path === "/workspace/a.txt") return Object.freeze({ size: 5, type: "file" });
      if (path === "/workspace/gone.txt" || path.startsWith("/tmp/cogs-index-"))
        throw new CogsSftpStatusError("no_such_file");
      throw new Error("unexpected lstat");
    },
    unlink: async (path: string) => {
      unlinked.push(path);
    },
  });
}

test("Git checkpoint creates isolated ref after bounded status, SFTP validation, staged revalidation, and cleanup", async () => {
  const commands: string[] = [];
  const unlinked: string[] = [];
  const checkpointer = createGitCheckpointer({
    commandPort: commandPort(commands),
    sftpWith: (operation) => operation(sftpPort(unlinked), new AbortController().signal),
    randomHex: () => "1".repeat(32),
    nowMs: () => 10,
    config: { enabled: true, exclusions: ["ignored/**"] },
  });

  const result = await checkpointer.checkpoint({
    repo: "repo-1",
    session: "session-1",
    entry: "1234abcd",
    turn: 7,
    head,
    observed_at: "2026-07-17T00:00:00.000Z",
  });

  assert.equal(result?.commit, commit);
  assert.equal(result?.checkpoint_ref, "refs/cogs/sessions/session-1/7");
  assert.equal(result?.file_count, 2);
  assert.equal(result?.total_bytes, 5);
  assert.ok(commands[0]?.startsWith("LC_ALL=C /usr/bin/git -C /workspace status --porcelain=v1 -z"));
  assert.ok(commands[0]?.includes(" -- . ':(exclude)ignored/**'"));
  assert.ok(
    commands.some((command) => command.includes("GIT_INDEX_FILE='/tmp/cogs-index-11111111111111111111111111111111'")),
  );
  assert.ok(commands.some((command) => command.includes("update-ref 'refs/cogs/sessions/session-1/7'")));
  assert.deepEqual(unlinked, []);

  assert.ok(result);
  const record = checkpointRecord(result);
  assert.equal(record.confidence, "checkpoint");
  assert.equal(record.checkpoint_ref, "refs/cogs/sessions/session-1/7");
  const event = checkpointEvent(result);
  assert.equal(event.trust, "trusted Cogs record of untrusted Git observation");
  assert.equal(Object.hasOwn(event, "path"), false);
});

test("Git checkpoint real local integration preserves HEAD and user index while creating hidden ref", async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-git-checkpoint-real-"));
  const repo = resolve(root, "repo");
  const seenCommands: string[] = [];
  const tempHex = randomBytes(16).toString("hex");
  const tempIndex = `/tmp/cogs-index-${tempHex}`;
  try {
    await git(root, "init", "repo");
    await git(repo, "config", "user.email", "test@example.invalid");
    await git(repo, "config", "user.name", "Test User");
    await writeFile(resolve(repo, "tracked.txt"), "base\n");
    await writeFile(resolve(repo, ".gitignore"), "ignored.txt\n");
    await git(repo, "add", ".");
    await git(repo, "commit", "-m", "base");
    const originalHead = (await git(repo, "rev-parse", "HEAD")).trim();
    const originalIndex = await readFile(resolve(repo, ".git/index"));
    await writeFile(resolve(repo, "tracked.txt"), "base\ndirty\n");
    await writeFile(resolve(repo, "new.txt"), "new\n");
    await writeFile(resolve(repo, "ignored.txt"), "ignored\n");

    const checkpointer = createGitCheckpointer({
      commandPort: {
        run: async ({ command, maxOutputBytes }) => {
          seenCommands.push(command);
          const transformed = command.replaceAll("-C /workspace", `-C ${shellQuote(repo)}`);
          const { stdout, stderr } = await execFileAsync("/bin/bash", ["-lc", transformed], {
            encoding: "buffer",
            maxBuffer: maxOutputBytes,
          });
          return Object.freeze({ code: 0, signal: null, stdout, stderrBytes: stderr.length });
        },
      },
      sftpWith: async (operation) =>
        operation(
          Object.freeze({
            lstat: async (path: string) => {
              try {
                const target = path.startsWith("/workspace/") ? resolve(repo, path.slice("/workspace/".length)) : path;
                const stats = await stat(target);
                return Object.freeze({ size: stats.size, type: stats.isFile() ? "file" : "unknown" });
              } catch {
                throw new CogsSftpStatusError("no_such_file");
              }
            },
            unlink: async (path: string) => {
              await unlink(path).catch(() => undefined);
            },
          }),
          new AbortController().signal,
        ),
      randomHex: () => tempHex,
      nowMs: () => 0,
      config: { enabled: true, exclusions: ["new.txt"] },
    });

    const result = await checkpointer.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 8,
      head: originalHead,
      observed_at: "2026-07-17T00:00:00.000Z",
    });

    assert.ok(result);
    assert.equal((await git(repo, "rev-parse", "HEAD")).trim(), originalHead);
    assert.deepEqual(await readFile(resolve(repo, ".git/index")), originalIndex);
    assert.equal(await git(repo, "show", `${result.commit}:tracked.txt`), "base\ndirty\n");
    await assert.rejects(() => git(repo, "show", `${result.commit}:new.txt`));
    assert.equal((await git(repo, "rev-parse", "refs/cogs/sessions/session-1/8")).trim(), result.commit);
    assert.ok(seenCommands.every((command) => command.includes("/usr/bin/git -C /workspace")));
    await assert.rejects(stat(tempIndex), { code: "ENOENT" });
    await assert.rejects(stat(`${tempIndex}.lock`), { code: "ENOENT" });
  } finally {
    await unlink(tempIndex).catch(() => undefined);
    await unlink(`${tempIndex}.lock`).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }
});

test("Git checkpoint pins observed head and supports SHA-256 create-only refs", async () => {
  const commands: string[] = [];
  const commit64 = "d".repeat(64);
  const checkpointer = createGitCheckpointer({
    commandPort: {
      run: async (input) => {
        commands.push(input.command);
        if (input.command.includes("status --porcelain")) return ok("?? a.txt\0");
        if (input.command.includes("read-tree")) return ok();
        if (input.command.includes(" add -A --")) return ok();
        if (input.command.includes("diff --cached --raw"))
          return ok(`:000000 100644 ${"0".repeat(64)} ${"b".repeat(64)} A\0a.txt\0`);
        if (input.command.includes("cat-file --batch-check")) return ok(`${"b".repeat(64)} blob 5\n`);
        if (input.command.includes("write-tree")) return ok(`${"c".repeat(64)}\n`);
        if (input.command.includes("commit-tree")) return ok(`${commit64}\n`);
        if (input.command.includes("update-ref")) return ok();
        throw new Error("unexpected command");
      },
    },
    sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
    randomHex: () => "3".repeat(32),
    config: { enabled: true },
  });
  const result = await checkpointer.checkpoint({
    repo: "repo-1",
    session: "session-1",
    entry: "1234abcd",
    turn: 9,
    head: "a".repeat(64),
    observed_at: "2026-07-17T00:00:00.000Z",
  });
  assert.equal(result?.commit, commit64);
  assert.ok(commands.some((command) => command.includes(`read-tree ${"a".repeat(64)}`)));
  assert.ok(
    commands.some((command) => command.includes(`diff --cached --raw -z --no-renames --no-abbrev ${"a".repeat(64)}`)),
  );
  assert.ok(commands.some((command) => command.endsWith(`${commit64} ${"0".repeat(64)}`)));
});

test("Git checkpoint rejects preexisting temp before first index command and hostile raw/limit cases", async () => {
  const commands: string[] = [];
  let preexistingUnlinks = 0;
  const preexisting = createGitCheckpointer({
    commandPort: {
      run: async (input) => {
        commands.push(input.command);
        return ok();
      },
    },
    sftpWith: (operation) =>
      operation(
        Object.freeze({
          lstat: async (path: string) =>
            path.startsWith("/tmp/cogs-index-")
              ? Object.freeze({ size: 1, type: "symlink" })
              : sftpPort().lstat(path, new AbortController().signal),
          unlink: async () => {
            preexistingUnlinks += 1;
          },
        }),
        new AbortController().signal,
      ),
    randomHex: () => "5".repeat(32),
    config: { enabled: true },
  });
  await assert.rejects(() =>
    preexisting.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );
  assert.equal(
    commands.some((command) => command.includes("read-tree")),
    false,
  );
  assert.equal(preexistingUnlinks, 0);

  let invalidRandomSftp = 0;
  const invalidRandom = createGitCheckpointer({
    commandPort: {
      run: async () => {
        throw new Error("no git");
      },
    },
    sftpWith: async (operation) => {
      invalidRandomSftp += 1;
      return operation(sftpPort(), new AbortController().signal);
    },
    randomHex: () => "../not-safe",
    config: { enabled: true },
  });
  await assert.rejects(() =>
    invalidRandom.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );
  assert.equal(invalidRandomSftp, 0);

  for (const raw of [
    `:000000 120000 ${"0".repeat(40)} ${blob} A\0a.txt\0`,
    `:160000 000000 ${blob} ${"0".repeat(40)} D\0gone.txt\0`,
    `:000000 100644 ${"0".repeat(40)} ${"b".repeat(64)} A\0a.txt\0`,
    `:000000 100644 ${"0".repeat(40)} ${blob} R\0a.txt\0`,
  ]) {
    const hostile = createGitCheckpointer({
      commandPort: {
        run: async (input) => {
          if (input.command.includes("status --porcelain")) return ok("?? a.txt\0");
          if (input.command.includes("read-tree") || input.command.includes(" add -A --")) return ok();
          if (input.command.includes("diff --cached --raw")) return ok(raw);
          return ok(`${blob} blob 5\n`);
        },
      },
      sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
      randomHex: () => "6".repeat(32),
      config: { enabled: true },
    });
    await assert.rejects(() =>
      hostile.checkpoint({
        repo: "repo-1",
        session: "session-1",
        entry: "1234abcd",
        turn: 1,
        head,
        observed_at: "2026-07-17T00:00:00.000Z",
      }),
    );
  }

  const oversized = createGitCheckpointer({
    commandPort: {
      run: async (input) => {
        if (input.command.includes("status --porcelain")) return ok("?? a.txt\0");
        if (input.command.includes("read-tree") || input.command.includes(" add -A --")) return ok();
        if (input.command.includes("diff --cached --raw"))
          return ok(`:000000 100644 ${"0".repeat(40)} ${blob} A\0a.txt\0`);
        if (input.command.includes("cat-file --batch-check")) return ok(`${blob} blob 6\n`);
        return ok(`${tree}\n`);
      },
    },
    sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
    randomHex: () => "7".repeat(32),
    config: { enabled: true, maxFileBytes: 5 },
  });
  await assert.rejects(() =>
    oversized.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );
});

test("Git checkpoint bounds hanging seams and rejects hostile command output", async () => {
  const timeouts: number[] = [];
  const hangingCommand = createGitCheckpointer({
    commandPort: {
      run: ({ signal, timeoutMs }) => {
        timeouts.push(timeoutMs);
        return new Promise((_, reject) =>
          signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true }),
        );
      },
    },
    sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
    randomHex: () => "8".repeat(32),
    nowMs: (() => {
      let now = 0;
      return () => (now += 5);
    })(),
    config: { enabled: true, timeoutMs: 20 },
  });
  await assert.rejects(() =>
    hangingCommand.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );
  assert.ok(timeouts.length > 0 && timeouts.every((value) => value <= 15));

  const badOutputs = [
    { code: 0, signal: null, stdout: Buffer.from(""), stderrBytes: 0, extra: true },
    Object.create(null, {
      code: { value: 0, enumerable: true },
      signal: { value: null, enumerable: true },
      stdout: { value: Buffer.from([0xff]), enumerable: true },
      stderrBytes: { value: 0, enumerable: true },
    }),
    Object.freeze({ code: 0, signal: null, stdout: Buffer.alloc(2048), stderrBytes: 0 }),
  ];
  for (const raw of badOutputs) {
    const checkpointer = createGitCheckpointer({
      commandPort: { run: async () => raw },
      sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
      randomHex: () => "9".repeat(32),
      config: { enabled: true, maxOutputBytes: 1024 },
    });
    await assert.rejects(() =>
      checkpointer.checkpoint({
        repo: "repo-1",
        session: "session-1",
        entry: "1234abcd",
        turn: 1,
        head,
        observed_at: "2026-07-17T00:00:00.000Z",
      }),
    );
  }

  const hangingSftp = createGitCheckpointer({
    commandPort: commandPort([]),
    sftpWith: (_operation, input) =>
      new Promise((_, reject) =>
        input.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }),
      ),
    randomHex: () => "a".repeat(32),
    config: { enabled: true, timeoutMs: 20 },
  });
  await assert.rejects(() =>
    hangingSftp.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );
});

test("Git checkpoint rejects hostile exclusions, malformed output, unsupported files, races, and existing refs generically", async () => {
  assert.throws(() =>
    createGitCheckpointer({
      commandPort: commandPort([]),
      sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
      config: { enabled: true, exclusions: ["../secret"] },
    }),
  );

  const badStatus = createGitCheckpointer({
    commandPort: { run: async () => ok("?? ../x\0") },
    sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
    config: { enabled: true },
  });
  await assert.rejects(() =>
    badStatus.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );

  const symlink = createGitCheckpointer({
    commandPort: commandPort([]),
    sftpWith: (operation) =>
      operation(
        Object.freeze({
          ...sftpPort(),
          lstat: async () => Object.freeze({ size: 1, type: "symlink" }),
        }),
        new AbortController().signal,
      ),
    config: { enabled: true },
  });
  await assert.rejects(() =>
    symlink.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );

  const existingRef = createGitCheckpointer({
    commandPort: {
      run: async (input) => (input.command.includes("update-ref") ? ok("bad\n") : commandPort([]).run(input)),
    },
    sftpWith: (operation) => operation(sftpPort(), new AbortController().signal),
    randomHex: () => "2".repeat(32),
    config: { enabled: true },
  });
  await assert.rejects(() =>
    existingRef.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );

  const cleanupFailure = createGitCheckpointer({
    commandPort: commandPort([]),
    sftpWith: (operation) =>
      operation(
        Object.freeze({
          ...sftpPort(),
          lstat: async (path: string) =>
            path.startsWith("/tmp/cogs-index-")
              ? Object.freeze({ size: 1, type: "file" })
              : sftpPort().lstat(path, new AbortController().signal),
          unlink: async (path: string) => {
            if (path.startsWith("/tmp/cogs-index-")) throw new CogsSftpStatusError("permission_denied");
          },
        }),
        new AbortController().signal,
      ),
    randomHex: () => "4".repeat(32),
    config: { enabled: true },
  });
  await assert.rejects(() =>
    cleanupFailure.checkpoint({
      repo: "repo-1",
      session: "session-1",
      entry: "1234abcd",
      turn: 1,
      head,
      observed_at: "2026-07-17T00:00:00.000Z",
    }),
  );
});

async function git(cwd: string, ...args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("/usr/bin/git", args, { cwd, encoding: "utf8" });
  return stdout;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}
