import { strict as assert } from "node:assert";
import test from "node:test";
import type { CogsGitMapRecord } from "../src/session/git-map.ts";
import { type CogsGitCommandPort, createGitObserver } from "../src/session/git-observer.ts";

const sha1 = "a".repeat(40);
const sha2 = "b".repeat(40);
const sha3 = "c".repeat(40);
const clock = () => new Date("2026-07-17T00:00:00.000Z");

test("Git observer uses fixed commit-peeling HEAD command and hides non-Git as unavailable", async () => {
  const seen: string[] = [];
  const observer = createGitObserver({
    repositoryId: "repo-1",
    clock,
    commandPort: port(async ({ command }) => {
      seen.push(command);
      return ok(`${sha1}\n`);
    }),
  });
  const result = await observer.observeHead();
  assert.equal(result.kind, "observed");
  assert.equal(result.kind === "observed" && result.repo, "repo-1");
  assert.equal(result.kind === "observed" && result.observed_at, "2026-07-17T00:00:00.000Z");
  assert.equal(seen[0], FIXED_HEAD);

  const unavailable = createGitObserver({
    repositoryId: "repo-1",
    commandPort: port(async () => ({ ...ok(""), code: 128 })),
  });
  assert.deepEqual(await unavailable.observeHead(), { kind: "unavailable" });
});

test("Git observer rejects malformed, stderr, flood, fatal UTF-8, terminal signal, hostile accessors, and timeout generically", async () => {
  for (const response of [
    ok(`${"A".repeat(40)}\n`),
    ok(`${sha1}`),
    ok(`${sha1}\nextra\n`),
    { ...ok(`${sha1}\n`), stderrBytes: 1 },
    { ...ok(`${sha1}\n`), signal: "TERM" },
    { ...ok(`${sha1}\n`), stdout: Buffer.from([0xff]) },
    Object.freeze({ code: 0, signal: null, stdout: Buffer.from(`${sha1}\n`), stderrBytes: 0, extra: true }),
    Object.freeze(
      Object.defineProperty({ code: 0, signal: null, stderrBytes: 0 }, "stdout", { get: () => Buffer.alloc(0) }),
    ),
    Object.freeze(
      Object.defineProperty({ code: 0, signal: null, stdout: Buffer.from(`${sha1}\n`) }, "stderrBytes", {
        value: 0,
        enumerable: false,
      }),
    ),
    Object.assign(Object.create(null), { code: 0, signal: null, stdout: Buffer.from(`${sha1}\n`), stderrBytes: 0 }),
    new Proxy(
      { code: 0, signal: null, stdout: Buffer.from(`${sha1}\n`), stderrBytes: 0 },
      { getPrototypeOf: () => null },
    ),
    ok(`${sha1}\n`, 70 * 1024),
  ]) {
    const observer = createGitObserver({ repositoryId: "repo-1", commandPort: port(async () => response) });
    assert.deepEqual(await observer.observeHead(), { kind: "unavailable" });
  }
  const timeout = createGitObserver({
    repositoryId: "repo-1",
    totalTimeoutMs: 1,
    commandPort: port(() => new Promise(() => undefined)),
  });
  assert.deepEqual(await timeout.observeHead(), { kind: "unavailable" });
});

test("Git nearest ancestor uses max+1 sentinel and first topo candidate is nearest only after non-truncated walk", async () => {
  let command = "";
  const complete = createGitObserver({
    repositoryId: "repo-1",
    maxAncestorCommits: 3,
    commandPort: port(async (input) => {
      command = input.command;
      return ok(`${sha3}\n${sha2}\n${sha1}\n`);
    }),
  });
  assert.equal(await complete.nearestAncestor({ requested: sha3, candidates: Object.freeze([sha1, sha2]) }), sha2);
  assert.match(command, /--max-count=4 /);

  const truncated = createGitObserver({
    repositoryId: "repo-1",
    maxAncestorCommits: 2,
    commandPort: port(async () => ok(`${sha3}\n${sha2}\n${sha1}\n`)),
  });
  await assert.rejects(() => truncated.nearestAncestor({ requested: sha3, candidates: Object.freeze([sha1]) }));
});

test("Git notes append without overwrite and require empty stdout/stderr exact success", async () => {
  let command = "";
  const observer = createGitObserver({
    repositoryId: "repo-1",
    commandPort: port(async (input) => {
      command = input.command;
      return ok("");
    }),
  });
  const record: CogsGitMapRecord = Object.freeze({
    version: "cogs.git-mapping/v1alpha1",
    repo: "repo-1",
    commit: sha1,
    session: "session-1",
    entry: "abcdef12",
    turn: 1,
    observed_at: "2026-07-17T00:00:00.000Z",
    confidence: "checkpoint",
    checkpoint_ref: "refs/cogs/sessions/session-1/1",
  });
  assert.equal(await observer.appendNote(record), true);
  assert.match(command, /^LC_ALL=C \/usr\/bin\/git -C \/workspace notes --ref=refs\/notes\/cogs append -m /);
  assert.doesNotMatch(command, / add | add -f |push|remote|config|stderr|stdout|secret|token|credential/i);
  assert.match(command, /observed_at=2026-07-17T00:00:00.000Z/);
  assert.match(command, /confidence=checkpoint/);

  const noisy = createGitObserver({ repositoryId: "repo-1", commandPort: port(async () => ok("noise\n")) });
  assert.equal(await noisy.appendNote(record), false);
});

test("Git observer bounds concurrent command operations and handles sync throw/non-Promise generically", async () => {
  let active = 0;
  let maxActive = 0;
  const observer = createGitObserver({
    repositoryId: "repo-1",
    maxConcurrentOperations: 2,
    totalTimeoutMs: 50,
    commandPort: port(
      () =>
        new Promise((resolve) => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          setTimeout(() => {
            active -= 1;
            resolve(ok(`${sha1}\n`));
          }, 10);
        }),
    ),
  });
  const results = await Promise.all(Array.from({ length: 8 }, () => observer.observeHead()));
  assert.ok(maxActive <= 2);
  assert.ok(results.some((result) => result.kind === "unavailable"));

  const throwing = createGitObserver({
    repositoryId: "repo-1",
    commandPort: port(() => {
      throw new Error("raw secret");
    }),
  });
  assert.deepEqual(await throwing.observeHead(), { kind: "unavailable" });
  const nonPromise = createGitObserver({
    repositoryId: "repo-1",
    commandPort: { run: (() => ok(`${sha1}\n`)) as unknown as CogsGitCommandPort["run"] },
  });
  assert.equal((await nonPromise.observeHead()).kind, "observed");
});

test("Git observer cancellation and async dispose abort active bounded work", async () => {
  const controller = new AbortController();
  controller.abort();
  const observer = createGitObserver({ repositoryId: "repo-1", commandPort: port(async () => ok(`${sha1}\n`)) });
  assert.deepEqual(await observer.observeHead({ signal: controller.signal }), { kind: "unavailable" });
  await observer.dispose();
  assert.deepEqual(await observer.observeHead(), { kind: "unavailable" });
  await assert.rejects(() => observer.nearestAncestor({ requested: sha1, candidates: Object.freeze([sha2]) }));
});

const FIXED_HEAD = "LC_ALL=C /usr/bin/git -C /workspace rev-parse --verify 'HEAD^{commit}'";

function ok(stdout: string, extraBytes = 0) {
  return {
    code: 0,
    signal: null,
    stdout: Buffer.concat([Buffer.from(stdout, "utf8"), Buffer.alloc(extraBytes)]),
    stderrBytes: 0,
  } as const;
}

function port(run: CogsGitCommandPort["run"]): CogsGitCommandPort {
  return Object.freeze({ run });
}
