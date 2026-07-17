import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { access, mkdir, mkdtemp, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { promisify } from "node:util";
import { type CogsGitCheckpointConfig, createGitCheckpointer } from "../src/session/git-checkpoint.ts";
import { CogsSftpStatusError } from "../src/ssh/connection.ts";

const execFileAsync = promisify(execFile);
const GIT = "/usr/bin/git";
const VERSION = "cogs.issue68-checkpoint-benchmark/v1alpha1";

type CaseReport = {
  readonly name: string;
  readonly requested_limits: {
    readonly maxChangedFiles: number;
    readonly maxFileBytes: number;
    readonly maxTotalBytes: number;
  };
  readonly measured: {
    readonly file_count: number;
    readonly total_bytes: number;
    readonly result_duration_ms: number;
    readonly wall_duration_ms: number;
    readonly eligible_changed_files: number;
    readonly eligible_changed_bytes: number;
  };
  readonly invariants: Record<string, boolean>;
};

type CaseSpec = {
  readonly name: string;
  readonly maxChangedFiles: number;
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
  readonly exclusions?: readonly string[];
  readonly setup: (repo: string) => Promise<{ expectedChanged: readonly string[]; expectedBytes: number }>;
};

async function main(): Promise<void> {
  if (process.argv.length > 2) throw new Error("unexpected arguments");
  const sourceSha = await gitText(process.cwd(), "rev-parse", "HEAD");
  const root = await mkdtemp(resolve(tmpdir(), "cogs-issue68-checkpoint-bench-"));
  const cases: CaseReport[] = [];
  let cleanupConfirmed = false;
  try {
    for (const spec of specs()) cases.push(await runCase(root, spec));
  } finally {
    await rm(root, { recursive: true, force: true });
    cleanupConfirmed = await absent(root);
  }
  const report = {
    version: VERSION,
    git: { source_sha: sourceSha.trim() },
    environment: { platform: process.platform, arch: process.arch, node: process.version },
    applicability: "local functional-only",
    release_eligible: false,
    isolation_authoritative: false,
    aws_resources_used: false,
    cases,
    cleanup: { temporary_root_removed: cleanupConfirmed },
  };
  if (!cleanupConfirmed) throw new Error("cleanup confirmation failed");
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function specs(): readonly CaseSpec[] {
  return Object.freeze([
    {
      name: "small",
      maxChangedFiles: 128,
      maxFileBytes: 1024,
      maxTotalBytes: 16 * 1024,
      setup: async (repo) => {
        await writeFile(resolve(repo, "tracked.txt"), "base\n");
        await git(repo, "add", ".");
        await git(repo, "commit", "-m", "base");
        await writeFile(resolve(repo, "tracked.txt"), "base\ndirty\n");
        await writeFile(resolve(repo, "new.txt"), "new eligible\n");
        return {
          expectedChanged: ["new.txt", "tracked.txt"],
          expectedBytes: byteLength("new eligible\n") + byteLength("base\ndirty\n"),
        };
      },
    },
    {
      name: "large-at-limit",
      maxChangedFiles: 128,
      maxFileBytes: 1024,
      maxTotalBytes: 128 * 1024,
      setup: async (repo) => {
        await writeFile(resolve(repo, "base.txt"), "base\n");
        await git(repo, "add", ".");
        await git(repo, "commit", "-m", "base");
        const expected: string[] = [];
        let bytes = 0;
        for (let index = 0; index < 128; index += 1) {
          const name = `eligible-${String(index).padStart(3, "0")}.txt`;
          const content = `eligible ${String(index).padStart(3, "0")} ${"x".repeat(24)}\n`;
          await writeFile(resolve(repo, name), content);
          expected.push(name);
          bytes += byteLength(content);
        }
        return { expectedChanged: expected, expectedBytes: bytes };
      },
    },
    {
      name: "dirty-ignored-excluded",
      maxChangedFiles: 128,
      maxFileBytes: 2048,
      maxTotalBytes: 32 * 1024,
      exclusions: ["excluded"],
      setup: async (repo) => {
        await mkdir(resolve(repo, "excluded"), { recursive: true });
        await writeFile(resolve(repo, ".gitignore"), "ignored.txt\nignored-dir/\n");
        await writeFile(resolve(repo, "tracked.txt"), "base\n");
        await writeFile(resolve(repo, "excluded", "tracked-excluded.txt"), "excluded base\n");
        await git(repo, "add", ".");
        await git(repo, "commit", "-m", "base");
        await writeFile(resolve(repo, "tracked.txt"), "base\ndirty\n");
        await writeFile(resolve(repo, "eligible.txt"), "eligible new\n");
        await writeFile(resolve(repo, "ignored.txt"), "ignored dirty\n");
        await mkdir(resolve(repo, "ignored-dir"), { recursive: true });
        await writeFile(resolve(repo, "ignored-dir", "file.txt"), "ignored dir\n");
        await writeFile(resolve(repo, "excluded", "tracked-excluded.txt"), "excluded dirty\n");
        await writeFile(resolve(repo, "excluded", "untracked-excluded.txt"), "excluded new\n");
        return {
          expectedChanged: ["eligible.txt", "tracked.txt"],
          expectedBytes: byteLength("eligible new\n") + byteLength("base\ndirty\n"),
        };
      },
    },
  ]);
}

async function runCase(root: string, spec: CaseSpec): Promise<CaseReport> {
  const repo = resolve(root, spec.name);
  const seenCommands: string[] = [];
  const tempHex = randomBytes(16).toString("hex");
  const tempIndex = `/tmp/cogs-index-${tempHex}`;
  const session = `bench-${randomBytes(6).toString("hex")}`;
  const config: CogsGitCheckpointConfig = {
    enabled: true,
    maxChangedFiles: spec.maxChangedFiles,
    maxFileBytes: spec.maxFileBytes,
    maxTotalBytes: spec.maxTotalBytes,
    maxOutputBytes: 1024 * 1024,
    timeoutMs: 10_000,
    ...(spec.exclusions === undefined ? {} : { exclusions: spec.exclusions }),
  };
  try {
    await git(root, "init", spec.name);
    await git(repo, "config", "user.email", "benchmark@example.invalid");
    await git(repo, "config", "user.name", "Cogs Benchmark");
    const expected = await spec.setup(repo);
    const headBefore = (await gitText(repo, "rev-parse", "HEAD")).trim();
    const indexBefore = await readFile(resolve(repo, ".git", "index"));
    const statusBefore = await gitBuffer(
      repo,
      "status",
      "--porcelain=v1",
      "-z",
      "--untracked-files=all",
      "--no-renames",
    );
    const checkpointer = createGitCheckpointer({
      commandPort: {
        run: async ({ command, maxOutputBytes }) => {
          seenCommands.push(command);
          if (!command.includes(`${GIT} -C /workspace`)) throw new Error("unexpected git command");
          const transformed = command.replaceAll("-C /workspace", `-C ${shellQuote(repo)}`);
          const { stdout, stderr } = await execFileAsync("/bin/bash", ["-lc", transformed], {
            encoding: "buffer",
            maxBuffer: maxOutputBytes,
          });
          return Object.freeze({ code: 0, signal: null, stdout, stderrBytes: stderr.length });
        },
      },
      sftpWith: async (operation, input) =>
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
              await unlink(path);
            },
          }),
          input.signal,
        ),
      randomHex: () => tempHex,
      config,
    });
    const started = performance.now();
    const result = await checkpointer.checkpoint({
      repo: "workspace-1",
      session,
      entry: randomBytes(4).toString("hex"),
      turn: 1,
      head: headBefore,
      observed_at: "2026-07-17T00:00:00.000Z",
    });
    const wallDurationMs = Math.round(performance.now() - started);
    if (result === null) throw new Error("checkpoint unexpectedly empty");
    const headAfter = (await gitText(repo, "rev-parse", "HEAD")).trim();
    const indexAfter = await readFile(resolve(repo, ".git", "index"));
    const statusAfter = await gitBuffer(
      repo,
      "status",
      "--porcelain=v1",
      "-z",
      "--untracked-files=all",
      "--no-renames",
    );
    const refCommit = (await gitText(repo, "rev-parse", `refs/cogs/sessions/${session}/1`)).trim();
    const changedPaths = (await gitText(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", result.commit))
      .trim()
      .split("\n")
      .filter(Boolean)
      .sort();
    const expectedPaths = [...expected.expectedChanged].sort();
    const remotes = (await gitText(repo, "remote", "-v")).trim();
    const invariants = {
      hidden_ref_created: refCommit === result.commit,
      hidden_ref_tree_matches_eligible: JSON.stringify(changedPaths) === JSON.stringify(expectedPaths),
      head_byte_identical: headAfter === headBefore,
      index_byte_identical: Buffer.compare(indexBefore, indexAfter) === 0,
      status_nul_byte_identical: Buffer.compare(statusBefore, statusAfter) === 0,
      temp_index_absent: await absent(tempIndex),
      temp_lock_absent: await absent(`${tempIndex}.lock`),
      no_remotes_configured: remotes === "",
      no_push_invoked: seenCommands.every((command) => !/(^|\s)push(\s|$)/.test(command)),
      fixed_git_workspace_commands: seenCommands.every(
        (command) => command.includes("LC_ALL=C") && command.includes(`${GIT} -C /workspace`),
      ),
      result_counts_match_expected:
        result.file_count === expectedPaths.length && result.total_bytes === expected.expectedBytes,
    };
    if (spec.name === "dirty-ignored-excluded") {
      const diffSet = new Set(changedPaths);
      Object.assign(invariants, {
        ignored_absent_from_checkpoint_diff: !diffSet.has("ignored.txt") && !diffSet.has("ignored-dir/file.txt"),
        excluded_absent_from_checkpoint_diff:
          !diffSet.has("excluded/tracked-excluded.txt") && !diffSet.has("excluded/untracked-excluded.txt"),
      });
    }
    if (Object.values(invariants).some((ok) => ok !== true)) throw new Error(`invariant failed for ${spec.name}`);
    return {
      name: spec.name,
      requested_limits: {
        maxChangedFiles: spec.maxChangedFiles,
        maxFileBytes: spec.maxFileBytes,
        maxTotalBytes: spec.maxTotalBytes,
      },
      measured: {
        file_count: result.file_count,
        total_bytes: result.total_bytes,
        result_duration_ms: result.duration_ms,
        wall_duration_ms: wallDurationMs,
        eligible_changed_files: expectedPaths.length,
        eligible_changed_bytes: expected.expectedBytes,
      },
      invariants,
    };
  } finally {
    await unlink(tempIndex).catch(() => undefined);
    await unlink(`${tempIndex}.lock`).catch(() => undefined);
  }
}

async function git(cwd: string, ...args: string[]): Promise<void> {
  await execFileAsync(GIT, args, { cwd, encoding: "buffer", maxBuffer: 1024 * 1024 });
}

async function gitText(cwd: string, ...args: string[]): Promise<string> {
  const { stdout } = await execFileAsync(GIT, args, { cwd, encoding: "utf8", maxBuffer: 1024 * 1024 });
  return stdout;
}

async function gitBuffer(cwd: string, ...args: string[]): Promise<Buffer> {
  const { stdout } = await execFileAsync(GIT, args, { cwd, encoding: "buffer", maxBuffer: 1024 * 1024 });
  return stdout;
}

async function absent(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return false;
  } catch {
    return true;
  }
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : "benchmark failed"}\n`);
  process.exitCode = 1;
});
