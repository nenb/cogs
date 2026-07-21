#!/usr/bin/env node
import { lstat, mkdir, realpath } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseLauncherArgs } from "./cli.ts";
import { runLauncherOperation, s309StageExitCode } from "./operations.ts";
import { commandDescriptor, runCommand } from "./runner.ts";

async function main(): Promise<void> {
  const request = parseLauncherArgs(process.argv.slice(2));
  const repoRoot = await realpath(fileURLToPath(new URL("../..", import.meta.url)));
  const devRoot = await privateChild(repoRoot, ".cogs-dev");
  const launcherRoot = await privateChild(devRoot, "launcher");
  const exportRoot = await privateChild(devRoot, "exports");
  const sourceRevision = await currentRevision(repoRoot);
  const result = await runLauncherOperation(
    request,
    Object.freeze({
      launcherRoot: await realpath(launcherRoot),
      repoRoot,
      exportRoot: await realpath(exportRoot),
      sourceRevision,
    }),
  );
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

async function privateChild(parent: string, name: string): Promise<string> {
  const path = join(parent, name);
  await lstat(path).catch(async (error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    await mkdir(path, { mode: 0o700 });
  });
  const stat = await lstat(path);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o700) throw new Error("launcher failed");
  if (typeof process.geteuid === "function" && stat.uid !== process.geteuid()) throw new Error("launcher failed");
  if ((await realpath(path)) !== path) throw new Error("launcher failed");
  return path;
}

async function currentRevision(repoRoot: string): Promise<string> {
  const result = await runCommand(
    commandDescriptor({
      executable: "/usr/bin/git",
      args: Object.freeze(["rev-parse", "--verify", "HEAD^{commit}"]),
      cwd: repoRoot,
      env: Object.freeze({ PATH: "/usr/bin:/bin" }),
      timeoutMs: 5000,
      maxOutputBytes: 128,
      killGraceMs: 1000,
    }),
  );
  const revision = result.stdout.trim();
  if (result.status !== "ok" || result.exitCode !== 0 || !/^[a-f0-9]{40}$/u.test(revision))
    throw new Error("launcher failed");
  return revision;
}

main().catch((error) => {
  process.stderr.write("launcher failed\n");
  process.exitCode = s309StageExitCode(error);
});
