import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { AdapterResult, ConformanceAdapter, ConformanceCase } from "../../controller/runner.ts";
import { type EnvoyCandidateConfigInput, renderEnvoyConfig } from "./config.ts";
import { ENVOY_IMAGE } from "./image.ts";

const outputLimit = 64 * 1024;
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export interface EnvoyCaseRuntime {
  proxyOrigin: string;
  stateDirectory: string;
}

export interface EnvoyCaseCommand {
  command: string;
  args: readonly string[];
  env?: Readonly<Record<string, string>>;
}

export interface EnvoyAccessRecord {
  event: "request-complete";
  intent_id: string;
  route_id: string;
  response_code: number;
  duration_ms: number;
}

export interface EnvoyAdapterOptions {
  stateRoot?: string;
  dockerCommand?: string;
  configurationFor(test: Readonly<ConformanceCase>): EnvoyCandidateConfigInput | Promise<EnvoyCandidateConfigInput>;
  commandFor(test: Readonly<ConformanceCase>, runtime: Readonly<EnvoyCaseRuntime>): EnvoyCaseCommand;
  sensitiveValues?: readonly string[];
}

interface CommandResult {
  stdout: string;
  stderr: string;
}

interface ActiveCase {
  container: string;
  directory: string;
  listenerPort: number;
  started: boolean;
}

function runFile(
  command: string,
  args: readonly string[],
  options: { timeoutMs: number; signal?: AbortSignal; env?: NodeJS.ProcessEnv } = { timeoutMs: 30_000 },
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    execFile(
      command,
      [...args],
      {
        timeout: options.timeoutMs,
        maxBuffer: outputLimit,
        windowsHide: true,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(options.env === undefined ? {} : { env: options.env }),
      },
      (error, stdout, stderr) => {
        if (error) {
          reject(error);
          return;
        }
        resolve({ stdout, stderr });
      },
    );
  });
}

export function parseExternalCaseResult(value: string): AdapterResult {
  if (Buffer.byteLength(value) > outputLimit) throw new Error("case command output exceeded its bound");
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("case command returned malformed JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("case command returned a malformed result");
  }
  const record = parsed as Record<string, unknown>;
  if (
    Object.keys(record).some((key) => key !== "passed" && key !== "diagnosticsRedacted") ||
    typeof record.passed !== "boolean" ||
    (record.diagnosticsRedacted !== undefined && typeof record.diagnosticsRedacted !== "string")
  ) {
    throw new Error("case command returned a malformed result");
  }
  return {
    passed: record.passed,
    ...(typeof record.diagnosticsRedacted === "string" ? { diagnosticsRedacted: record.diagnosticsRedacted } : {}),
  };
}

function parseAccessRecords(logs: string): EnvoyAccessRecord[] {
  const records: EnvoyAccessRecord[] = [];
  for (const line of logs.split("\n")) {
    if (!line.trimStart().startsWith("{")) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) continue;
    const value = parsed as Record<string, unknown>;
    if (value.event !== "request-complete") continue;
    const responseCode = Number(value.response_code);
    const duration = Number(value.duration_ms);
    if (
      typeof value.intent_id !== "string" ||
      !idPattern.test(value.intent_id) ||
      typeof value.route_id !== "string" ||
      !idPattern.test(value.route_id) ||
      !Number.isInteger(responseCode) ||
      responseCode < 100 ||
      responseCode > 599 ||
      !Number.isInteger(duration) ||
      duration < 0 ||
      duration > 300_000
    ) {
      throw new Error("Envoy emitted a malformed structured completion record");
    }
    records.push({
      event: "request-complete",
      intent_id: value.intent_id,
      route_id: value.route_id,
      response_code: responseCode,
      duration_ms: duration,
    });
  }
  return records;
}

async function waitForListener(port: number, signal: AbortSignal): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (signal.aborted) throw signal.reason;
    const connected = await new Promise<boolean>((resolve) => {
      const socket = createConnection({ host: "127.0.0.1", port });
      const finish = (value: boolean) => {
        socket.destroy();
        resolve(value);
      };
      socket.setTimeout(500, () => finish(false));
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
    });
    if (connected) return;
    await delay(100, undefined, { signal });
  }
  throw new Error("Envoy forward-proxy listener readiness timed out");
}

export class EnvoyConformanceAdapter implements ConformanceAdapter {
  readonly name = "envoy";
  readonly #options: EnvoyAdapterOptions;
  readonly #docker: string;
  readonly #stateRoot: string;
  readonly #runId = randomUUID().replaceAll("-", "");
  readonly #accessRecords: EnvoyAccessRecord[] = [];
  #active: ActiveCase | undefined;

  constructor(options: EnvoyAdapterOptions) {
    if (options.sensitiveValues?.some((value) => value.length === 0)) {
      throw new Error("adapter sensitive values must not be empty");
    }
    this.#options = options;
    this.#docker = options.dockerCommand ?? "docker";
    this.#stateRoot = options.stateRoot ?? tmpdir();
  }

  accessRecords(): readonly EnvoyAccessRecord[] {
    return Object.freeze(structuredClone(this.#accessRecords));
  }

  async execute(test: Readonly<ConformanceCase>, signal: AbortSignal): Promise<AdapterResult> {
    if (this.#active !== undefined) throw new Error("Envoy adapter already has an active case");
    await mkdir(this.#stateRoot, { recursive: true, mode: 0o700 });
    const directory = await mkdtemp(join(this.#stateRoot, "cogs-envoy-"));
    const configuration = await this.#options.configurationFor(test);
    const configPath = join(directory, "envoy.json");
    await writeFile(configPath, renderEnvoyConfig(configuration), { mode: 0o400, flag: "wx" });
    const container = `cogs-envoy-${this.#runId.slice(0, 12)}-${test.id.replaceAll(/[^A-Za-z0-9_.-]/g, "-")}`;
    this.#active = { container, directory, listenerPort: configuration.listenerPort, started: false };

    const user =
      typeof process.getuid === "function"
        ? `${process.getuid()}:${process.getgid?.() ?? process.getuid()}`
        : "65532:65532";
    const common = [
      "run",
      "--network",
      "host",
      "--read-only",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--pids-limit=256",
      "--memory=256m",
      "--cpus=1",
      "--user",
      user,
      "--mount",
      `type=bind,src=${directory},dst=/cogs,readonly`,
      "--tmpfs",
      "/tmp:rw,nosuid,nodev,noexec,size=32m",
    ];
    await runFile(this.#docker, [...common, "--rm", ENVOY_IMAGE, "--mode", "validate", "-c", "/cogs/envoy.json"], {
      timeoutMs: 30_000,
      signal,
    });
    await runFile(
      this.#docker,
      [
        ...common,
        "--detach",
        "--rm",
        "--name",
        container,
        "--label",
        `dev.cogs.envoy-adapter=${this.#runId}`,
        ENVOY_IMAGE,
        "-c",
        "/cogs/envoy.json",
        "--disable-hot-restart",
        "--log-level",
        "warning",
        "--drain-time-s",
        "2",
        "--parent-shutdown-time-s",
        "3",
      ],
      { timeoutMs: 30_000, signal },
    );
    if (this.#active !== undefined) this.#active.started = true;
    await waitForListener(configuration.listenerPort, signal);

    const runtime = Object.freeze({
      proxyOrigin: `http://127.0.0.1:${configuration.listenerPort}`,
      stateDirectory: directory,
    });
    const plan = this.#options.commandFor(test, runtime);
    const result = await runFile(plan.command, plan.args, {
      timeoutMs: Math.max(100, test.timeout_ms - 100),
      signal,
      env: { ...process.env, ...plan.env },
    });
    const combined = `${result.stdout}\n${result.stderr}`;
    if (this.#options.sensitiveValues?.some((secret) => combined.includes(secret))) {
      return { passed: false, diagnosticsRedacted: "external case command exposed a sensitive value" };
    }
    if (result.stderr.trim() !== "") {
      return { passed: false, diagnosticsRedacted: "external case command wrote unexpected diagnostics" };
    }
    await delay(50, undefined, { signal });
    await this.#captureLogs();
    return parseExternalCaseResult(result.stdout.trim());
  }

  async cleanup(_test: Readonly<ConformanceCase>): Promise<void> {
    await this.#cleanupActive();
  }

  async teardown(): Promise<void> {
    await this.#cleanupActive();
    const listed = await runFile(
      this.#docker,
      ["container", "ls", "--all", "--quiet", "--filter", `label=dev.cogs.envoy-adapter=${this.#runId}`],
      { timeoutMs: 15_000 },
    );
    const leftovers = listed.stdout.trim().split("\n").filter(Boolean);
    for (const container of leftovers) {
      await runFile(this.#docker, ["container", "rm", "--force", container], { timeoutMs: 15_000 });
    }
    const verified = await runFile(
      this.#docker,
      ["container", "ls", "--all", "--quiet", "--filter", `label=dev.cogs.envoy-adapter=${this.#runId}`],
      { timeoutMs: 15_000 },
    );
    if (verified.stdout.trim() !== "") throw new Error("Envoy adapter teardown left labelled containers behind");
  }

  async #captureLogs(): Promise<void> {
    if (this.#active === undefined || !this.#active.started) return;
    const logs = await runFile(this.#docker, ["logs", this.#active.container], { timeoutMs: 15_000 });
    const combined = `${logs.stdout}\n${logs.stderr}`;
    if (this.#options.sensitiveValues?.some((secret) => combined.includes(secret))) {
      throw new Error("Envoy logs contained a configured sensitive value");
    }
    const known = new Set(this.#accessRecords.map((record) => `${record.intent_id}:${record.route_id}`));
    for (const record of parseAccessRecords(combined)) {
      const key = `${record.intent_id}:${record.route_id}`;
      if (!known.has(key)) {
        this.#accessRecords.push(record);
        known.add(key);
      }
    }
  }

  async #cleanupActive(): Promise<void> {
    const active = this.#active;
    if (active === undefined) return;
    try {
      if (!active.started) {
        await rm(active.directory, { recursive: true, force: true });
        this.#active = undefined;
        return;
      }
      await this.#captureLogs();
      await runFile(this.#docker, ["stop", "--time", "3", active.container], { timeoutMs: 10_000 });
      const listed = await runFile(
        this.#docker,
        ["container", "ls", "--all", "--format", "{{.Names}}", "--filter", `name=^/${active.container}$`],
        { timeoutMs: 15_000 },
      );
      if (listed.stdout.trim() !== "") throw new Error("Envoy case cleanup did not remove its container");
      await rm(active.directory, { recursive: true, force: true });
      try {
        await readFile(active.directory);
        throw new Error("Envoy case cleanup did not remove trusted configuration state");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EISDIR" && (error as NodeJS.ErrnoException).code !== "ENOENT") {
          throw error;
        }
        if ((error as NodeJS.ErrnoException).code === "EISDIR") {
          throw new Error("Envoy case cleanup did not remove trusted configuration state");
        }
      }
      this.#active = undefined;
    } catch (error) {
      throw new Error(error instanceof Error ? error.message : "Envoy case cleanup failed");
    }
  }
}
