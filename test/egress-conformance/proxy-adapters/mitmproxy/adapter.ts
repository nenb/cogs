import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import type { AdapterResult, ConformanceAdapter, ConformanceCase } from "../../controller/runner.ts";
import { parseExternalCaseResult } from "../envoy/adapter.ts";
import { MITMPROXY_IMAGE } from "./image.ts";
import { type MitmproxyPolicyInput, renderMitmproxyPolicy } from "./policy.ts";

const outputLimit = 64 * 1024;
const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const here = dirname(fileURLToPath(import.meta.url));

export interface MitmproxyCaseRuntime {
  proxyOrigin: string;
  publicCaPath: string;
}
export interface MitmproxyCaseCommand {
  command: string;
  args: readonly string[];
  env?: Readonly<Record<string, string>>;
}
export interface MitmproxyAccessRecord {
  event: "request-complete";
  intent_id: string;
  route_id: string;
  response_code: number;
  duration_ms: number;
  completion_recorded: boolean;
}
export interface MitmproxyAdapterOptions {
  listenerPort: number;
  upstreamCaCertificatePem: string;
  stateRoot?: string;
  dockerCommand?: string;
  policyFor(test: Readonly<ConformanceCase>): MitmproxyPolicyInput | Promise<MitmproxyPolicyInput>;
  commandFor(test: Readonly<ConformanceCase>, runtime: Readonly<MitmproxyCaseRuntime>): MitmproxyCaseCommand;
  sensitiveValues?: readonly string[];
}
interface ActiveCase {
  container: string;
  directory: string;
  started: boolean;
}

function runFile(
  command: string,
  args: readonly string[],
  timeoutMs: number,
  signal?: AbortSignal,
  env?: NodeJS.ProcessEnv,
) {
  return new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
    execFile(
      command,
      [...args],
      {
        timeout: timeoutMs,
        maxBuffer: outputLimit,
        windowsHide: true,
        ...(signal ? { signal } : {}),
        ...(env ? { env } : {}),
      },
      (error, stdout, stderr) => (error ? reject(error) : resolve({ stdout, stderr })),
    );
  });
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
  throw new Error("mitmproxy listener readiness timed out");
}

function parseRecords(logs: string): MitmproxyAccessRecord[] {
  const output: MitmproxyAccessRecord[] = [];
  for (const line of logs.split("\n")) {
    const start = line.indexOf('{"event":"request-complete"');
    if (start < 0) continue;
    let value: Record<string, unknown>;
    try {
      value = JSON.parse(line.slice(start));
    } catch {
      throw new Error("mitmproxy emitted malformed structured completion JSON");
    }
    const status = Number(value.response_code);
    const duration = Number(value.duration_ms);
    if (
      typeof value.intent_id !== "string" ||
      !idPattern.test(value.intent_id) ||
      typeof value.route_id !== "string" ||
      !idPattern.test(value.route_id) ||
      !Number.isInteger(status) ||
      status < 100 ||
      status > 599 ||
      !Number.isInteger(duration) ||
      duration < 0 ||
      duration > 300_000 ||
      typeof value.completion_recorded !== "boolean"
    )
      throw new Error("mitmproxy emitted a malformed structured completion record");
    output.push({
      event: "request-complete",
      intent_id: value.intent_id,
      route_id: value.route_id,
      response_code: status,
      duration_ms: duration,
      completion_recorded: value.completion_recorded,
    });
  }
  return output;
}

export class MitmproxyConformanceAdapter implements ConformanceAdapter {
  readonly name = "mitmproxy";
  readonly #options: MitmproxyAdapterOptions;
  readonly #docker: string;
  readonly #stateRoot: string;
  readonly #runId = randomUUID().replaceAll("-", "");
  readonly #records: MitmproxyAccessRecord[] = [];
  #active: ActiveCase | undefined;

  constructor(options: MitmproxyAdapterOptions) {
    if (!Number.isInteger(options.listenerPort) || options.listenerPort < 1024 || options.listenerPort > 65535)
      throw new Error("mitmproxy listener port is invalid");
    if (options.sensitiveValues?.some((value) => value.length === 0))
      throw new Error("sensitive values must not be empty");
    this.#options = options;
    this.#docker = options.dockerCommand ?? "docker";
    this.#stateRoot = options.stateRoot ?? tmpdir();
  }

  accessRecords(): readonly MitmproxyAccessRecord[] {
    return Object.freeze(structuredClone(this.#records));
  }

  async execute(test: Readonly<ConformanceCase>, signal: AbortSignal): Promise<AdapterResult> {
    if (this.#active) throw new Error("mitmproxy adapter already has an active case");
    await mkdir(this.#stateRoot, { recursive: true, mode: 0o700 });
    const directory = await mkdtemp(join(this.#stateRoot, "cogs-mitmproxy-"));
    const configDirectory = join(directory, "config");
    const stateDirectory = join(directory, "state");
    await Promise.all([mkdir(configDirectory, { mode: 0o700 }), mkdir(stateDirectory, { mode: 0o700 })]);
    await Promise.all([
      writeFile(join(configDirectory, "policy.json"), renderMitmproxyPolicy(await this.#options.policyFor(test)), {
        mode: 0o400,
        flag: "wx",
      }),
      writeFile(join(configDirectory, "upstream-ca.pem"), this.#options.upstreamCaCertificatePem, {
        mode: 0o400,
        flag: "wx",
      }),
      readFile(join(here, "addon.py")).then((source) =>
        writeFile(join(configDirectory, "addon.py"), source, { mode: 0o400, flag: "wx" }),
      ),
    ]);
    const container = `cogs-mitmproxy-${this.#runId.slice(0, 12)}-${test.id.replaceAll(/[^A-Za-z0-9_.-]/g, "-")}`;
    this.#active = { container, directory, started: false };
    const user =
      typeof process.getuid === "function"
        ? `${process.getuid()}:${process.getgid?.() ?? process.getuid()}`
        : "65532:65532";
    await runFile(
      this.#docker,
      [
        "run",
        "--detach",
        "--name",
        container,
        "--label",
        `dev.cogs.mitmproxy-adapter=${this.#runId}`,
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
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--mount",
        `type=bind,src=${configDirectory},dst=/cogs,readonly`,
        "--mount",
        `type=bind,src=${stateDirectory},dst=/state`,
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,noexec,size=32m",
        MITMPROXY_IMAGE,
        "mitmdump",
        "--quiet",
        "--listen-host",
        "0.0.0.0",
        "--listen-port",
        String(this.#options.listenerPort),
        "--set",
        "confdir=/state",
        "--set",
        "connection_strategy=lazy",
        "--set",
        "ssl_verify_upstream_trusted_ca=/cogs/upstream-ca.pem",
        "--set",
        "cogs_policy=/cogs/policy.json",
        "--scripts",
        "/cogs/addon.py",
      ],
      30_000,
      signal,
    );
    if (this.#active) this.#active.started = true;
    try {
      await waitForListener(this.#options.listenerPort, signal);
    } catch {
      const logs = await runFile(this.#docker, ["logs", container], 15_000);
      let diagnostic = `${logs.stdout}\n${logs.stderr}`.trim();
      for (const secret of this.#options.sensitiveValues ?? [])
        diagnostic = diagnostic.replaceAll(secret, "[redacted]");
      throw new Error(`mitmproxy listener readiness failed${diagnostic ? `: ${diagnostic.slice(-2048)}` : ""}`);
    }
    const publicCaPath = join(stateDirectory, "mitmproxy-ca-cert.pem");
    const ca = await readFile(publicCaPath, "utf8");
    if (!ca.includes("BEGIN CERTIFICATE") || ca.includes("PRIVATE KEY"))
      throw new Error("mitmproxy public CA output is invalid");

    const plan = this.#options.commandFor(test, {
      proxyOrigin: `http://127.0.0.1:${this.#options.listenerPort}`,
      publicCaPath,
    });
    const result = await runFile(plan.command, plan.args, Math.max(100, test.timeout_ms - 100), signal, {
      ...process.env,
      ...plan.env,
    });
    const combined = `${result.stdout}\n${result.stderr}`;
    if (this.#options.sensitiveValues?.some((secret) => combined.includes(secret)))
      return { passed: false, diagnosticsRedacted: "external case command exposed a sensitive value" };
    if (result.stderr.trim())
      return { passed: false, diagnosticsRedacted: "external case command wrote unexpected diagnostics" };
    await delay(50, undefined, { signal });
    await this.#captureLogs();
    return parseExternalCaseResult(result.stdout.trim());
  }

  async cleanup(): Promise<void> {
    await this.#cleanupActive();
  }

  async teardown(): Promise<void> {
    await this.#cleanupActive();
    const filter = `label=dev.cogs.mitmproxy-adapter=${this.#runId}`;
    const listed = await runFile(this.#docker, ["container", "ls", "--all", "--quiet", "--filter", filter], 15_000);
    for (const container of listed.stdout.trim().split("\n").filter(Boolean))
      await runFile(this.#docker, ["container", "rm", "--force", container], 15_000);
    const verified = await runFile(this.#docker, ["container", "ls", "--all", "--quiet", "--filter", filter], 15_000);
    if (verified.stdout.trim()) throw new Error("mitmproxy teardown left labelled containers behind");
  }

  async #captureLogs(): Promise<void> {
    if (!this.#active?.started) return;
    const logs = await runFile(this.#docker, ["logs", this.#active.container], 15_000);
    const combined = `${logs.stdout}\n${logs.stderr}`;
    if (this.#options.sensitiveValues?.some((secret) => combined.includes(secret)))
      throw new Error("mitmproxy logs contained a configured sensitive value");
    const known = new Set(this.#records.map((record) => `${record.intent_id}:${record.route_id}`));
    for (const record of parseRecords(combined)) {
      const key = `${record.intent_id}:${record.route_id}`;
      if (!known.has(key)) {
        this.#records.push(record);
        known.add(key);
      }
    }
  }

  async #cleanupActive(): Promise<void> {
    const active = this.#active;
    if (!active) return;
    try {
      if (active.started) {
        await this.#captureLogs();
        await runFile(this.#docker, ["stop", "--time", "3", active.container], 10_000);
        await runFile(this.#docker, ["container", "rm", active.container], 15_000);
        const exists = await runFile(
          this.#docker,
          ["container", "ls", "--all", "--quiet", "--filter", `name=^/${active.container}$`],
          15_000,
        );
        if (exists.stdout.trim()) throw new Error("mitmproxy cleanup did not remove its container");
      }
      await rm(active.directory, { recursive: true, force: true });
      try {
        await stat(active.directory);
        throw new Error("mitmproxy cleanup retained CA private state");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      this.#active = undefined;
    } catch (error) {
      throw new Error(error instanceof Error ? error.message : "mitmproxy cleanup failed");
    }
  }
}
