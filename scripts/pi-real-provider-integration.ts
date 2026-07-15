import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { type CogsPiSessionOptions, type CogsToolPorts, createCogsPiSession } from "../src/pi/session.ts";

const enabled = process.env.COGS_PI_REAL_PROVIDER_INTEGRATION === "1";
const apiKey = process.env.COGS_PI_ANTHROPIC_API_KEY;

if (!enabled) throw new Error("set COGS_PI_REAL_PROVIDER_INTEGRATION=1 to run this opt-in integration");
if (!apiKey) throw new Error("set COGS_PI_ANTHROPIC_API_KEY; the value is never printed or persisted by this script");

function withDefaults(
  options: Omit<CogsPiSessionOptions, "emit" | "onFatal"> & Partial<Pick<CogsPiSessionOptions, "emit" | "onFatal">>,
): CogsPiSessionOptions {
  return { emit: () => true, onFatal: () => undefined, ...options };
}

const ports: CogsToolPorts = {
  read: async () => ({ ok: true, content: "real-provider integration read stub" }),
  write: async () => ({ ok: true }),
  edit: async () => ({ ok: true }),
  bash: async () => ({ ok: true, exit_code: 0, stdout: "" }),
};

const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-real-provider-"));
try {
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  await mkdir(cwd, { recursive: true });
  await mkdir(agentDir, { recursive: true });
  const adapter = await createCogsPiSession(
    withDefaults({
      cwd,
      agentDir,
      sessionId: "real-provider-integration",
      model: { provider: "anthropic", id: process.env.COGS_PI_MODEL ?? "claude-sonnet-4-5" },
      apiKey,
      sessionRoot: sessionDir,
      toolPorts: ports,
      operationTimeoutMs: 120_000,
    }),
  );
  try {
    await adapter.input({
      requestId: "real-provider-request",
      correlationId: "real-provider-correlation",
      kind: "prompt",
      content: "Reply with one short sentence confirming the Cogs Pi adapter is reachable. Do not call tools.",
    });
    await new Promise((resolveTimer, reject) => {
      const deadline = Date.now() + 120_000;
      const poll = async () => {
        const state = await adapter.state();
        if (state.runState === "settled") return resolveTimer(undefined);
        if (Date.now() > deadline) return reject(new Error("real-provider integration timed out"));
        setTimeout(poll, 250);
      };
      poll().catch(reject);
    });
    console.log("Pi real-provider integration completed without printing credentials.");
  } finally {
    await adapter.dispose();
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
