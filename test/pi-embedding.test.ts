import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { DefaultResourceLoader, SessionManager, SettingsManager } from "@earendil-works/pi-coding-agent";
import { createSpikeSession, SPIKE_API_KEY, SPIKE_TOOL_NAMES } from "../spikes/pi-embedding.ts";

const execFileAsync = promisify(execFile);
const root = resolve(import.meta.dirname, "..");
const fixtures = resolve(root, "test/fixtures/hostile-discovery");

async function installHostileCanaries(cwd: string, agentDir: string): Promise<void> {
  const projectExtension = resolve(cwd, ".pi/extensions/canary.js");
  const globalExtension = resolve(agentDir, "extensions/canary.js");
  const projectPackage = resolve(cwd, "hostile-project-package");
  const globalPackage = resolve(agentDir, "hostile-global-package");

  await mkdir(dirname(projectExtension), { recursive: true });
  await mkdir(dirname(globalExtension), { recursive: true });
  await cp(resolve(fixtures, "project-extension/canary.js"), projectExtension);
  await cp(resolve(fixtures, "global-extension/canary.js"), globalExtension);
  await cp(resolve(fixtures, "project-package"), projectPackage, { recursive: true });
  await cp(resolve(fixtures, "global-package"), globalPackage, { recursive: true });

  await writeFile(
    resolve(cwd, ".pi/settings.json"),
    JSON.stringify({ extensions: [projectExtension], packages: [projectPackage] }),
  );
  await writeFile(
    resolve(agentDir, "settings.json"),
    JSON.stringify({ extensions: [globalExtension], packages: [globalPackage] }),
  );
}

async function assertMissing(path: string, message: string): Promise<void> {
  await assert.rejects(readFile(path, "utf8"), { code: "ENOENT" }, message);
}

test("headless Pi embedding uses only four stubs, ignores hostile discovery, and preserves native JSONL", async () => {
  const temporaryRoot = await mkdtemp(resolve(tmpdir(), "cogs-pi-spike-"));
  const cwd = resolve(temporaryRoot, "workspace");
  const agentDir = resolve(temporaryRoot, "agent");
  const sessionDir = resolve(temporaryRoot, "sessions");
  const marker = resolve(temporaryRoot, "CANARY_EXECUTED");
  const priorMarker = process.env.COGS_CANARY_MARKER;
  process.env.COGS_CANARY_MARKER = marker;

  try {
    await mkdir(cwd, { recursive: true });
    await mkdir(agentDir, { recursive: true });
    await installHostileCanaries(cwd, agentDir);

    const sessionManager = SessionManager.create(cwd, sessionDir);
    const { session, authStorage, fakeModelState, executedTools } = await createSpikeSession(
      sessionManager,
      cwd,
      agentDir,
    );

    try {
      assert.deepEqual(
        session.agent.state.tools.map((tool) => tool.name).sort(),
        [...SPIKE_TOOL_NAMES].sort(),
        "the trusted worker must expose exactly the four Cogs tools",
      );
      assert.equal(authStorage.getAuthStatus("anthropic").source, "runtime");
      assert.equal(await authStorage.getApiKey("anthropic"), SPIKE_API_KEY);

      await assertMissing(marker, "resource construction must not execute discovery canaries");
      await session.prompt("Use read once, then finish.");
      await assertMissing(marker, "prompt execution must not execute discovery canaries");

      assert.deepEqual(executedTools, ["read"], "the fake model must execute the harmless custom read stub");
      const manualArguments: Record<string, Record<string, string>> = {
        write: { path: "/workspace/proof.txt", content: "harmless" },
        edit: { path: "/workspace/proof.txt", oldText: "old", newText: "new" },
        bash: { command: "printf harmless" },
      };
      for (const name of ["write", "edit", "bash"] as const) {
        const tool = session.agent.state.tools.find((candidate) => candidate.name === name);
        assert.ok(tool, `custom ${name} tool must be active`);
        const result = await tool.execute(`manual-${name}`, manualArguments[name]);
        assert.deepEqual(result.details, { stub: true }, `${name} must resolve to the harmless SDK stub`);
      }
      assert.deepEqual(executedTools, ["read", "write", "edit", "bash"]);
      assert.equal(fakeModelState.calls, 2, "the fake model should run once before and once after the tool result");
      assert.deepEqual(fakeModelState.observedApiKeys, [SPIKE_API_KEY, SPIKE_API_KEY]);
      await assertMissing(
        resolve(agentDir, "auth.json"),
        "runtime-only authentication must not create persistent auth state",
      );
    } finally {
      session.dispose();
    }

    const sessionFile = sessionManager.getSessionFile();
    assert.ok(sessionFile, "persistent SessionManager must expose a JSONL file");
    const originalJsonl = await readFile(sessionFile, "utf8");
    assert.equal(originalJsonl.includes(SPIKE_API_KEY), false, "runtime API keys must not enter native JSONL");

    const reopened = SessionManager.open(sessionFile, sessionDir);
    assert.equal(await readFile(sessionFile, "utf8"), originalJsonl, "opening native JSONL must not rewrite its bytes");
    const header = reopened.getHeader();
    assert.ok(header, "native JSONL must contain a session header");
    assert.equal(header.version, 3);
    const originalEntries = reopened.getEntries();
    const firstUser = originalEntries.find((entry) => entry.type === "message" && entry.message.role === "user");
    assert.ok(firstUser, "native JSONL must contain the prompt entry");
    const originalLeaf = reopened.getLeafId();
    assert.ok(originalLeaf, "native JSONL must have a leaf");

    reopened.branch(firstUser.id);
    assert.equal(reopened.getLeafId(), firstUser.id, "SessionManager must navigate to an earlier branch point");
    const alternateLeaf = reopened.appendCustomEntry("cogs.stage0-branch-proof", { harmless: true });
    assert.notEqual(alternateLeaf, originalLeaf);

    const roundTripped = SessionManager.open(sessionFile, sessionDir);
    roundTripped.branch(originalLeaf);
    assert.equal(roundTripped.getLeafId(), originalLeaf, "the original branch must survive append-only round-trip");
    roundTripped.branch(alternateLeaf);
    assert.equal(roundTripped.getLeafId(), alternateLeaf, "the alternate branch must survive append-only round-trip");

    const htmlOutput = resolve(temporaryRoot, "session.html");
    const piCli = resolve(root, "node_modules/.bin/pi");
    await execFileAsync(piCli, ["--export", sessionFile, htmlOutput], {
      cwd,
      env: {
        ...process.env,
        PI_CODING_AGENT_DIR: agentDir,
        PI_OFFLINE: "1",
        PI_TELEMETRY: "0",
        PI_SKIP_VERSION_CHECK: "1",
      },
      timeout: 30_000,
    });
    assert.match(await readFile(htmlOutput, "utf8"), /<!DOCTYPE html>/i);
    await assertMissing(marker, "the pinned Pi CLI export path must not execute discovery canaries");

    const discoverySettings = SettingsManager.create(cwd, agentDir, { projectTrusted: true });
    const positiveControlLoader = new DefaultResourceLoader({ cwd, agentDir, settingsManager: discoverySettings });
    await positiveControlLoader.reload({ resolveProjectTrust: async () => true });
    const discoveredExtensions = positiveControlLoader.getExtensions();
    assert.equal(
      discoveredExtensions.errors.length,
      0,
      "positive-control discovery must load every hostile extension cleanly",
    );
    assert.ok(discoveredExtensions.extensions.length >= 4, "the pinned default loader must discover all four canaries");
    const markerContents = await readFile(marker, "utf8");
    for (const expected of ["project-extension", "global-extension", "project-package", "global-package"]) {
      assert.match(markerContents, new RegExp(expected), `${expected} canary must execute when explicitly imported`);
    }
  } finally {
    if (priorMarker === undefined) delete process.env.COGS_CANARY_MARKER;
    else process.env.COGS_CANARY_MARKER = priorMarker;
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});
