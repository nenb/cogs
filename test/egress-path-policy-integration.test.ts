import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { type TestContext, test } from "node:test";
import { type CogsEgressRoute, compilePathMatch, createEgressPathMatcher } from "../src/egress/route-policy.ts";

function matcher(
  pattern: string,
  strategy: CogsEgressRoute["pathStrategy"],
  queryPolicy: CogsEgressRoute["queryPolicy"] = { mode: "deny" },
) {
  const route: CogsEgressRoute = Object.freeze({
    integrationId: "fixture",
    ruleName: "fixture",
    routeId: "fixture",
    host: "fixture.invalid",
    port: 443,
    method: "GET",
    pathPattern: pattern,
    pathStrategy: strategy,
    queryPolicy,
    pathMatch: compilePathMatch(pattern, strategy, queryPolicy),
    injectAuth: false,
    credentialRequired: false,
  });
  return createEgressPathMatcher(route);
}

function requireCommand(t: TestContext, command: string, args: readonly string[] = ["--version"]): boolean {
  const result = spawnSync(command, args, { stdio: "ignore", timeout: 5_000 });
  if (result.error || result.status === null) {
    t.skip(`${command} unavailable`);
    return false;
  }
  return true;
}

async function captureFirstTarget(command: string, arguments_: readonly string[]): Promise<string> {
  let settle: ((value: string) => void) | undefined;
  let reject: ((error: Error) => void) | undefined;
  const target = new Promise<string>((resolve, rejectTarget) => {
    settle = resolve;
    reject = rejectTarget;
  });
  const server = createServer((request, response) => {
    const raw = request.url;
    response.statusCode = 404;
    response.setHeader("content-type", "text/plain");
    response.end("fixture not found\n");
    if (raw !== undefined) settle?.(raw);
  });
  await new Promise<void>((resolve, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("fixture unavailable");
  const origin = `http://127.0.0.1:${address.port}`;
  const child = spawn(
    command,
    arguments_.map((value) => value.replaceAll("FIXTURE_ORIGIN", origin)),
    {
      stdio: "ignore",
      env: {
        HOME: process.env.HOME,
        PATH: process.env.PATH,
        NO_PROXY: "127.0.0.1,localhost",
        no_proxy: "127.0.0.1,localhost",
        HTTP_PROXY: "",
        HTTPS_PROXY: "",
        ALL_PROXY: "",
      },
    },
  );
  child.once("error", (error) => reject?.(error));
  const timer = setTimeout(() => reject?.(new Error("real client path timeout")), 10_000);
  try {
    return await target;
  } finally {
    clearTimeout(timer);
    child.kill("SIGKILL");
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) resolve();
      else child.once("exit", () => resolve());
    });
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test("real Git smart-HTTP target is accepted without decoding or normalization", async (t) => {
  if (!requireCommand(t, "git")) return;
  const target = await captureFirstTarget("git", [
    "-c",
    "credential.helper=",
    "-c",
    "http.followRedirects=false",
    "ls-remote",
    "FIXTURE_ORIGIN/owner/repo.git",
  ]);
  assert.equal(target, "/owner/repo.git/info/refs?service=git-upload-pack");
  const matches = matcher("/*/*.git/info/refs", "segment-glob", {
    mode: "exact",
    values: ["service=git-upload-pack"],
    canonical: "service=git-upload-pack",
  });
  assert.equal(matches(target), true);
});

test("real npm unscoped metadata target is accepted and scoped encoding is explicitly unsupported", async (t) => {
  if (!requireCommand(t, "npm")) return;
  const unscoped = await captureFirstTarget("npm", [
    "view",
    "fixture-package",
    "--registry=FIXTURE_ORIGIN",
    "--fetch-retries=0",
    "--fetch-timeout=2000",
    "--ignore-scripts",
  ]);
  assert.equal(unscoped, "/fixture-package");
  assert.equal(matcher("/*", "segment-glob")(unscoped), true);

  const scoped = await captureFirstTarget("npm", [
    "view",
    "@fixture/package",
    "--registry=FIXTURE_ORIGIN",
    "--fetch-retries=0",
    "--fetch-timeout=2000",
    "--ignore-scripts",
  ]);
  assert.match(scoped, /^\/@fixture%2[fF]package$/);
  assert.equal(matcher("/*", "segment-glob")(scoped), false);
});

test("real pip simple-index target is accepted as raw ASCII", async (t) => {
  if (!requireCommand(t, "python3", ["-m", "pip", "--version"])) return;
  const target = await captureFirstTarget("python3", [
    "-m",
    "pip",
    "index",
    "versions",
    "fixture-package",
    "--index-url",
    "FIXTURE_ORIGIN/simple",
    "--no-cache-dir",
    "--retries",
    "0",
    "--timeout",
    "2",
    "--trusted-host",
    "127.0.0.1",
  ]);
  assert.equal(target, "/simple/fixture-package/");
  assert.equal(matcher("/simple/*/", "segment-glob")(target), true);
});
