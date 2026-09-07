import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type TestContext, test } from "node:test";
import { type CogsEgressRoute, compilePathMatch, createEgressPathMatcher } from "../src/egress/route-policy.ts";

// Real Git/npm/pip, but ONLY a Node HTTP fixture applying preset path matchers.
// No Envoy, CONNECT, TLS, production authz, cgroup or streaming/resource-bound evidence.
// In particular this npm result does not supersede Stage 1's CONNECT-auth incompatibility.
function requireCommand(t: TestContext, command: string): boolean {
  const result = spawnSync(command, ["--version"], { stdio: "ignore", timeout: 5_000 });
  if ((result.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
    t.skip(`${command} unavailable`);
    return false;
  }
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${command} --version failed`);
  return true;
}

// Only PATH is inherited: no user Git/npm/pip configuration, credentials, proxies, or caches.
function environment(root: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    HOME: root,
    XDG_CONFIG_HOME: root,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: join(root, "empty-config"),
    GIT_TERMINAL_PROMPT: "0",
    GIT_ALLOW_PROTOCOL: "http",
    GIT_AUTHOR_NAME: "Fixture",
    GIT_AUTHOR_EMAIL: "fixture@example.invalid",
    GIT_COMMITTER_NAME: "Fixture",
    GIT_COMMITTER_EMAIL: "fixture@example.invalid",
    npm_config_userconfig: join(root, "empty-config"),
    npm_config_globalconfig: join(root, "empty-global-config"),
    npm_config_cache: join(root, "npm-cache"),
    PIP_CONFIG_FILE: "/dev/null",
    PIP_DISABLE_PIP_VERSION_CHECK: "1",
    NO_PROXY: "127.0.0.1,localhost",
    no_proxy: "127.0.0.1,localhost",
  };
}

async function run(root: string, command: string, args: string[], input?: Buffer, expectedSuccess = true) {
  const child = spawn(command, args, { cwd: root, env: environment(root), stdio: "pipe" });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (data: Buffer) => stdout.push(data));
  child.stderr.on("data", (data: Buffer) => stderr.push(data));
  child.stdin.on("error", () => {});
  child.stdin.end(input);
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, 30_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("close", resolve);
    });
    assert.equal(timedOut, false, `${command} timed out`);
    if (expectedSuccess) assert.equal(code, 0, `${command} ${args.join(" ")}: ${Buffer.concat(stderr)}`);
    else assert.notEqual(code, 0, `${command} unexpectedly succeeded`);
    return Buffer.concat(stdout);
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  }
}

interface PresetRule {
  name: string;
  host: string;
  port: number;
  methods: string[];
  path_patterns: string[];
  path_policy: { strategy: CogsEgressRoute["pathStrategy"] };
  query_policy: { mode: "deny" } | { mode: "exact"; values: string[] };
}

async function presetMatchers(preset: string) {
  const data = JSON.parse(
    await readFile(new URL(`../integrations/presets/${preset}-v1.json`, import.meta.url), "utf8"),
  ) as {
    rules: PresetRule[];
  };
  return data.rules.flatMap((rule) =>
    rule.methods.flatMap((method) =>
      rule.path_patterns.map((pattern) => {
        const queryPolicy: CogsEgressRoute["queryPolicy"] =
          rule.query_policy.mode === "deny"
            ? { mode: "deny" }
            : { ...rule.query_policy, canonical: [...rule.query_policy.values].sort().join("&") };
        return {
          method,
          matches: createEgressPathMatcher({
            integrationId: preset,
            ruleName: rule.name,
            routeId: rule.name,
            host: rule.host,
            port: rule.port,
            method,
            pathPattern: pattern,
            pathStrategy: rule.path_policy.strategy,
            queryPolicy,
            pathMatch: compilePathMatch(pattern, rule.path_policy.strategy, queryPolicy),
            injectAuth: false,
            credentialRequired: false,
          }),
        };
      }),
    ),
  );
}

async function fixture(t: TestContext, preset: string) {
  const root = await mkdtemp(join(tmpdir(), "cogs-real-client-"));
  let closeServer = async () => {};
  t.after(async () => {
    try {
      await closeServer();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  await writeFile(join(root, "empty-config"), "");
  await writeFile(join(root, "empty-global-config"), "");
  const routes = await presetMatchers(preset);
  const requests: string[] = [];
  const rejected: string[] = [];
  const errors: unknown[] = [];
  const pending = new Set<Promise<void>>();
  let serve: (request: IncomingMessage, response: ServerResponse) => Promise<void> = async () => {
    throw new Error("fixture handler missing");
  };
  const server = createServer((request, response) => {
    const target = request.url ?? "";
    const label = `${request.method} ${target}`;
    requests.push(label);
    if (!routes.some((route) => route.method === request.method && route.matches(target))) {
      rejected.push(label);
      response.writeHead(403).end("path policy denied");
      return;
    }
    const task = serve(request, response).catch((error) => {
      errors.push(error);
      response.writeHead(500).end("fixture failed");
    });
    pending.add(task);
    void task.finally(() => pending.delete(task));
  });
  closeServer = async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await Promise.all(pending);
    assert.deepEqual(errors, []);
  };
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return {
    root,
    origin: `http://127.0.0.1:${address.port}`,
    requests,
    rejected,
    routes,
    handle(handler: typeof serve) {
      serve = handler;
    },
  };
}

function assertPaths(actual: string[], expected: string[]) {
  assert.deepEqual([...new Set(actual)].sort(), [...expected].sort());
}

test("real Git completes smart-HTTP clone and incremental fetch through preset matchers", async (t) => {
  if (!requireCommand(t, "git")) return;
  const f = await fixture(t, "github-smart-http");
  const git = (...args: string[]) => run(f.root, "git", ["-c", "protocol.version=0", ...args]);
  const repo = join(f.root, "source");
  const clone = join(f.root, "clone");
  await git("init", "--initial-branch=main", repo);
  await writeFile(join(repo, "fixture.txt"), "first synthetic commit\n");
  await git("-C", repo, "add", "fixture.txt");
  await git("-C", repo, "commit", "-m", "first");
  const refs = "GET /owner/repo.git/info/refs?service=git-upload-pack";
  const upload = "POST /owner/repo.git/git-upload-pack";
  f.handle(async (request, response) => {
    if (`${request.method} ${request.url}` === refs) {
      const advertisement = await git("upload-pack", "--stateless-rpc", "--advertise-refs", repo);
      response.setHeader("content-type", "application/x-git-upload-pack-advertisement");
      response.end(Buffer.concat([Buffer.from("001e# service=git-upload-pack\n0000"), advertisement]));
    } else {
      assert.equal(`${request.method} ${request.url}`, upload);
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      const pack = await run(f.root, "git", ["upload-pack", "--stateless-rpc", repo], Buffer.concat(chunks));
      response.setHeader("content-type", "application/x-git-upload-pack-result");
      response.end(pack);
    }
  });
  await git("clone", `${f.origin}/owner/repo.git`, clone);
  assert.equal(await readFile(join(clone, "fixture.txt"), "utf8"), "first synthetic commit\n");
  assertPaths(f.requests, [refs, upload]);
  f.requests.length = 0;
  await writeFile(join(repo, "fixture.txt"), "second synthetic commit\n");
  await git("-C", repo, "commit", "-am", "second");
  await git("-C", clone, "fetch", "origin");
  assert.equal((await git("-C", clone, "show", "origin/main:fixture.txt")).toString(), "second synthetic commit\n");
  assert.equal(
    (await git("-C", clone, "rev-parse", "origin/main")).toString(),
    (await git("-C", repo, "rev-parse", "HEAD")).toString(),
  );
  assertPaths(f.requests, [refs, upload]);
  assert.deepEqual(f.rejected, []);
});

test("real npm installs an unscoped tarball; scoped percent-encoded targets remain unsupported", async (t) => {
  if (!requireCommand(t, "npm")) return;
  const f = await fixture(t, "npm");
  const source = join(f.root, "package");
  const consumer = join(f.root, "consumer");
  await mkdir(source);
  await mkdir(consumer);
  await writeFile(
    join(source, "package.json"),
    JSON.stringify({ name: "fixture-package", version: "1.0.0", main: "index.js" }),
  );
  await writeFile(join(source, "index.js"), 'module.exports = "synthetic npm content";\n');
  await writeFile(join(consumer, "package.json"), '{"name":"fixture-consumer","version":"1.0.0","private":true}');
  await run(f.root, "npm", ["pack", source, "--ignore-scripts", "--offline"]);
  // npm pack populates its content cache; remove it so installation must fetch the tarball.
  await rm(join(f.root, "npm-cache"), { recursive: true, force: true });
  const tarball = await readFile(join(f.root, "fixture-package-1.0.0.tgz"));
  const tarPath = "/fixture-package/-/fixture-package-1.0.0.tgz";
  f.handle(async (request, response) => {
    if (request.url === "/fixture-package") {
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify({
          name: "fixture-package",
          "dist-tags": { latest: "1.0.0" },
          versions: {
            "1.0.0": {
              name: "fixture-package",
              version: "1.0.0",
              dist: {
                tarball: `${f.origin}${tarPath}`,
                integrity: `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
              },
            },
          },
        }),
      );
    } else {
      assert.equal(request.url, tarPath);
      response.setHeader("content-type", "application/octet-stream");
      response.end(tarball);
    }
  });
  const options = [
    `--registry=${f.origin}`,
    "--fetch-retries=0",
    "--fetch-timeout=5000",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--update-notifier=false",
  ];
  await run(f.root, "npm", ["install", "--prefix", consumer, "fixture-package@1.0.0", ...options]);
  assert.equal(
    (
      await run(f.root, process.execPath, [
        "-e",
        `process.stdout.write(require(${JSON.stringify(join(consumer, "node_modules/fixture-package"))}))`,
      ])
    ).toString(),
    "synthetic npm content",
  );
  assertPaths(f.requests, ["GET /fixture-package", `GET ${tarPath}`]);
  assert.deepEqual(f.rejected, []);
  f.requests.length = 0;
  await run(f.root, "npm", ["view", "@fixture/package", ...options], undefined, false);
  assert.ok(f.requests.length > 0);
  for (const target of f.requests) assert.match(target, /^GET \/@fixture%2[fF]package$/);
  assert.deepEqual(f.rejected, f.requests);
  for (const target of [
    "/@fixture%2fpackage",
    "/@fixture%2Fpackage",
    "/%66ixture-package",
    "/@fixture/package/-/package-1.0.0.tgz",
  ]) {
    assert.equal(
      f.routes.some((route) => route.matches(target)),
      false,
      target,
    );
  }
});

test("real pip installs and imports a synthetic simple-index wheel through preset matchers", async (t) => {
  if (!requireCommand(t, "python3")) return;
  const f = await fixture(t, "pypi");
  // A present Python without pip is a failure, not an unsupported-client skip.
  await run(f.root, "python3", ["-m", "pip", "--version"]);
  const wheelName = "fixture_package-1.0.0-py3-none-any.whl";
  await run(f.root, "python3", [
    "-c",
    `
import base64, csv, hashlib, io, zipfile
files = {
 'fixture_package/__init__.py': b'VALUE = "synthetic pip content"\\n',
 'fixture_package-1.0.0.dist-info/METADATA': b'Metadata-Version: 2.1\\nName: fixture-package\\nVersion: 1.0.0\\n',
 'fixture_package-1.0.0.dist-info/WHEEL': b'Wheel-Version: 1.0\\nGenerator: local-fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n',
}
record = io.StringIO()
writer = csv.writer(record, lineterminator='\\n')
for name, data in files.items():
 writer.writerow([name, 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode(), len(data)])
writer.writerow(['fixture_package-1.0.0.dist-info/RECORD', '', ''])
files['fixture_package-1.0.0.dist-info/RECORD'] = record.getvalue().encode()
with zipfile.ZipFile('${wheelName}', 'w') as wheel:
 for name, data in files.items(): wheel.writestr(name, data)
`,
  ]);
  const wheel = await readFile(join(f.root, wheelName));
  const wheelPath = `/packages/local/${wheelName}`;
  f.handle(async (request, response) => {
    if (request.url === "/simple/fixture-package/") {
      response.setHeader("content-type", "text/html");
      response.end(
        `<a href="${f.origin}${wheelPath}#sha256=${createHash("sha256").update(wheel).digest("hex")}">${wheelName}</a>`,
      );
    } else {
      assert.equal(request.url, wheelPath);
      response.setHeader("content-type", "application/octet-stream");
      response.end(wheel);
    }
  });
  const target = join(f.root, "installed");
  await run(f.root, "python3", [
    "-m",
    "pip",
    "install",
    "fixture-package==1.0.0",
    "--target",
    target,
    "--index-url",
    `${f.origin}/simple`,
    "--trusted-host",
    "127.0.0.1",
    "--no-cache-dir",
    "--no-deps",
    "--only-binary=:all:",
    "--ignore-installed",
    "--retries",
    "0",
    "--timeout",
    "5",
    "--no-input",
  ]);
  assert.equal(
    (
      await run(f.root, "python3", [
        "-I",
        "-c",
        `import sys; sys.path.insert(0, ${JSON.stringify(target)}); import fixture_package; print(fixture_package.VALUE)`,
      ])
    ).toString(),
    "synthetic pip content\n",
  );
  assertPaths(f.requests, ["GET /simple/fixture-package/", `GET ${wheelPath}`]);
  assert.deepEqual(f.rejected, []);
});
