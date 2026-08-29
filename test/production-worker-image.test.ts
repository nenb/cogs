import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const dockerfile = readFileSync(join(root, "images/worker/Dockerfile"), "utf8");
const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
};
const buildConfig = JSON.parse(readFileSync(join(root, "tsconfig.build.json"), "utf8")) as {
  include: string[];
  exclude: string[];
  compilerOptions: Record<string, unknown>;
};

const nodeImage =
  "docker.io/library/node:22.22.2-bookworm-slim@sha256:9f6d5975c7dca860947d3915877f85607946403fc55349f39b4bc3688448bb6e";
const envoyImage = "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb";
const finalImage =
  "gcr.io/distroless/nodejs22-debian13:nonroot@sha256:4e4fb0ce55fd73901600796ef079a9490369d2515d7da31633a91608c82ca13b";

function filesBelow(path: string): string[] {
  const output: string[] = [];
  const visit = (current: string) => {
    for (const name of readdirSync(current).sort()) {
      const absolute = join(current, name);
      if (statSync(absolute).isDirectory()) visit(absolute);
      else output.push(relative(path, absolute));
    }
  };
  visit(path);
  return output;
}

function emit(outDir: string): void {
  const result = spawnSync(
    process.execPath,
    [join(root, "node_modules/typescript/bin/tsc"), "--project", join(root, "tsconfig.build.json"), "--outDir", outDir],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
}

test("worker uses exact pinned linux/amd64 Node, Envoy, and compatible distroless stages", () => {
  assert.match(
    dockerfile,
    new RegExp(`^FROM --platform=linux/amd64 ${nodeImage.replaceAll("/", "\\/")} AS node-runtime$`, "mu"),
  );
  assert.match(
    dockerfile,
    new RegExp(`^FROM --platform=linux/amd64 ${envoyImage.replaceAll("/", "\\/")} AS envoy-runtime$`, "mu"),
  );
  assert.match(
    dockerfile,
    new RegExp(`^FROM --platform=linux/amd64 ${finalImage.replaceAll("/", "\\/")} AS worker$`, "mu"),
  );
  assert.match(dockerfile, /COPY --from=node-runtime[^\n]*\/usr\/local\/bin\/node \/nodejs\/bin\/node/u);
  assert.match(dockerfile, /COPY --from=envoy-runtime[^\n]*\/usr\/local\/bin\/envoy \/usr\/local\/bin\/envoy/u);
  assert.match(dockerfile, /process\.version !== 'v22\.22\.2'/u);
  assert.match(dockerfile, /affffb8d08a14fdc375b1f7dd8d0f3004eacdf51ce07f5636d7e168a01c6b373/u);
  assert.match(dockerfile, /spawnSync\('\/usr\/local\/bin\/envoy', \['--version'\]/u);
  assert.ok(dockerfile.includes("1\\\\.38\\\\.3"));
});

test("worker final stage is nonroot, read-only-root compatible, and starts the fixed emitted entry", () => {
  assert.match(
    dockerfile,
    /ENV NODE_ENV=production[\s\S]*HOME=\/tmp[\s\S]*TMPDIR=\/tmp[\s\S]*XDG_CACHE_HOME=\/tmp\/\.cache/u,
  );
  assert.match(dockerfile, /^USER 65532:65532$/mu);
  assert.match(dockerfile, /^ENTRYPOINT \["\/nodejs\/bin\/node"\]$/mu);
  assert.match(dockerfile, /^CMD \["\/opt\/cogs\/dist\/src\/main\.js"\]$/mu);
  assert.doesNotMatch(dockerfile, /stage0-scaffold|production-ready="true"|runtime-qualified/iu);
  for (const label of [
    'dev.cogs.profile="production-worker-release-candidate"',
    'dev.cogs.source-kind="local-source"',
    'dev.cogs.runtime-qualification="none"',
    'dev.cogs.production-ready="false"',
  ]) {
    assert.ok(dockerfile.includes(label), label);
  }
});

test("worker installs without lifecycle scripts and copies only production runtime material into the final stage", () => {
  assert.equal((dockerfile.match(/npm ci[^\n]*--ignore-scripts/gu) ?? []).length, 2);
  assert.match(dockerfile, /npm ci --omit=dev --ignore-scripts/u);
  assert.equal(packageJson.dependencies["@earendil-works/pi-agent-core"], "0.84.2");
  assert.equal(packageJson.dependencies["@earendil-works/pi-ai"], "0.84.2");
  assert.equal(packageJson.dependencies["@earendil-works/pi-coding-agent"], "0.84.2");
  assert.equal(packageJson.dependencies["brace-expansion"], undefined);
  assert.equal(packageJson.dependencies.undici, undefined);
  assert.match(dockerfile, /Pi 0\.84\.2's authenticated shrinkwrap/u);
  for (const packageName of ["pi-agent-core", "pi-ai", "pi-coding-agent"]) {
    assert.match(
      dockerfile,
      new RegExp(
        `node_modules/@earendil-works/${packageName}/package\\.json[\\s\\S]*version\\)'\\)" = 0\\.84\\.2`,
        "u",
      ),
    );
  }
  assert.match(
    dockerfile,
    /node_modules\/@earendil-works\/pi-coding-agent\/node_modules\/brace-expansion\/package\.json[\s\S]*version\)'\)" = 5\.0\.9/u,
  );
  assert.match(
    dockerfile,
    /node_modules\/@earendil-works\/pi-coding-agent\/node_modules\/undici\/package\.json[\s\S]*version\)'\)" = 8\.9\.0/u,
  );
  assert.match(
    dockerfile,
    /node_modules\/@earendil-works\/pi-coding-agent\/node_modules\/protobufjs\/package\.json[\s\S]*version\)'\)" = 7\.6\.5/u,
  );
  assert.doesNotMatch(dockerfile, /cp -a node_modules\/(?:brace-expansion|undici)|= (?:5\.0\.6|8\.5\.0)/u);
  assert.match(dockerfile, /rm -rf node_modules\/\.bin node_modules\/\.cache/u);
  const finalStage = dockerfile.slice(dockerfile.indexOf(`FROM --platform=linux/amd64 ${finalImage}`));
  assert.doesNotMatch(finalStage, /\b(?:apt|apt-get|apk|dnf|yum|npm|npx|tsc)\b|\/bin\/(?:ba)?sh/u);
  assert.doesNotMatch(
    finalStage,
    /COPY[^\n]*(?:dev\/|scripts\/|spikes\/|test\/|src\/|tsconfig|package-lock|\.env|\.git)/u,
  );
  assert.match(
    dockerfile,
    /COPY schemas\/integration-v1alpha1\.json schemas\/launch-v1alpha1\.json schemas\/runtime-v1alpha1\.json \.\/schemas\//u,
  );
  assert.doesNotMatch(dockerfile, /COPY schemas\/\s|COPY schemas\/\.\//u);
  assert.match(dockerfile, /ext_authz\.descriptor\.pb third_party\/envoy-ext-authz-v1\.38\.3\/manifest\.json/u);
  assert.match(dockerfile, /third_party\/envoy-ext-authz-v1\.38\.3\/LICENSES\//u);
  assert.doesNotMatch(dockerfile, /envoy-ext-authz-v1\.38\.3\/(?:protos|README|ext_authz\.descriptor\.sha256)/u);
});

test("production build emits a byte-reproducible main closure with rewritten bounded imports", () => {
  assert.equal(packageJson.scripts.build, "rm -rf dist && tsc --project tsconfig.build.json");
  assert.deepEqual(buildConfig.include, ["src/main.ts"]);
  assert.deepEqual(buildConfig.exclude, ["dev", "scripts", "spikes", "test"]);
  assert.equal(buildConfig.compilerOptions.noEmit, false);
  assert.equal(buildConfig.compilerOptions.noEmitOnError, true);
  assert.equal(buildConfig.compilerOptions.rewriteRelativeImportExtensions, true);
  assert.equal(buildConfig.compilerOptions.rootDir, ".");
  assert.equal(buildConfig.compilerOptions.outDir, "./dist");
  assert.equal(buildConfig.compilerOptions.sourceMap, false);
  assert.equal(buildConfig.compilerOptions.incremental, false);

  const temporary = mkdtempSync(join(tmpdir(), "cogs-worker-emit-"));
  const first = join(temporary, "first");
  const second = join(temporary, "second");
  try {
    emit(first);
    emit(second);
    const firstFiles = filesBelow(first);
    assert.deepEqual(firstFiles, filesBelow(second));
    assert.ok(firstFiles.includes("src/main.js"));
    assert.deepEqual(
      firstFiles.filter((path) => path.startsWith("schemas/")),
      ["schemas/integration-v1alpha1.json", "schemas/launch-v1alpha1.json", "schemas/runtime-v1alpha1.json"],
    );
    assert.ok(firstFiles.every((path) => path.endsWith(".js") || path.endsWith(".json")));
    for (const path of firstFiles) {
      const firstBytes = readFileSync(join(first, path));
      assert.deepEqual(firstBytes, readFileSync(join(second, path)), path);
      if (!path.endsWith(".js")) continue;
      const source = firstBytes.toString("utf8");
      assert.doesNotMatch(source, /(?:from\s+|import\s*\()(["'])[^"']*\.ts\1/u, path);
      assert.doesNotMatch(source, /(?:^|\/)\.(?:\.\/)+(?:dev|scripts|spikes|test)(?:\/|$)/u, path);
      for (const match of source.matchAll(/(?:from\s+|import\s*\()(["'])(\.[^"']+)\1/gu)) {
        const target = resolve(dirname(join(first, path)), match[2] as string);
        assert.equal(statSync(target).isFile(), true, `${path}: ${match[2]}`);
      }
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});

test("Docker context is deny-by-default and admits no source proto tree or secret-shaped files", () => {
  const lines = readFileSync(join(root, ".dockerignore"), "utf8").trim().split("\n");
  assert.equal(lines[0], "**");
  for (const required of [
    "!src/**",
    "!schemas/integration-v1alpha1.json",
    "!schemas/launch-v1alpha1.json",
    "!schemas/runtime-v1alpha1.json",
    "!third_party/envoy-ext-authz-v1.38.3/ext_authz.descriptor.pb",
    "!third_party/envoy-ext-authz-v1.38.3/manifest.json",
    "!third_party/envoy-ext-authz-v1.38.3/LICENSES/**",
  ]) {
    assert.ok(lines.includes(required), required);
  }
  assert.equal(
    lines.some((line) => /^!.*(?:protos|\.env|\.pem|\.key|secrets?|node_modules|dist)(?:\/|$)/iu.test(line)),
    false,
  );
});
