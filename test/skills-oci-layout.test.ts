import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { link, mkdir, mkdtemp, open, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { buildCogsSkillBundle, COGS_SKILLS_BUNDLE_MEDIA_TYPE } from "../src/skills/bundle.ts";
import {
  COGS_OCI_EMPTY_CONFIG_MEDIA_TYPE,
  COGS_OCI_MANIFEST_MEDIA_TYPE,
  CogsSharedSkillOciLayoutError,
  createCogsSharedSkillOciLayoutResolver,
} from "../src/skills/oci-layout.ts";

function sha(bytes: Buffer | string): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function assertInvalid(operation: () => Promise<unknown> | unknown): Promise<void> | void {
  const result = operation();
  const validate = (error: unknown) => {
    assert.ok(error instanceof CogsSharedSkillOciLayoutError);
    assert.equal(error.message, "invalid shared skill OCI layout");
    assert.equal(error.code, "COGS_SHARED_SKILL_OCI_LAYOUT_INVALID");
    assert.equal(String(error).includes("/"), false);
    return true;
  };
  if (result instanceof Promise) return assert.rejects(result, validate);
  assert.fail("operation unexpectedly succeeded");
}

async function withTemp<T>(fn: (root: string) => Promise<T>): Promise<T> {
  const root = await mkdtemp(path.join(tmpdir(), "cogs-oci-"));
  try {
    return await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

async function writeBlob(root: string, digest: `sha256:${string}`, bytes: Buffer | string) {
  const file = path.join(root, "blobs", "sha256", digest.slice("sha256:".length));
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, bytes);
}

function descriptor(mediaType: string, digest: `sha256:${string}`, bytes: Buffer | string, artifactType?: string) {
  return { mediaType, digest, size: Buffer.byteLength(bytes), ...(artifactType === undefined ? {} : { artifactType }) };
}

async function makeLayout(root: string, bundle = buildCogsSkillBundle({ entries: [] })) {
  const configBytes = "{}";
  const configDigest = sha(configBytes);
  const bundleBytes = bundle.copyBytes();
  const manifestObject = {
    schemaVersion: 2,
    mediaType: COGS_OCI_MANIFEST_MEDIA_TYPE,
    artifactType: COGS_SKILLS_BUNDLE_MEDIA_TYPE,
    config: descriptor(COGS_OCI_EMPTY_CONFIG_MEDIA_TYPE, configDigest, configBytes),
    layers: [descriptor(COGS_SKILLS_BUNDLE_MEDIA_TYPE, bundle.digest, bundleBytes)],
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifestObject));
  const manifestDigest = sha(manifestBytes);
  const indexObject = {
    schemaVersion: 2,
    manifests: [descriptor(COGS_OCI_MANIFEST_MEDIA_TYPE, manifestDigest, manifestBytes, COGS_SKILLS_BUNDLE_MEDIA_TYPE)],
  };
  await writeFile(path.join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
  await writeFile(path.join(root, "index.json"), JSON.stringify(indexObject));
  await writeBlob(root, configDigest, configBytes);
  await writeBlob(root, bundle.digest, bundleBytes);
  await writeBlob(root, manifestDigest, manifestBytes);
  return { manifestDigest, bundle, configDigest, manifestBytes, bundleBytes };
}

async function rewriteManifest(root: string, mutate: (manifest: Record<string, unknown>) => void) {
  const index = JSON.parse(await readFile(path.join(root, "index.json"), "utf8"));
  const oldDigest = index.manifests[0].digest as `sha256:${string}`;
  const manifestPath = path.join(root, "blobs", "sha256", oldDigest.slice("sha256:".length));
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  mutate(manifest);
  const manifestBytes = Buffer.from(JSON.stringify(manifest));
  const manifestDigest = sha(manifestBytes);
  await writeBlob(root, manifestDigest, manifestBytes);
  index.manifests[0].digest = manifestDigest;
  index.manifests[0].size = manifestBytes.length;
  await writeFile(path.join(root, "index.json"), JSON.stringify(index));
  return manifestDigest;
}

test("resolves a canonical local OCI layout including empty bundle", async () => {
  await withTemp(async (root) => {
    const { manifestDigest, bundle } = await makeLayout(root);
    const resolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: root });
    const result = await resolver.resolve({ manifestDigest });
    assert.equal(result.scope, "shared");
    assert.equal(result.manifestDigest, manifestDigest);
    assert.equal(result.bundleDigest, bundle.digest);
    assert.equal(result.fileCount, 0);
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(resolver));
  });
});

test("resolves a non-empty bundle and exposes only copy handles", async () => {
  await withTemp(async (root) => {
    const bundle = buildCogsSkillBundle({
      entries: [{ path: "skill.md", executable: false, content: Buffer.from("skill") }],
    });
    const { manifestDigest } = await makeLayout(root, bundle);
    const result = await (await createCogsSharedSkillOciLayoutResolver({ layoutRoot: root })).resolve({
      manifestDigest,
    });
    assert.equal(result.fileCount, 1);
    const copy = result.bundle.copyFile("skill.md");
    copy.fill(0);
    assert.equal(result.bundle.copyFile("skill.md").toString("utf8"), "skill");
  });
});

test("rejects malformed canonical JSON, annotations, extras, duplicate keys, and multiple descriptors", async () => {
  await withTemp(async (root) => {
    const { manifestDigest } = await makeLayout(root);
    const resolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: root });
    await writeFile(path.join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }, null, 2));
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await writeFile(path.join(root, "oci-layout"), JSON.stringify({ imageLayoutVersion: "1.0.0" }));
    const index = JSON.parse(await readFile(path.join(root, "index.json"), "utf8"));
    await writeFile(path.join(root, "index.json"), JSON.stringify({ ...index, annotations: {} }));
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await writeFile(
      path.join(root, "index.json"),
      JSON.stringify({ schemaVersion: 2, manifests: [...index.manifests, index.manifests[0]] }),
    );
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await writeFile(
      path.join(root, "index.json"),
      JSON.stringify(index).replace('"schemaVersion":2', '"schemaVersion":2,"schemaVersion":2'),
    );
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
  });
});

test("rejects wrong digest, size, media type, config, and layer", async () => {
  await withTemp(async (root) => {
    const fixture = await makeLayout(root);
    const resolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: root });
    await assertInvalid(() => resolver.resolve({ manifestDigest: `sha256:${"0".repeat(64)}` }));
    const index = JSON.parse(await readFile(path.join(root, "index.json"), "utf8"));
    index.manifests[0].size += 1;
    await writeFile(path.join(root, "index.json"), JSON.stringify(index));
    await assertInvalid(() => resolver.resolve({ manifestDigest: fixture.manifestDigest }));

    await makeLayout(root);
    let manifestDigest = await rewriteManifest(root, (manifest) => (manifest.mediaType = "bad"));
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    manifestDigest = await rewriteManifest(root, (manifest) => (manifest.artifactType = "bad"));
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    manifestDigest = await rewriteManifest(
      root,
      (manifest) => ((manifest.config as Record<string, unknown>).mediaType = "bad"),
    );
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    const badConfig = "[]";
    const badConfigDigest = sha(badConfig);
    await writeBlob(root, badConfigDigest, badConfig);
    manifestDigest = await rewriteManifest(root, (manifest) => {
      (manifest.config as Record<string, unknown>).digest = badConfigDigest;
      (manifest.config as Record<string, unknown>).size = Buffer.byteLength(badConfig);
    });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    manifestDigest = await rewriteManifest(
      root,
      (manifest) => (((manifest.layers as Record<string, unknown>[])[0] as Record<string, unknown>).mediaType = "bad"),
    );
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    manifestDigest = await rewriteManifest(root, (manifest) => {
      ((manifest.layers as Record<string, unknown>[])[0] as Record<string, unknown>).size = 1;
    });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    manifestDigest = await rewriteManifest(root, (manifest) => {
      ((manifest.layers as Record<string, unknown>[])[0] as Record<string, unknown>).digest =
        `sha256:${"f".repeat(64)}`;
    });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    manifestDigest = await rewriteManifest(root, (manifest) => {
      (manifest.layers as unknown[]).push((manifest.layers as unknown[])[0]);
    });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
    await makeLayout(root);
    manifestDigest = await rewriteManifest(root, (manifest) => (manifest.annotations = {}));
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
  });
});

test("rejects filesystem hazards, races, oversize, abort, and hostile shapes", async () => {
  await withTemp(async (root) => {
    const { manifestDigest } = await makeLayout(root);
    await assertInvalid(() => createCogsSharedSkillOciLayoutResolver({ layoutRoot: "relative" }));
    await assertInvalid(() =>
      createCogsSharedSkillOciLayoutResolver(
        Object.defineProperty({}, "layoutRoot", { enumerable: true, get: () => root }) as never,
      ),
    );
    const symlinkRoot = path.join(path.dirname(root), `${path.basename(root)}-link`);
    await symlink(root, symlinkRoot);
    try {
      await assertInvalid(() => createCogsSharedSkillOciLayoutResolver({ layoutRoot: symlinkRoot }));
    } finally {
      await rm(symlinkRoot, { force: true });
    }
    const controller = new AbortController();
    controller.abort();
    await assertInvalid(() =>
      createCogsSharedSkillOciLayoutResolver({ layoutRoot: root }).then((r) =>
        r.resolve({ manifestDigest, signal: controller.signal }),
      ),
    );
    await rm(path.join(root, "index.json"));
    await symlink("oci-layout", path.join(root, "index.json"));
    const resolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: root });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
  });
  await withTemp(async (root) => {
    const { manifestDigest } = await makeLayout(root);
    const index = path.join(root, "index.json");
    await link(index, path.join(root, "index-hard"));
    const resolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: root });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
  });
  await withTemp(async (root) => {
    const { manifestDigest } = await makeLayout(root);
    await writeFile(path.join(root, "index.json"), Buffer.alloc(2048));
    const resolver = await createCogsSharedSkillOciLayoutResolver({ layoutRoot: root });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
  });
  await withTemp(async (root) => {
    const { manifestDigest } = await makeLayout(root);
    let calls = 0;
    const resolver = await createCogsSharedSkillOciLayoutResolver({
      layoutRoot: root,
      fs: {
        open: async (target: string, flags: number) => {
          const handle = await open(target, flags);
          return {
            stat: async () => {
              const stat = (await handle.stat({ bigint: true })) as never as { mtimeNs: bigint };
              calls += 1;
              if (calls > 1) stat.mtimeNs += 1n;
              return stat as never;
            },
            read: (buffer: Buffer, offset: number, length: number, position: number) =>
              handle.read(buffer, offset, length, position),
            close: () => handle.close(),
          };
        },
      },
    });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
  });
  await withTemp(async (root) => {
    const { manifestDigest } = await makeLayout(root);
    const resolver = await createCogsSharedSkillOciLayoutResolver({
      layoutRoot: root,
      fs: {
        open: async (target: string, flags: number) => {
          const handle = await open(target, flags);
          return {
            stat: () => handle.stat({ bigint: true }) as never,
            read: async () => ({ bytesRead: Number.MAX_SAFE_INTEGER }),
            close: () => handle.close(),
          };
        },
      },
    });
    await assertInvalid(() => resolver.resolve({ manifestDigest }));
  });
});
