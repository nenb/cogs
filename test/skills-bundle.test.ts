import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import {
  buildCogsSkillBundle,
  COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES,
  COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES,
  COGS_SKILLS_BUNDLE_MAX_FILE_BYTES,
  COGS_SKILLS_BUNDLE_MAX_FILES,
  COGS_SKILLS_BUNDLE_MAX_PATH_BYTES,
  COGS_SKILLS_BUNDLE_MEDIA_TYPE,
  COGS_SKILLS_BUNDLE_VERSION,
  CogsSkillBundleError,
  verifyCogsSkillBundle,
} from "../src/skills/bundle.ts";

function digest(bytes: Buffer): `sha256:${string}` {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function assertInvalid(operation: () => unknown, message?: string): void {
  assert.throws(
    operation,
    (error: unknown) => {
      assert.ok(error instanceof CogsSkillBundleError);
      assert.equal(error.message, "invalid skill bundle");
      assert.equal(error.code, "COGS_SKILL_BUNDLE_INVALID");
      return true;
    },
    message,
  );
}

test("builds deterministic canonical bytes with entries sorted by UTF-8 byte order", () => {
  const first = buildCogsSkillBundle({
    entries: [
      { path: "zeta/SKILL.md", executable: false, content: Buffer.from("z") },
      { path: "alpha.md", executable: true, content: Buffer.from("alpha") },
      { path: "🦊.md", executable: false, content: Buffer.from("fox") },
    ],
  });
  const second = buildCogsSkillBundle({
    entries: [
      { path: "🦊.md", executable: false, content: Buffer.from("fox") },
      { path: "alpha.md", executable: true, content: Buffer.from("alpha") },
      { path: "zeta/SKILL.md", executable: false, content: Buffer.from("z") },
    ],
  });

  assert.equal(first.digest, second.digest);
  assert.deepEqual(
    first.files.map((file) => file.path),
    ["alpha.md", "zeta/SKILL.md", "🦊.md"],
  );
  assert.equal(first.mediaType, COGS_SKILLS_BUNDLE_MEDIA_TYPE);
  assert.equal(first.version, COGS_SKILLS_BUNDLE_VERSION);
  assert.equal(first.digest, digest(first.copyBytes()));
  assert.deepEqual(verifyCogsSkillBundle(first.copyBytes()).files, first.files);
});

test("documents deterministic empty bundle digest", () => {
  const empty = buildCogsSkillBundle({ entries: [] });
  const expected = Buffer.from(
    `{"version":"${COGS_SKILLS_BUNDLE_VERSION}","mediaType":"${COGS_SKILLS_BUNDLE_MEDIA_TYPE}","entries":[]}`,
    "utf8",
  );
  assert.equal(empty.fileCount, 0);
  assert.equal(empty.decodedByteLength, 0);
  assert.equal(empty.digest, "sha256:db1d1d550f597a03595794d95ca6c596c16a4b3b4f2304301f03c93bc6b53c0c");
  assert.deepEqual(empty.copyBytes(), expected);
  assert.equal(verifyCogsSkillBundle(expected).digest, empty.digest);
});

test("copies input buffers and never exposes retained mutable bytes", () => {
  const source = Buffer.from("trusted");
  const bundle = buildCogsSkillBundle({ entries: [{ path: "skill.md", executable: false, content: source }] });
  source.fill(0);

  assert.equal(bundle.copyFile("skill.md").toString("utf8"), "trusted");
  const fileCopy = bundle.copyFile("skill.md");
  fileCopy.fill(1);
  assert.equal(bundle.copyFile("skill.md").toString("utf8"), "trusted");

  const bytesCopy = bundle.copyBytes();
  bytesCopy.fill(2);
  assert.equal(verifyCogsSkillBundle(bundle.copyBytes()).digest, bundle.digest);
  assert.ok(Object.isFrozen(bundle));
  assert.ok(Object.isFrozen(bundle.files));
  assert.ok(Object.isFrozen(bundle.files[0]));
});

test("rejects hostile build input shapes before accepting content", () => {
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: [{ path: "a", executable: false, content: Buffer.alloc(0), extra: true } as never],
    }),
  );
  let accessorCalls = 0;
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: [
        Object.defineProperty({ path: "a", executable: false }, "content", {
          get: () => {
            accessorCalls += 1;
            return Buffer.alloc(0);
          },
          enumerable: true,
        }) as never,
      ],
    }),
  );
  assert.equal(accessorCalls, 0);

  let proxyGetCalls = 0;
  let proxyOwnKeysCalls = 0;
  const proxiedEntry = new Proxy(
    { path: "proxy.md", executable: false, content: Buffer.from("proxy") },
    {
      get: () => {
        proxyGetCalls += 1;
        throw new Error("proxy get must not run");
      },
      ownKeys: (target) => {
        proxyOwnKeysCalls += 1;
        if (proxyOwnKeysCalls > 1) return [...Reflect.ownKeys(target), "extra"];
        return Reflect.ownKeys(target);
      },
    },
  );
  assert.equal(
    buildCogsSkillBundle({ entries: [proxiedEntry] })
      .copyFile("proxy.md")
      .toString("utf8"),
    "proxy",
  );
  assert.equal(proxyGetCalls, 0);
  assert.equal(proxyOwnKeysCalls, 1);

  assertInvalid(() => {
    const entry = { path: "a", executable: false, content: Buffer.alloc(0) } as Record<PropertyKey, unknown>;
    entry[Symbol("s")] = true;
    buildCogsSkillBundle({ entries: [entry as never] });
  });
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: [
        Object.defineProperty({ path: "a", executable: false, content: Buffer.alloc(0) }, "hidden", {
          value: true,
        }) as never,
      ],
    }),
  );
  assertInvalid(() => buildCogsSkillBundle(new Proxy({ entries: [] }, { getPrototypeOf: () => null }) as never));
});

test("rejects hostile array shapes by descriptor snapshot", () => {
  const valid = { path: "a.md", executable: false, content: Buffer.alloc(0) };
  const sparse = [valid, valid];
  delete sparse[0];
  assertInvalid(() => buildCogsSkillBundle({ entries: sparse }));

  const accessor = [valid];
  let accessorCalls = 0;
  Object.defineProperty(accessor, "0", {
    get: () => {
      accessorCalls += 1;
      return valid;
    },
    enumerable: true,
  });
  assertInvalid(() => buildCogsSkillBundle({ entries: accessor }));
  assert.equal(accessorCalls, 0);

  assertInvalid(() => {
    const entries = [valid] as unknown[] & Record<PropertyKey, unknown>;
    entries[Symbol("s")] = true;
    buildCogsSkillBundle({ entries: entries as never });
  });
  assertInvalid(() => {
    const entries = [valid] as unknown[] & { extra?: boolean };
    entries.extra = true;
    buildCogsSkillBundle({ entries: entries as never });
  });

  let getCalls = 0;
  let ownKeysCalls = 0;
  let lengthDescriptorCalls = 0;
  const proxiedArray = new Proxy([valid], {
    get: () => {
      getCalls += 1;
      throw new Error("array get must not run");
    },
    ownKeys: (target) => {
      ownKeysCalls += 1;
      if (ownKeysCalls > 1) return [...Reflect.ownKeys(target), "extra"];
      return Reflect.ownKeys(target);
    },
    getOwnPropertyDescriptor: (target, property) => {
      if (property === "length") lengthDescriptorCalls += 1;
      if (property === "length" && lengthDescriptorCalls > 1) return { value: 2, configurable: false };
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  assert.equal(buildCogsSkillBundle({ entries: proxiedArray }).copyFile("a.md").length, 0);
  assert.equal(getCalls, 0);
  assert.equal(ownKeysCalls, 1);
  assert.equal(lengthDescriptorCalls, 1);
});

test("rejects invalid and duplicate normalized paths", () => {
  for (const path of [
    "",
    "/absolute",
    "../escape",
    "a/../b",
    "a/./b",
    "a//b",
    "C:drive",
    "a\\b",
    "nul\0x",
    "line\nbreak",
    "\ud800.md",
    "\udc00.md",
  ]) {
    assertInvalid(
      () => buildCogsSkillBundle({ entries: [{ path, executable: false, content: Buffer.alloc(0) }] }),
      path,
    );
  }
  assertInvalid(() =>
    buildCogsSkillBundle({ entries: [{ path: "e\u0301.md", executable: false, content: Buffer.alloc(0) }] }),
  );
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: [
        { path: "same.md", executable: false, content: Buffer.alloc(0) },
        { path: "same.md", executable: true, content: Buffer.alloc(0) },
      ],
    }),
  );

  const astral = "😀".repeat(Math.floor(COGS_SKILLS_BUNDLE_MAX_PATH_BYTES / 4));
  assert.equal(Buffer.byteLength(astral, "utf8"), COGS_SKILLS_BUNDLE_MAX_PATH_BYTES);
  assert.equal(
    buildCogsSkillBundle({ entries: [{ path: astral, executable: false, content: Buffer.alloc(0) }] }).fileCount,
    1,
  );
  assertInvalid(() =>
    buildCogsSkillBundle({ entries: [{ path: `${astral}a`, executable: false, content: Buffer.alloc(0) }] }),
  );
});

test("enforces file count, per-file, decoded total, and canonical byte bounds", () => {
  assert.equal(
    buildCogsSkillBundle({
      entries: Array.from({ length: COGS_SKILLS_BUNDLE_MAX_FILES }, (_, index) => ({
        path: `f${index}.md`,
        executable: false,
        content: Buffer.alloc(0),
      })),
    }).fileCount,
    COGS_SKILLS_BUNDLE_MAX_FILES,
  );
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: Array.from({ length: COGS_SKILLS_BUNDLE_MAX_FILES + 1 }, (_, index) => ({
        path: `f${index}.md`,
        executable: false,
        content: Buffer.alloc(0),
      })),
    }),
  );
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: [
        { path: "too-large.md", executable: false, content: Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES + 1) },
      ],
    }),
  );
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: [
        { path: "a.md", executable: false, content: Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES) },
        { path: "b.md", executable: false, content: Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES) },
        { path: "c.md", executable: false, content: Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES) },
        { path: "d.md", executable: false, content: Buffer.alloc(1) },
      ],
    }),
  );
  assertInvalid(() => verifyCogsSkillBundle(Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_CANONICAL_BYTES + 1, 0x20)));
  assertInvalid(() =>
    buildCogsSkillBundle({
      entries: [
        { path: "a.md", executable: false, content: Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES) },
        { path: "b.md", executable: false, content: Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES) },
        { path: "c.md", executable: false, content: Buffer.alloc(COGS_SKILLS_BUNDLE_MAX_FILE_BYTES) },
      ],
    }),
  );
  assert.equal(COGS_SKILLS_BUNDLE_MAX_DECODED_BYTES, 768 * 1024);
});

test("verify rejects noncanonical bytes, entry order, key order, whitespace, and extras", () => {
  const bundle = buildCogsSkillBundle({ entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }] });
  const parsed = JSON.parse(bundle.copyBytes().toString("utf8"));

  assertInvalid(() => verifyCogsSkillBundle(Buffer.from(JSON.stringify(parsed, null, 2))));
  assertInvalid(() =>
    verifyCogsSkillBundle(
      Buffer.from(JSON.stringify({ mediaType: parsed.mediaType, version: parsed.version, entries: parsed.entries })),
    ),
  );
  assertInvalid(() => verifyCogsSkillBundle(Buffer.from(JSON.stringify({ ...parsed, extra: true }))));

  const unsorted = buildCogsSkillBundle({
    entries: [
      { path: "a.md", executable: false, content: Buffer.from("a") },
      { path: "b.md", executable: false, content: Buffer.from("b") },
    ],
  });
  const unsortedParsed = JSON.parse(unsorted.copyBytes().toString("utf8"));
  unsortedParsed.entries.reverse();
  assertInvalid(() => verifyCogsSkillBundle(Buffer.from(JSON.stringify(unsortedParsed))));

  const duplicateKey = bundle.copyBytes().toString("utf8").replace('"path":"a.md"', '"path":"a.md","path":"a.md"');
  assertInvalid(() => verifyCogsSkillBundle(Buffer.from(duplicateKey)));
});

test("verify rejects malformed UTF-8, JSON, types, integers, digests, base64, and content", () => {
  assertInvalid(() => verifyCogsSkillBundle(Buffer.from([0xff])));
  assertInvalid(() => verifyCogsSkillBundle(Buffer.from("not-json", "utf8")));

  const bundle = buildCogsSkillBundle({ entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }] });
  const parsed = JSON.parse(bundle.copyBytes().toString("utf8"));
  for (const mutate of [
    (value: typeof parsed) => ({ ...value, version: "wrong" }),
    (value: typeof parsed) => ({ ...value, mediaType: "wrong" }),
    (value: typeof parsed) => ({ ...value, entries: {} }),
    (value: typeof parsed) => ({ ...value, entries: [{ ...value.entries[0], executable: "false" }] }),
    (value: typeof parsed) => ({ ...value, entries: [{ ...value.entries[0], size: 1.5 }] }),
    (value: typeof parsed) => ({ ...value, entries: [{ ...value.entries[0], size: Number.MAX_SAFE_INTEGER + 1 }] }),
    (value: typeof parsed) => ({ ...value, entries: [{ ...value.entries[0], sha256: `sha256:${"0".repeat(63)}g` }] }),
    (value: typeof parsed) => ({ ...value, entries: [{ ...value.entries[0], contentBase64: "YQ" }] }),
    (value: typeof parsed) => ({ ...value, entries: [{ ...value.entries[0], contentBase64: "Yg==" }] }),
    (value: typeof parsed) => ({ ...value, entries: [{ ...value.entries[0], path: "./a.md" }] }),
  ]) {
    assertInvalid(() => verifyCogsSkillBundle(Buffer.from(JSON.stringify(mutate(parsed)))));
  }
});

test("copyFile validates requested path and fails generically for missing files", () => {
  const bundle = buildCogsSkillBundle({ entries: [{ path: "a.md", executable: false, content: Buffer.from("a") }] });
  assert.equal(bundle.copyFile("a.md").toString("utf8"), "a");
  assertInvalid(() => bundle.copyFile("missing.md"));
  assertInvalid(() => bundle.copyFile("../a.md"));
});
