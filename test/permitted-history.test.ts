import assert from "node:assert/strict";
import test from "node:test";
import { permittedJson, permittedJsonBytes } from "../src/session/permitted-history.ts";

const limits = { secrets: ["abc", "bcd"], maxInputBytes: 8 * 1024 * 1024, maxOutputBytes: 64 * 1024 * 1024 };
test("permitted projection preserves large values, collections, flags, escapes and canonical integer keys", () => {
  const value = {
    content: '🙂\\"'.repeat(5000),
    eof: true,
    truncated: false,
    array: Array.from({ length: 250 }, (_, i) => i),
  };
  assert.deepEqual(permittedJson(value, limits), value);
  assert.equal(
    permittedJsonBytes({ "2": 2, "10": 10, z: "\ud800" }, limits).toString(),
    '{"10":10,"2":2,"z":"\\ud800"}',
  );
  let deep: unknown = "tail";
  for (let i = 0; i < 100; i++) deep = [deep];
  assert.deepEqual(permittedJson(deep, limits), deep);
});

test("redaction unions overlaps before serialization, drops sensitive keys and closes marker collisions", () => {
  assert.deepEqual(
    permittedJson({ value: "xabcdabcy", abcKey: "omitted", authorization: { nested: "omitted" }, keep: 7 }, limits),
    {
      value: "x[redacted]y",
      authorization: null,
      keep: 7,
    },
  );
  assert.equal(permittedJson("abc", { ...limits, secrets: ["abc", "redacted"] }), null);
  assert.equal(permittedJson("xabcy", { ...limits, secrets: ["abc", "x[redacted]y"] }), null);
  assert.equal(
    permittedJson("old-key new-key", { ...limits, secrets: ["old-key", "new-key"] }),
    "[redacted] [redacted]",
  );
  assert.throws(() => permittedJson("old-key", { ...limits, secrets: undefined }), /unavailable/);
});

test("strict admission rejects unsupported values without invoking getters or toJSON", () => {
  let invoked = 0;
  const cycle: unknown[] = [];
  cycle.push(cycle);
  const accessor = Object.defineProperty({}, "secret", {
    enumerable: true,
    get: () => {
      invoked++;
      return "abc";
    },
  });
  const arrayAccessor = Object.defineProperty([1], "0", {
    get: () => {
      invoked++;
      return 1;
    },
  });
  const sparse = Array(2);
  sparse[1] = 1;
  for (const value of [
    cycle,
    accessor,
    arrayAccessor,
    sparse,
    [undefined],
    { x: Infinity },
    { x: 1n },
    { [Symbol("x")]: 1 },
    new Date(),
    {
      toJSON: () => {
        invoked++;
        return 1;
      },
    },
    Object.create(null),
  ]) {
    assert.throws(() => permittedJson(value, limits), /unavailable/);
  }
  assert.equal(invoked, 0);
  assert.throws(() =>
    permittedJson("abc", { ...limits, secrets: Array.from({ length: 257 }, (_, index) => `secret-${index}`) }),
  );
  assert.equal(permittedJson("abc", { ...limits, secrets: Array(257).fill("abc") }), "[redacted]");
  assert.throws(() => permittedJson("abc", { ...limits, secrets: [""] }));
});

test("input and output budgets count syntax, keys, escape expansion, nodes and redaction expansion", () => {
  assert.throws(() => permittedJson({ hugekey: "" }, { ...limits, maxInputBytes: 10 }));
  assert.throws(() => permittedJson("\u0000".repeat(10), { ...limits, maxInputBytes: 20 }));
  assert.throws(() => permittedJson("abc", { ...limits, maxOutputBytes: 5 }));
  assert.throws(() => permittedJson([1, 2], { ...limits, maxNodes: 2 }));
  const value = { content: "x".repeat(5000), eof: true, truncated: false };
  const length = Buffer.byteLength(JSON.stringify(value));
  assert.deepEqual(permittedJson(value, { ...limits, maxInputBytes: length, maxOutputBytes: length }), value);
  assert.throws(() => permittedJson(value, { ...limits, maxInputBytes: length - 1 }));
});
