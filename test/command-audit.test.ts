import assert from "node:assert/strict";
import test from "node:test";
import { createCogsCommandAuditHook, validateCogsCommandAuditHook } from "../src/audit/command-audit.ts";

test("command audit factory is disabled, exact, idempotent, and stateless", async () => {
  const first = createCogsCommandAuditHook();
  const second = createCogsCommandAuditHook();
  assert.equal(first, second);
  assert.equal(first.mode, "disabled");
  assert.equal(first.enabled, false);
  assert.equal(first.record(), false);
  assert.equal(JSON.stringify(first), '{"mode":"disabled","enabled":false}');
  const many = await Promise.all(Array.from({ length: 16 }, () => Promise.resolve(createCogsCommandAuditHook())));
  assert.ok(many.every((hook) => hook === first));
});

test("command audit validates exact disabled hooks without retaining supplied callbacks", () => {
  let calls = 0;
  const supplied = Object.freeze({
    mode: "disabled",
    enabled: false,
    record: () => {
      calls += 1;
      throw new Error("SECRET supplied callback");
    },
  });
  const hook = createCogsCommandAuditHook(supplied);
  assert.notEqual(hook, supplied);
  assert.equal(hook.record(), false);
  assert.equal(calls, 0);
  validateCogsCommandAuditHook(hook);
});

test("command audit rejects malformed hostile hooks generically", () => {
  const cases: unknown[] = [
    null,
    Object.freeze({ mode: "enabled", enabled: true, record: () => false }),
    Object.freeze({ mode: "disabled", enabled: false }),
    Object.freeze({ mode: "disabled", enabled: false, record: () => false, extra: true }),
    Object.freeze(
      Object.defineProperty({ enabled: false, record: () => false }, "mode", {
        enumerable: true,
        get: () => "disabled",
      }),
    ),
    Object.freeze({ mode: "disabled", enabled: false, record: () => false, [Symbol.for("x")]: true }),
    new Proxy(Object.freeze({ mode: "disabled", enabled: false, record: () => false }), {
      getOwnPropertyDescriptor: () => {
        throw new Error("SECRET trap");
      },
    }),
  ];
  for (const value of cases)
    assert.throws(() => createCogsCommandAuditHook(value), /^Error: invalid command audit hook$/);
});
