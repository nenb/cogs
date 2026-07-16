import assert from "node:assert/strict";
import { test } from "node:test";
import { type ModelApiKeySource, type ModelAuthRequest, ModelCredentialResolver } from "../src/auth/model-auth.ts";
import { CogsEgressMaterialError, ModelBackedEgressCredentialSource } from "../src/egress/egress-material.ts";
import type { CogsEnvoyCredentialRequest, CogsEnvoyCredentialValue } from "../src/egress/envoy-runtime-config.ts";

class FakeSource implements ModelApiKeySource {
  public calls: ModelAuthRequest[] = [];
  public material = "credential-material";
  public mode: "normal" | "reject" | "missing" | "duplicate" = "normal";
  public async withApiKey(request: ModelAuthRequest, operation: (apiKey: string) => Promise<void>): Promise<void> {
    this.calls.push(request);
    if (this.mode === "reject") throw new Error(`leak ${request.credentialHandle} ${this.material}`);
    if (this.mode === "missing") return;
    await operation(this.material);
    if (this.mode === "duplicate") await operation(this.material);
  }
}

function sourceFor(fake = new FakeSource(), signal?: AbortSignal): ModelBackedEgressCredentialSource {
  return new ModelBackedEgressCredentialSource({
    userId: "user-1",
    resolver: new ModelCredentialResolver(fake),
    ...(signal === undefined ? {} : { signal }),
  });
}

async function getCredential(
  source: ModelBackedEgressCredentialSource,
  request: CogsEnvoyCredentialRequest,
): Promise<CogsEnvoyCredentialValue> {
  let credential: CogsEnvoyCredentialValue | undefined;
  await source.withCredential(request, async (value) => {
    credential = value;
  });
  assert.ok(credential);
  return credential;
}

test("maps bearer credentials through the model resolver", async () => {
  const fake = new FakeSource();
  const credential = await getCredential(sourceFor(fake), {
    integrationId: "github",
    authType: "bearer_header",
    secretHandle: "users/user-1/github-token",
  });
  assert.deepEqual(credential, { type: "bearer", token: "credential-material" });
  assert.equal(Object.isFrozen(credential), true);
  assert.equal(fake.calls.length, 1);
  assert.deepEqual(
    pick(fake.calls[0] as ModelAuthRequest),
    pick({
      userId: "user-1",
      provider: "github",
      model: "egress-bearer",
      credentialHandle: "users/user-1/github-token",
    }),
  );
});

test("maps api-key and basic credentials to renderer variants", async () => {
  const api = new FakeSource();
  assert.deepEqual(
    await getCredential(sourceFor(api), {
      integrationId: "npm",
      authType: "api_key_header",
      secretHandle: "organizations/acme/npm-token",
    }),
    { type: "api_key", value: "credential-material" },
  );
  assert.equal(api.calls[0]?.model, "egress-api-key");

  const basic = new FakeSource();
  basic.material = "dXNlcjpwYXNzd29yZA==";
  assert.deepEqual(
    await getCredential(sourceFor(basic), {
      integrationId: "pypi",
      authType: "basic_header",
      secretHandle: "organizations/acme/pypi-basic",
    }),
    { type: "basic", base64: "dXNlcjpwYXNzd29yZA==" },
  );
  assert.equal(basic.calls[0]?.model, "egress-basic");
});

test("accepts minimal organization handles and 512 byte handles", async () => {
  const organization = new FakeSource();
  await getCredential(sourceFor(organization), {
    integrationId: "github",
    authType: "bearer_header",
    secretHandle: "organizations/aaaa",
  });
  assert.equal(organization.calls[0]?.credentialHandle, "organizations/aaaa");

  const bounded = new FakeSource();
  const secretHandle = `organizations/${"a".repeat(100)}/${"b".repeat(100)}/${"c".repeat(100)}/${"d".repeat(100)}/${"e".repeat(94)}`;
  assert.equal(secretHandle.length, 512);
  await getCredential(sourceFor(bounded), { integrationId: "github", authType: "bearer_header", secretHandle });
  assert.equal(bounded.calls[0]?.credentialHandle, secretHandle);
});

test("rejects invalid, oversized, or cross-user handles before resolver access", async () => {
  const oversized = `organizations/${"a".repeat(100)}/${"b".repeat(100)}/${"c".repeat(100)}/${"d".repeat(100)}/${"e".repeat(95)}`;
  assert.equal(oversized.length, 513);
  for (const secretHandle of [
    "users/user-2/github-token",
    "users/user-1",
    "sessions/session-1/github-token",
    "relative-token",
    "teams/acme/github-token",
    "users/user-1//token",
    oversized,
  ]) {
    const fake = new FakeSource();
    await assert.rejects(
      sourceFor(fake).withCredential(
        { integrationId: "github", authType: "bearer_header", secretHandle },
        async () => {},
      ),
      genericError,
    );
    assert.equal(fake.calls.length, 0);
  }
});

test("rejects missing request ids without coercion", async () => {
  for (const request of [
    { authType: "bearer_header", secretHandle: "users/user-1/github-token" },
    { integrationId: "github", secretHandle: "users/user-1/github-token" },
    { integrationId: "github", authType: "bearer_header" },
  ]) {
    const fake = new FakeSource();
    await assert.rejects(
      sourceFor(fake).withCredential(request as CogsEnvoyCredentialRequest, async () => {}),
      genericError,
    );
    assert.equal(fake.calls.length, 0);
  }
});

test("snapshots request fields and rejects hostile getters generically", async () => {
  const fake = new FakeSource();
  const request = {} as CogsEnvoyCredentialRequest;
  Object.defineProperty(request, "integrationId", {
    get() {
      throw new Error("leaky getter");
    },
  });
  await assert.rejects(
    sourceFor(fake).withCredential(request, async () => {}),
    genericError,
  );
  assert.equal(fake.calls.length, 0);
});

test("aborted session rejects before source callback", async () => {
  const controller = new AbortController();
  controller.abort();
  const fake = new FakeSource();
  await assert.rejects(
    sourceFor(fake, controller.signal).withCredential(
      { integrationId: "github", authType: "bearer_header", secretHandle: "users/user-1/github-token" },
      async () => {},
    ),
    genericError,
  );
  assert.equal(fake.calls.length, 0);
});

test("consumer and resolver callback failures are redacted", async () => {
  const fake = new FakeSource();
  await assert.rejects(
    sourceFor(fake).withCredential(
      { integrationId: "github", authType: "bearer_header", secretHandle: "users/user-1/secret-handle" },
      async () => {
        throw new Error("consumer leaked credential-material users/user-1/secret-handle");
      },
    ),
    genericError,
  );

  const rejecting = new FakeSource();
  rejecting.mode = "reject";
  await assert.rejects(
    sourceFor(rejecting).withCredential(
      { integrationId: "github", authType: "bearer_header", secretHandle: "users/user-1/secret-handle" },
      async () => {},
    ),
    genericError,
  );
});

test("resolver missing and duplicate callbacks are rejected generically", async () => {
  for (const mode of ["missing", "duplicate"] as const) {
    const fake = new FakeSource();
    fake.mode = mode;
    let consumed = 0;
    await assert.rejects(
      sourceFor(fake).withCredential(
        { integrationId: "github", authType: "bearer_header", secretHandle: "users/user-1/github-token" },
        async () => {
          consumed += 1;
        },
      ),
      genericError,
    );
    assert.equal(consumed, 0);
  }
});

function pick(request: Pick<ModelAuthRequest, "userId" | "provider" | "model" | "credentialHandle">) {
  return {
    userId: request.userId,
    provider: request.provider,
    model: request.model,
    credentialHandle: request.credentialHandle,
  };
}

function genericError(error: unknown): boolean {
  assert.ok(error instanceof CogsEgressMaterialError);
  assert.equal(error.code, "COGS_EGRESS_MATERIAL_FAILED");
  assert.equal(error.message, "egress material unavailable");
  assert.doesNotMatch(String(error.stack), /credential-material|secret-handle|leak/);
  return true;
}
