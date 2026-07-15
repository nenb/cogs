import assert from "node:assert/strict";
import { createSocket } from "node:dgram";
import { connect as connectHttp2 } from "node:http2";
import { request as httpsRequest } from "node:https";
import { connect as connectTcp } from "node:net";
import test from "node:test";
import type { UpstreamFixtures } from "./server.ts";
import { startUpstreamFixtures } from "./server.ts";

const credentials = {
  bearer: "Bearer cogs-fixture-bearer-value",
  apiKey: "cogs-fixture-api-key-value",
  basic: "Basic Y29nczpmaXh0dXJl",
};

interface ResponseData {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

function requestHttp1(
  fixtures: UpstreamFixtures,
  path: string,
  headers: Record<string, string> = {},
): Promise<ResponseData> {
  return new Promise((resolve, reject) => {
    const request = httpsRequest(
      `${fixtures.tlsOrigin}${path}`,
      { ca: fixtures.caCertificatePem, headers, method: "GET" },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.once("end", () =>
          resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks) }),
        );
      },
    );
    request.once("error", reject);
    request.end();
  });
}

function requestHttp2(
  fixtures: UpstreamFixtures,
  path: string,
  headers: Record<string, string> = {},
): Promise<ResponseData> {
  return new Promise((resolve, reject) => {
    const client = connectHttp2(fixtures.tlsOrigin, { ca: fixtures.caCertificatePem });
    client.once("error", (error) => {
      client.destroy();
      reject(error);
    });
    const request = client.request({ ":method": "GET", ":path": path, ...headers });
    const chunks: Buffer[] = [];
    let status = 0;
    let responseHeaders: Record<string, string | string[] | undefined> = {};
    request.once("response", (received) => {
      status = Number(received[":status"] ?? 0);
      responseHeaders = received;
    });
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.once("end", () => {
      client.close();
      resolve({ status, headers: responseHeaders, body: Buffer.concat(chunks) });
    });
    request.once("error", (error) => {
      client.destroy();
      reject(error);
    });
    request.end();
  });
}

function abortHttp2AfterFirstChunk(fixtures: UpstreamFixtures, path: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const client = connectHttp2(fixtures.tlsOrigin, { ca: fixtures.caCertificatePem });
    client.once("error", reject);
    const request = client.request({ ":method": "GET", ":path": path });
    request.once("data", () => {
      request.close();
      client.close();
      resolve();
    });
    request.once("error", (error) => {
      client.destroy();
      reject(error);
    });
    request.end();
  });
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for fixture observation");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

async function withFixtures(run: (fixtures: UpstreamFixtures) => Promise<void>): Promise<void> {
  const fixtures = await startUpstreamFixtures({
    expectedCredentials: credentials,
    redirectLocation: "https://allowed.fixture.invalid/next",
    largeResponseBytes: 128 * 1024,
    streamChunks: 4,
    streamIntervalMs: 5,
    delayedResponseMs: 75,
  });
  try {
    await run(fixtures);
  } finally {
    await fixtures.stop();
  }
}

test("HTTP/1.1 and HTTP/2 TLS fixtures provide non-reflecting positive controls", async () => {
  await withFixtures(async (fixtures) => {
    const http1 = await requestHttp1(fixtures, "/health?never-record=this-query");
    const http2 = await requestHttp2(fixtures, "/health");
    const protectedHttp2 = await requestHttp2(fixtures, "/protected/header", {
      authorization: credentials.bearer,
    });
    assert.equal(http1.status, 200);
    assert.equal(http2.status, 200);
    assert.equal(protectedHttp2.status, 200);
    assert.equal(http1.body.toString(), "ok");
    assert.equal(http2.body.toString(), "ok");

    const observations = fixtures.observations();
    assert.deepEqual(
      observations.filter((observation) => observation.kind === "http").map((observation) => observation.protocol),
      ["http/1.1", "h2", "h2"],
    );
    assert.equal(JSON.stringify(observations).includes("never-record"), false);
  });
});

test("credential fixtures retain only boolean comparisons and never reflect values", async () => {
  await withFixtures(async (fixtures) => {
    const accepted = await Promise.all([
      requestHttp1(fixtures, "/protected/header", { authorization: credentials.bearer }),
      requestHttp1(fixtures, "/protected/api-key", { "x-api-key": credentials.apiKey }),
      requestHttp1(fixtures, "/protected/basic", { authorization: credentials.basic }),
    ]);
    assert.deepEqual(
      accepted.map((response) => response.status),
      [200, 200, 200],
    );
    const rejected = await requestHttp1(fixtures, "/protected/header", {
      authorization: "Bearer wrong-secret-value",
    });
    assert.equal(rejected.status, 401);

    const serialized = JSON.stringify({ observations: fixtures.observations(), responses: [...accepted, rejected] });
    for (const value of [
      ...Object.values(credentials),
      credentials.bearer.replace("Bearer ", ""),
      credentials.basic.replace("Basic ", ""),
      "cogs:fixture",
      "wrong-secret-value",
    ]) {
      assert.equal(serialized.includes(value), false, "credential material must not enter records or responses");
    }
    const matches = fixtures
      .observations()
      .flatMap((observation) =>
        observation.kind === "http" && observation.credential_matches !== null ? [observation.credential_matches] : [],
      );
    assert.deepEqual(matches, [true, true, true, false]);
  });
});

test("redirect, large, streaming, and delayed fixtures are deterministic", async () => {
  await withFixtures(async (fixtures) => {
    const redirect = await requestHttp1(fixtures, "/redirect");
    assert.equal(redirect.status, 302);
    assert.equal(redirect.headers.location, "https://allowed.fixture.invalid/next");

    const large = await requestHttp1(fixtures, "/large");
    assert.equal(large.body.length, 128 * 1024);

    const stream = await requestHttp1(fixtures, "/stream");
    assert.equal(stream.body.toString(), "chunk-0\nchunk-1\nchunk-2\nchunk-3\n");

    const started = Date.now();
    const delayed = await requestHttp1(fixtures, "/delayed");
    assert.equal(delayed.status, 200);
    assert.ok(Date.now() - started >= 60, "delayed endpoint must keep a connection open for drain tests");
  });
});

test("HTTP/2 large response backpressure does not leak response listeners", async () => {
  const warnings: Error[] = [];
  const onWarning = (warning: Error) => {
    if (warning.name === "MaxListenersExceededWarning" && warning.message.includes("Http2ServerResponse")) {
      warnings.push(warning);
    }
  };
  process.prependListener("warning", onWarning);
  const fixtures = await startUpstreamFixtures({
    expectedCredentials: credentials,
    redirectLocation: "https://allowed.fixture.invalid/next",
    largeResponseBytes: 4 * 1024 * 1024,
  });
  try {
    const response = await requestHttp2(fixtures, "/large");
    assert.equal(response.status, 200);
    assert.equal(response.body.length, 4 * 1024 * 1024);
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(warnings, []);
  } finally {
    process.off("warning", onWarning);
    await fixtures.stop();
  }
});

test("HTTP/2 closed large response backpressure does not leak response listeners", async () => {
  const warnings: Error[] = [];
  const onWarning = (warning: Error) => {
    if (warning.name === "MaxListenersExceededWarning" && warning.message.includes("Http2ServerResponse")) {
      warnings.push(warning);
    }
  };
  process.prependListener("warning", onWarning);
  const fixtures = await startUpstreamFixtures({
    expectedCredentials: credentials,
    redirectLocation: "https://allowed.fixture.invalid/next",
    largeResponseBytes: 4 * 1024 * 1024,
  });
  try {
    await abortHttp2AfterFirstChunk(fixtures, "/large");
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(warnings, []);
  } finally {
    process.off("warning", onWarning);
    await fixtures.stop();
  }
});

test("TCP and UDP listeners are silent denial sensors with positive controls", async () => {
  await withFixtures(async (fixtures) => {
    const tcp = connectTcp({ host: "127.0.0.1", port: fixtures.tcpSensorPort });
    try {
      await new Promise<void>((resolve, reject) => {
        tcp.once("connect", () => resolve());
        tcp.once("error", reject);
      });
    } finally {
      tcp.destroy();
    }

    const udp = createSocket("udp4");
    try {
      await new Promise<void>((resolve, reject) => {
        udp.send(Buffer.from("denial-positive-control"), fixtures.udpSensorPort, "127.0.0.1", (error) =>
          error === null ? resolve() : reject(error),
        );
      });
      await waitFor(() => fixtures.observations().some((observation) => observation.kind === "udp-reached"));
    } finally {
      udp.close();
    }

    assert.equal(
      fixtures.observations().some((observation) => observation.kind === "tcp-reached"),
      true,
    );
    assert.equal(
      fixtures.observations().some((observation) => observation.kind === "udp-reached"),
      true,
    );
  });
});

test("observation capacity fails closed without recording excess request data", async () => {
  const fixtures = await startUpstreamFixtures({
    expectedCredentials: credentials,
    redirectLocation: "https://allowed.fixture.invalid/next",
    maxObservations: 1,
  });
  try {
    assert.equal((await requestHttp1(fixtures, "/health")).status, 200);
    assert.equal((await requestHttp1(fixtures, "/health")).status, 503);
    await new Promise<void>((resolve, reject) => {
      const socket = connectTcp({ host: "127.0.0.1", port: fixtures.tcpSensorPort });
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
      socket.once("error", reject);
    });
    assert.equal(fixtures.observations().filter((observation) => observation.kind === "http").length, 1);
    await waitFor(() => fixtures.observations().some((observation) => observation.kind === "tcp-reached"));
  } finally {
    await fixtures.stop();
  }
});

test("deterministic client artifacts require the bearer credential and never reflect it", async () => {
  await withFixtures(async (fixtures) => {
    const headers = { authorization: credentials.bearer };
    const [wheel, npm, git] = await Promise.all([
      requestHttp1(fixtures, "/clients/cogs_fixture-1.0.0-py3-none-any.whl", headers),
      requestHttp1(fixtures, "/clients/cogs-fixture-1.0.0.tgz", headers),
      requestHttp1(fixtures, "/clients/repo.git/info/refs?service=git-upload-pack", headers),
    ]);
    assert.equal(wheel.status, 200);
    assert.equal(npm.status, 200);
    assert.equal(git.status, 200);
    assert.equal(wheel.body.subarray(0, 2).toString("ascii"), "PK");
    assert.equal(npm.body.subarray(0, 2).toString("hex"), "1f8b");
    assert.match(git.body.toString("ascii"), /service=git-upload-pack/);
    assert.equal(Buffer.concat([wheel.body, npm.body, git.body]).includes(Buffer.from(credentials.bearer)), false);
    const observations = fixtures.observations().filter((item) => item.kind === "http");
    assert.equal(
      observations.slice(-3).every((item) => item.credential_matches === true),
      true,
    );
  });
});
