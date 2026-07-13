import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface OtlpMetadataRecord {
  test_id: string;
  outcome: "success" | "failed";
  status_class: number;
  duration_ms: number;
}
export interface OtlpFixture {
  origin: string;
  records(): readonly OtlpMetadataRecord[];
  stop(): Promise<void>;
}

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const maxBody = 32 * 1024;

function reply(response: ServerResponse, status: number): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, {
    "content-type": "application/json",
    "cache-control": "no-store",
    connection: "close",
  });
  response.end(`${JSON.stringify(status === 200 ? { partialSuccess: {} } : { error: "invalid-telemetry" })}\n`);
}

async function body(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += value.length;
    if (size > maxBody) throw new Error("telemetry body exceeds bound");
    chunks.push(value);
  }
  return Buffer.concat(chunks);
}

function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join(",") === [...keys].sort().join(",")
  );
}

function decodeEnvelope(value: unknown): OtlpMetadataRecord | undefined {
  if (!exactKeys(value, ["resourceLogs"]) || !Array.isArray(value.resourceLogs) || value.resourceLogs.length !== 1)
    return undefined;
  const resourceLog = value.resourceLogs[0];
  if (
    !exactKeys(resourceLog, ["resource", "scopeLogs"]) ||
    !exactKeys(resourceLog.resource, ["attributes"]) ||
    !Array.isArray(resourceLog.resource.attributes) ||
    resourceLog.resource.attributes.length !== 0 ||
    !Array.isArray(resourceLog.scopeLogs) ||
    resourceLog.scopeLogs.length !== 1
  )
    return undefined;
  const scopeLog = resourceLog.scopeLogs[0];
  if (
    !exactKeys(scopeLog, ["scope", "logRecords"]) ||
    !exactKeys(scopeLog.scope, ["name"]) ||
    scopeLog.scope.name !== "cogs-stage1-fixture" ||
    !Array.isArray(scopeLog.logRecords) ||
    scopeLog.logRecords.length !== 1
  )
    return undefined;
  const log = scopeLog.logRecords[0];
  if (
    !exactKeys(log, ["severityText", "body", "attributes"]) ||
    log.severityText !== "INFO" ||
    !exactKeys(log.body, ["stringValue"]) ||
    log.body.stringValue !== "cogs.egress.complete" ||
    !Array.isArray(log.attributes) ||
    log.attributes.length !== 4
  )
    return undefined;
  const attributes = new Map<string, string>();
  for (const attribute of log.attributes) {
    if (
      !exactKeys(attribute, ["key", "value"]) ||
      typeof attribute.key !== "string" ||
      !exactKeys(attribute.value, ["stringValue"]) ||
      typeof attribute.value.stringValue !== "string" ||
      attributes.has(attribute.key)
    )
      return undefined;
    attributes.set(attribute.key, attribute.value.stringValue);
  }
  const testId = attributes.get("cogs.test_id");
  const outcome = attributes.get("cogs.outcome");
  const statusClass = Number(attributes.get("cogs.status_class"));
  const duration = Number(attributes.get("cogs.duration_ms"));
  if (
    typeof testId !== "string" ||
    !idPattern.test(testId) ||
    (outcome !== "success" && outcome !== "failed") ||
    !Number.isInteger(statusClass) ||
    statusClass < 1 ||
    statusClass > 5 ||
    !Number.isInteger(duration) ||
    duration < 0 ||
    duration > 300_000
  )
    return undefined;
  return { test_id: testId, outcome, status_class: statusClass, duration_ms: duration };
}

function envelope(record: OtlpMetadataRecord): object {
  const attribute = (key: string, value: string) => ({ key, value: { stringValue: value } });
  return {
    resourceLogs: [
      {
        resource: { attributes: [] },
        scopeLogs: [
          {
            scope: { name: "cogs-stage1-fixture" },
            logRecords: [
              {
                severityText: "INFO",
                body: { stringValue: "cogs.egress.complete" },
                attributes: [
                  attribute("cogs.test_id", record.test_id),
                  attribute("cogs.outcome", record.outcome),
                  attribute("cogs.status_class", String(record.status_class)),
                  attribute("cogs.duration_ms", String(record.duration_ms)),
                ],
              },
            ],
          },
        ],
      },
    ],
  };
}

export async function emitOtlpMetadata(origin: string, record: OtlpMetadataRecord): Promise<void> {
  const response = await fetch(`${origin}/v1/logs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(envelope(record)),
  });
  if (response.status !== 200) throw new Error("OTLP fixture rejected bounded metadata");
}

export async function startOtlpFixture(forbiddenValues: readonly string[]): Promise<OtlpFixture> {
  if (forbiddenValues.some((value) => value.length === 0)) throw new Error("OTLP forbidden values must not be empty");
  const key = randomBytes(32);
  const forbidden = forbiddenValues.map((value) => createHash("sha256").update(key).update(value).digest());
  const records: OtlpMetadataRecord[] = [];
  const server = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? "/", "http://otlp.invalid");
      if (request.method !== "POST" || url.pathname !== "/v1/logs" || url.search || records.length >= 4096) {
        reply(response, 400);
        return;
      }
      const raw = await body(request);
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw.toString("utf8"));
      } catch {
        reply(response, 400);
        return;
      }
      const record = decodeEnvelope(parsed);
      if (!record) {
        reply(response, 400);
        return;
      }
      const testIdDigest = createHash("sha256").update(key).update(record.test_id).digest();
      if (forbidden.some((digest) => timingSafeEqual(digest, testIdDigest))) {
        reply(response, 400);
        return;
      }
      records.push(record);
      reply(response, 200);
    })().catch(() => reply(response, 400));
  });
  server.maxConnections = 64;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${address.port}`,
    records: () => Object.freeze(structuredClone(records)),
    stop: () =>
      new Promise<void>((resolve) =>
        server.close(() => {
          key.fill(0);
          for (const digest of forbidden) digest.fill(0);
          resolve();
        }),
      ),
  };
}
