import {
  type handleUnaryCall,
  type MethodDefinition,
  Server,
  ServerCredentials,
  type ServiceDefinition,
  status,
} from "@grpc/grpc-js";

interface DecodedCheckRequest {
  headers: Readonly<Record<string, string>>;
  context: Readonly<Record<string, string>>;
}

export interface EnvoyAuthorizationDecision {
  outcome: "allow" | "deny" | "error";
  intentId?: string;
}

export interface EnvoyAuthorizationGrpc {
  target: string;
  stop(): Promise<void>;
}

interface StartOptions {
  decide(request: DecodedCheckRequest): EnvoyAuthorizationDecision;
}

interface WireField {
  number: number;
  wireType: number;
  value: bigint | Buffer;
}

interface EncodedDecision {
  outcome: "allow" | "deny";
  intentId?: string;
}

function readVarint(buffer: Buffer, offset: number): { value: bigint; offset: number } {
  let value = 0n;
  let shift = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (offset >= buffer.length) throw new Error("truncated protobuf varint");
    const byte = buffer[offset++] ?? 0;
    value |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return { value, offset };
    shift += 7n;
  }
  throw new Error("oversized protobuf varint");
}

function decodeFields(buffer: Buffer): WireField[] {
  const fields: WireField[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    const tag = readVarint(buffer, offset);
    offset = tag.offset;
    const number = Number(tag.value >> 3n);
    const wireType = Number(tag.value & 7n);
    if (number < 1) throw new Error("invalid protobuf field number");
    if (wireType === 0) {
      const decoded = readVarint(buffer, offset);
      offset = decoded.offset;
      fields.push({ number, wireType, value: decoded.value });
      continue;
    }
    if (wireType === 2) {
      const length = readVarint(buffer, offset);
      offset = length.offset;
      const size = Number(length.value);
      if (!Number.isSafeInteger(size) || size < 0 || offset + size > buffer.length) {
        throw new Error("invalid protobuf field length");
      }
      fields.push({ number, wireType, value: buffer.subarray(offset, offset + size) });
      offset += size;
      continue;
    }
    if (wireType === 1) {
      offset += 8;
    } else if (wireType === 5) {
      offset += 4;
    } else {
      throw new Error("unsupported protobuf wire type");
    }
    if (offset > buffer.length) throw new Error("truncated protobuf field");
  }
  return fields;
}

function messageField(buffer: Buffer, number: number): Buffer | undefined {
  const field = decodeFields(buffer).find((candidate) => candidate.number === number && candidate.wireType === 2);
  return Buffer.isBuffer(field?.value) ? field.value : undefined;
}

function decodeStringMap(buffer: Buffer, number: number): Record<string, string> {
  const output: Record<string, string> = {};
  for (const field of decodeFields(buffer)) {
    if (field.number !== number || !Buffer.isBuffer(field.value)) continue;
    const entry = decodeFields(field.value);
    const key = entry.find((candidate) => candidate.number === 1 && Buffer.isBuffer(candidate.value));
    const value = entry.find((candidate) => candidate.number === 2 && Buffer.isBuffer(candidate.value));
    if (!Buffer.isBuffer(key?.value) || !Buffer.isBuffer(value?.value)) continue;
    const decodedKey = key.value.toString("utf8");
    const decodedValue = value.value.toString("utf8");
    if (decodedKey.length > 0 && decodedKey.length <= 256 && decodedValue.length <= 8192)
      output[decodedKey] = decodedValue;
  }
  return output;
}

function decodeCheckRequest(buffer: Buffer): DecodedCheckRequest {
  if (buffer.length > 128 * 1024) throw new Error("ext-authz request exceeded its bound");
  const attributes = messageField(buffer, 1);
  const request = attributes === undefined ? undefined : messageField(attributes, 4);
  const http = request === undefined ? undefined : messageField(request, 2);
  return {
    headers: Object.freeze(http === undefined ? {} : decodeStringMap(http, 3)),
    context: Object.freeze(attributes === undefined ? {} : decodeStringMap(attributes, 10)),
  };
}

function encodeVarint(value: number | bigint): Buffer {
  let remaining = BigInt(value);
  const bytes: number[] = [];
  do {
    let byte = Number(remaining & 0x7fn);
    remaining >>= 7n;
    if (remaining > 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining > 0);
  return Buffer.from(bytes);
}

function encodeTag(number: number, wireType: number): Buffer {
  return encodeVarint((number << 3) | wireType);
}

function encodeVarintField(number: number, value: number): Buffer {
  return Buffer.concat([encodeTag(number, 0), encodeVarint(value)]);
}

function encodeMessageField(number: number, value: Buffer): Buffer {
  return Buffer.concat([encodeTag(number, 2), encodeVarint(value.length), value]);
}

function encodeStringField(number: number, value: string): Buffer {
  return encodeMessageField(number, Buffer.from(value, "utf8"));
}

function encodeStringStruct(key: string, value: string): Buffer {
  const protobufValue = encodeStringField(3, value);
  const entry = Buffer.concat([encodeStringField(1, key), encodeMessageField(2, protobufValue)]);
  return encodeMessageField(1, entry);
}

function encodeDecision(decision: EncodedDecision): Buffer {
  if (decision.outcome === "deny") {
    const statusMessage = encodeVarintField(1, 7);
    const httpStatus = encodeVarintField(1, 403);
    const deniedResponse = encodeMessageField(1, httpStatus);
    return Buffer.concat([encodeMessageField(1, statusMessage), encodeMessageField(2, deniedResponse)]);
  }
  const fields = [encodeMessageField(1, Buffer.alloc(0)), encodeMessageField(3, Buffer.alloc(0))];
  if (decision.intentId !== undefined) {
    fields.push(encodeMessageField(4, encodeStringStruct("x-cogs-intent-id", decision.intentId)));
  }
  return Buffer.concat(fields);
}

const checkMethod: MethodDefinition<DecodedCheckRequest, EncodedDecision> = {
  path: "/envoy.service.auth.v3.Authorization/Check",
  requestStream: false,
  responseStream: false,
  requestSerialize: () => {
    throw new Error("server-side ext-authz method cannot serialize requests");
  },
  requestDeserialize: decodeCheckRequest,
  responseSerialize: encodeDecision,
  responseDeserialize: () => {
    throw new Error("server-side ext-authz method cannot deserialize responses");
  },
};

export async function startEnvoyAuthorizationGrpc(options: StartOptions): Promise<EnvoyAuthorizationGrpc> {
  const server = new Server({
    "grpc.max_receive_message_length": 128 * 1024,
    "grpc.max_send_message_length": 16 * 1024,
  });
  const service: ServiceDefinition = { Check: checkMethod };
  const check: handleUnaryCall<DecodedCheckRequest, EncodedDecision> = (call, callback) => {
    let decision: EnvoyAuthorizationDecision;
    try {
      decision = options.decide(call.request);
    } catch {
      callback({ code: status.INTERNAL, message: "authorization decision failed" });
      return;
    }
    if (decision.outcome === "error") {
      callback({ code: status.UNAVAILABLE, message: "authorization dependency unavailable" });
      return;
    }
    callback(null, {
      outcome: decision.outcome,
      ...(decision.intentId === undefined ? {} : { intentId: decision.intentId }),
    });
  };
  server.addService(service, { Check: check });
  const port = await new Promise<number>((resolve, reject) => {
    server.bindAsync("127.0.0.1:0", ServerCredentials.createInsecure(), (error, boundPort) => {
      if (error) reject(error);
      else resolve(boundPort);
    });
  });
  return {
    target: `127.0.0.1:${port}`,
    stop: () =>
      new Promise<void>((resolve) => {
        const timeout = setTimeout(() => {
          server.forceShutdown();
          resolve();
        }, 2_000);
        server.tryShutdown(() => {
          clearTimeout(timeout);
          resolve();
        });
      }),
  };
}
