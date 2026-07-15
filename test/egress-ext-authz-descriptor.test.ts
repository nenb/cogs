import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import {
  createExtAuthzDescriptorLoader,
  ExtAuthzDescriptorError,
  loadExtAuthzDescriptor,
} from "../src/egress/ext-authz-descriptor.ts";

const manifestPath = "third_party/envoy-ext-authz-v1.38.3/manifest.json";
const descriptorPath = "third_party/envoy-ext-authz-v1.38.3/ext_authz.descriptor.pb";

test("loads only the pinned descriptor and exposes the Authorization Check boundary", async () => {
  const loaded = await loadExtAuthzDescriptor();
  assert.equal(loaded.authorizationService.Check.path, "/envoy.service.auth.v3.Authorization/Check");
  assert.equal(loaded.authorizationService.Check.requestStream, false);
  assert.equal(loaded.authorizationService.Check.responseStream, false);
  assert.equal(Object.isFrozen(loaded.authorizationService), true);
  assert.equal(Object.isFrozen(loaded.authorizationService.Check), true);
  assert.equal("packageDefinition" in loaded, false);
  const response = loaded.authorizationService.Check.responseDeserialize(
    loaded.authorizationService.Check.responseSerialize({
      status: { code: 0, message: "", details: [] },
      ok_response: {},
    }),
  ) as { status?: { code?: number } };
  assert.equal(response.status?.code, 0);
});

test("descriptor loader simulated open failures are generic", async () => {
  const loader = createExtAuthzDescriptorLoader({
    readTrustedRegularFile: async (path) => {
      if (path.endsWith("manifest.json")) return Buffer.from("{}\n");
      return Buffer.from("bad");
    },
    loadFileDescriptorSetFromBuffer: protoLoader.loadFileDescriptorSetFromBuffer,
    loadPackageDefinition: grpc.loadPackageDefinition,
    packageVersion: () => "1.14.4",
  });
  await assert.rejects(loader, (error) => {
    assert.equal(error instanceof ExtAuthzDescriptorError, true);
    assert.equal((error as Error).message.includes("third_party"), false);
    assert.equal((error as Error).message.includes("f380"), false);
    return true;
  });
  await assert.rejects(
    createExtAuthzDescriptorLoader({
      readTrustedRegularFile: async () => {
        throw Object.assign(new Error("ELOOP /tmp/secret-path"), { code: "ELOOP" });
      },
      loadFileDescriptorSetFromBuffer: protoLoader.loadFileDescriptorSetFromBuffer,
      loadPackageDefinition: grpc.loadPackageDefinition,
      packageVersion: () => "1.14.4",
    }),
    (error) => {
      assert.equal(error instanceof ExtAuthzDescriptorError, true);
      assert.equal((error as Error).message.includes("ELOOP"), false);
      assert.equal((error as Error).message.includes("secret-path"), false);
      return true;
    },
  );
});

test("descriptor loader coalesces singleton success and records exact bounds/options", async () => {
  const manifest = await readFile(manifestPath);
  const descriptor = await readFile(descriptorPath);
  const reads: Array<{ path: string; bounds: { exactSize?: number; sha256?: string } }> = [];
  let loadCalls = 0;
  const loader = createExtAuthzDescriptorLoader({
    readTrustedRegularFile: async (path, bounds) => {
      reads.push({ path, bounds });
      return path.endsWith("manifest.json") ? manifest : descriptor;
    },
    loadFileDescriptorSetFromBuffer: (_buffer, options) => {
      loadCalls += 1;
      assert.deepEqual(options, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: false,
        oneofs: true,
        json: false,
        includeDirs: [],
      });
      return {} as protoLoader.PackageDefinition;
    },
    loadPackageDefinition: () =>
      ({
        envoy: {
          service: {
            auth: {
              v3: {
                Authorization: {
                  service: {
                    Check: {
                      path: "/envoy.service.auth.v3.Authorization/Check",
                      requestStream: false,
                      responseStream: false,
                    },
                  },
                },
              },
            },
          },
        },
      }) as unknown as grpc.GrpcObject,
    packageVersion: (specifier) => (specifier.includes("proto-loader") ? "0.8.1" : "1.14.4"),
  });
  const first = loader();
  const second = loader();
  assert.equal(first, second);
  const result = await first;
  assert.equal(await second, result);
  assert.equal(loadCalls, 1);
  assert.deepEqual(
    reads.map((read) => read.bounds),
    [
      {
        exactSize: 11_823,
        sha256: "a55f0670e871111d688fe41bf9d14325151cbc1844dcd773b6488e1ef5d5b500",
      },
      {
        exactSize: 44_227,
        sha256: "f380ca351c3aa52c40b70c1cfe11378ec514b670060139e6c3ac92baa22051dd",
      },
    ],
  );
});

test("descriptor loader retains singleton rejection and rejects package-version mismatch", async () => {
  const loader = createExtAuthzDescriptorLoader({
    readTrustedRegularFile: async () => Buffer.from("{}\n"),
    loadFileDescriptorSetFromBuffer: protoLoader.loadFileDescriptorSetFromBuffer,
    loadPackageDefinition: grpc.loadPackageDefinition,
    packageVersion: () => "bad",
  });
  const first = loader();
  await assert.rejects(first, ExtAuthzDescriptorError);
  assert.equal(loader(), first);

  const manifest = await readFile(manifestPath);
  const descriptor = await readFile(descriptorPath);
  await assert.rejects(
    createExtAuthzDescriptorLoader({
      readTrustedRegularFile: async (path) => (path.endsWith("manifest.json") ? manifest : descriptor),
      loadFileDescriptorSetFromBuffer: protoLoader.loadFileDescriptorSetFromBuffer,
      loadPackageDefinition: grpc.loadPackageDefinition,
      packageVersion: () => "0.0.0",
    }),
    ExtAuthzDescriptorError,
  );
});

test("descriptor loader rejects malformed manifest, wrong descriptor, and bad service", async () => {
  const manifest = await readFile(manifestPath);
  const descriptor = await readFile(descriptorPath);
  const goodRead = async (path: string) => (path.endsWith("manifest.json") ? manifest : descriptor);
  await assert.rejects(
    createExtAuthzDescriptorLoader({
      readTrustedRegularFile: async (path) => (path.endsWith("manifest.json") ? Buffer.from("{}\n") : descriptor),
      loadFileDescriptorSetFromBuffer: protoLoader.loadFileDescriptorSetFromBuffer,
      loadPackageDefinition: grpc.loadPackageDefinition,
      packageVersion: () => "1.14.4",
    }),
    ExtAuthzDescriptorError,
  );
  await assert.rejects(
    createExtAuthzDescriptorLoader({
      readTrustedRegularFile: async (path) => (path.endsWith("manifest.json") ? manifest : Buffer.from("bad")),
      loadFileDescriptorSetFromBuffer: protoLoader.loadFileDescriptorSetFromBuffer,
      loadPackageDefinition: grpc.loadPackageDefinition,
      packageVersion: (specifier) => (specifier.includes("proto-loader") ? "0.8.1" : "1.14.4"),
    }),
    ExtAuthzDescriptorError,
  );
  await assert.rejects(
    createExtAuthzDescriptorLoader({
      readTrustedRegularFile: goodRead,
      loadFileDescriptorSetFromBuffer: () => ({}) as protoLoader.PackageDefinition,
      loadPackageDefinition: () =>
        ({
          envoy: { service: { auth: { v3: { Authorization: { service: { Check: { path: "/bad" } } } } } } },
        }) as unknown as grpc.GrpcObject,
      packageVersion: (specifier) => (specifier.includes("proto-loader") ? "0.8.1" : "1.14.4"),
    }),
    ExtAuthzDescriptorError,
  );
});
