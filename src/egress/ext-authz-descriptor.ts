import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { open } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const require = createRequire(import.meta.url);
const assetRoot = resolve(fileURLToPath(new URL("../../third_party/envoy-ext-authz-v1.38.3/", import.meta.url)));
const manifestPath = resolve(
  fileURLToPath(new URL("../../third_party/envoy-ext-authz-v1.38.3/manifest.json", import.meta.url)),
);
const descriptorPath = resolve(
  fileURLToPath(new URL("../../third_party/envoy-ext-authz-v1.38.3/ext_authz.descriptor.pb", import.meta.url)),
);
const manifestSha256 = "a55f0670e871111d688fe41bf9d14325151cbc1844dcd773b6488e1ef5d5b500";
const manifestSize = 11_823;
const descriptorSha256 = "f380ca351c3aa52c40b70c1cfe11378ec514b670060139e6c3ac92baa22051dd";
const descriptorSize = 44_227;
const servicePath = "/envoy.service.auth.v3.Authorization/Check";

export interface LoadedExtAuthzDescriptor {
  readonly authorizationService: Readonly<{ Check: grpc.MethodDefinition<unknown, unknown> }>;
}

interface DescriptorLoaderDeps {
  readonly readTrustedRegularFile: (
    path: string,
    bounds: { exactSize?: number; maxSize?: number; sha256?: string },
  ) => Promise<Buffer>;
  readonly loadFileDescriptorSetFromBuffer: typeof protoLoader.loadFileDescriptorSetFromBuffer;
  readonly loadPackageDefinition: typeof grpc.loadPackageDefinition;
  readonly packageVersion: (specifier: string) => string;
}

export class ExtAuthzDescriptorError extends Error {
  public readonly code = "COGS_EXT_AUTHZ_DESCRIPTOR_FAILED";
  public constructor() {
    super("ext_authz descriptor unavailable");
    this.name = "ExtAuthzDescriptorError";
  }
}

const defaultLoader = createExtAuthzDescriptorLoader(defaultDeps());

export function loadExtAuthzDescriptor(): Promise<LoadedExtAuthzDescriptor> {
  return defaultLoader();
}

export function createExtAuthzDescriptorLoader(deps: DescriptorLoaderDeps): () => Promise<LoadedExtAuthzDescriptor> {
  let singleton: Promise<LoadedExtAuthzDescriptor> | undefined;
  return () => {
    singleton ??= loadOnce(deps);
    return singleton;
  };
}

async function loadOnce(deps: DescriptorLoaderDeps): Promise<LoadedExtAuthzDescriptor> {
  try {
    const manifest = JSON.parse(
      (await deps.readTrustedRegularFile(manifestPath, { exactSize: manifestSize, sha256: manifestSha256 })).toString(
        "utf8",
      ),
    ) as unknown;
    verifyManifest(manifest, deps.packageVersion);
    const descriptor = await deps.readTrustedRegularFile(descriptorPath, {
      exactSize: descriptorSize,
      sha256: descriptorSha256,
    });
    const packageDefinition = deps.loadFileDescriptorSetFromBuffer(descriptor, loaderOptions());
    const loaded = deps.loadPackageDefinition(packageDefinition) as Record<string, unknown>;
    const check = serviceCheck(loaded);
    if (check.path !== servicePath || check.requestStream !== false || check.responseStream !== false) {
      throw new Error("bad service");
    }
    const authorizationService = Object.freeze({ Check: Object.freeze(check) });
    return Object.freeze({ authorizationService });
  } catch {
    throw new ExtAuthzDescriptorError();
  }
}

function defaultDeps(): DescriptorLoaderDeps {
  return {
    readTrustedRegularFile,
    loadFileDescriptorSetFromBuffer: protoLoader.loadFileDescriptorSetFromBuffer,
    loadPackageDefinition: grpc.loadPackageDefinition,
    packageVersion,
  };
}

async function readTrustedRegularFile(
  path: string,
  bounds: { exactSize?: number; maxSize?: number; sha256?: string },
): Promise<Buffer> {
  const trustedPath = trustedAssetPath(path);
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const handle = await open(trustedPath, flags);
  try {
    const stat = await handle.stat();
    assertRegular(stat, bounds);
    const data = await handle.readFile();
    if (bounds.exactSize !== undefined && data.length !== bounds.exactSize) throw new Error("bad size");
    if (bounds.maxSize !== undefined && data.length > bounds.maxSize) throw new Error("too large");
    if (bounds.sha256 !== undefined && createHash("sha256").update(data).digest("hex") !== bounds.sha256) {
      throw new Error("bad hash");
    }
    return data;
  } finally {
    await handle.close();
  }
}

function trustedAssetPath(path: string): string {
  const resolved = resolve(path);
  const rel = relative(assetRoot, resolved);
  if (isAbsolute(rel) || rel.startsWith("..") || rel.includes("..")) throw new Error("bad path");
  if (dirname(resolved) !== assetRoot) throw new Error("bad asset location");
  return resolved;
}

function assertRegular(stat: Stats, bounds: { exactSize?: number; maxSize?: number }): void {
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("bad file");
  if (bounds.exactSize !== undefined && stat.size !== bounds.exactSize) throw new Error("bad file size");
  if (bounds.maxSize !== undefined && stat.size > bounds.maxSize) throw new Error("oversized file");
}

function verifyManifest(value: unknown, version: (specifier: string) => string): void {
  const manifest = object(value);
  if (manifest.version !== "cogs.envoy-ext-authz-descriptor/v1alpha1") throw new Error("bad manifest");
  const descriptor = object(manifest.descriptor);
  if (descriptor.sha256 !== descriptorSha256 || descriptor.size_bytes !== descriptorSize) {
    throw new Error("bad descriptor manifest");
  }
  const loader = object(manifest.loader);
  const options = object(loader.options);
  if (
    loader.grpc_js_version !== "1.14.4" ||
    loader.proto_loader_version !== "0.8.1" ||
    loader.method !== "loadFileDescriptorSetFromBuffer" ||
    loader.service_path !== servicePath ||
    loader.request_stream !== false ||
    loader.response_stream !== false ||
    options.keepCase !== true ||
    options.longs !== "String" ||
    options.enums !== "String" ||
    options.defaults !== false ||
    options.oneofs !== true ||
    options.json !== false ||
    !Array.isArray(options.includeDirs) ||
    options.includeDirs.length !== 0
  ) {
    throw new Error("bad loader manifest");
  }
  if (version("@grpc/grpc-js/package.json") !== "1.14.4" || version("@grpc/proto-loader/package.json") !== "0.8.1") {
    throw new Error("bad package version");
  }
}

function loaderOptions(): protoLoader.Options {
  return {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: false,
    oneofs: true,
    json: false,
    includeDirs: [],
  };
}

function packageVersion(specifier: string): string {
  const value = require(specifier) as { version?: unknown };
  if (typeof value.version !== "string") throw new Error("bad package");
  return value.version;
}

function serviceCheck(root: Record<string, unknown>): grpc.MethodDefinition<unknown, unknown> {
  const envoy = object(root.envoy);
  const service = object(envoy.service);
  const auth = object(service.auth);
  const v3 = object(auth.v3);
  const authorization = callableObject(v3.Authorization);
  const definition = object(authorization.service);
  const check = definition.Check;
  if (typeof check !== "object" || check === null) throw new Error("missing check");
  return check as grpc.MethodDefinition<unknown, unknown>;
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("bad object");
  return value as Record<string, unknown>;
}

function callableObject(value: unknown): Record<string, unknown> {
  if ((typeof value !== "object" && typeof value !== "function") || value === null)
    throw new Error("bad callable object");
  return value as Record<string, unknown>;
}
