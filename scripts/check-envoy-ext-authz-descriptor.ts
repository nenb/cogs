import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, createWriteStream } from "node:fs";
import { mkdtemp, open, readdir, readFile, rm, unlink } from "node:fs/promises";
import { get } from "node:https";
import { arch, platform, tmpdir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

const execFile = promisify(execFileCallback);
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const assetRoot = join(root, "third_party/envoy-ext-authz-v1.38.3");
const manifestPath = join(assetRoot, "manifest.json");
const descriptorPath = join(assetRoot, "ext_authz.descriptor.pb");
const protosRoot = join(assetRoot, "protos");
const expectedVersion = "cogs.envoy-ext-authz-descriptor/v1alpha1";
const expectedManifestSha256 = "a55f0670e871111d688fe41bf9d14325151cbc1844dcd773b6488e1ef5d5b500";
const expectedManifestSize = 11_823;
const expectedDescriptorSha256 = "f380ca351c3aa52c40b70c1cfe11378ec514b670060139e6c3ac92baa22051dd";
const expectedDescriptorSize = 44_227;
const expectedGrpcVersion = "1.14.4";
const expectedProtoLoaderVersion = "0.8.1";
const expectedServicePath = "/envoy.service.auth.v3.Authorization/Check";
const expectedProtocUrl =
  "https://github.com/protocolbuffers/protobuf/releases/download/v33.1/protoc-33.1-linux-x86_64.zip";
const expectedProtocSha256 = "f3340e28a83d1c637d8bafdeed92b9f7db6a384c26bca880a6e5217b40a4328b";
const expectedProtocVersion = "libprotoc 33.1";
const expectedLicenseNoticePaths = new Set([
  "LICENSES/envoy-Apache-2.0.txt",
  "LICENSES/googleapis-Apache-2.0.txt",
  "LICENSES/protobuf-BSD-3-Clause.txt",
  "LICENSES/protoc-gen-validate-Apache-2.0.txt",
  "LICENSES/xds-Apache-2.0.txt",
]);
const maxProtocBytes = 10 * 1024 * 1024;

const mode = process.argv[2];
if (mode !== "--static" && mode !== "--regenerate") {
  throw new Error("usage: check-envoy-ext-authz-descriptor.ts (--static|--regenerate)");
}

async function main(): Promise<void> {
  const manifest = JSON.parse(
    await readTrustedFile(manifestPath, assetRoot, {
      exactSize: expectedManifestSize,
      sha256: expectedManifestSha256,
    }).then(String),
  ) as Manifest;
  assertManifest(manifest);
  await verifySources(manifest);
  await verifyLicenseNotices(manifest);
  await verifyDescriptor(manifest);
  await verifyLoader();
  if (mode === "--regenerate") await verifyRegeneration(manifest);
}

async function verifySources(manifest: Manifest): Promise<void> {
  const expected = new Set(manifest.files.map((file) => file.path));
  const actual = new Set(await listProtoFiles(protosRoot));
  if (actual.size !== expected.size || [...actual].some((path) => !expected.has(path)))
    throw new Error("proto set mismatch");
  const sources = new Map(manifest.sources.map((source) => [source.id, source]));
  const expectedSourceIds = new Set(["envoy", "googleapis", "pgv", "protobuf", "xds"]);
  if (
    sources.size !== expectedSourceIds.size ||
    [...sources.keys()].some((id) => !expectedSourceIds.has(id)) ||
    sources.get("pgv")?.name !== "protoc-gen-validate"
  ) {
    throw new Error("bad source ids");
  }
  for (const file of manifest.files) {
    const source = sources.get(file.sourceId);
    if (source === undefined || source.license !== file.license) throw new Error("bad file source");
    const path = checkedChild(protosRoot, file.path);
    await readTrustedFile(path, protosRoot, { sha256: file.sha256 });
  }
}

async function verifyLicenseNotices(manifest: Manifest): Promise<void> {
  const expected = new Set(manifest.license_notices.map((notice) => notice.path));
  const actual = new Set(
    (await readdir(checkedChild(assetRoot, "LICENSES"), { withFileTypes: true })).map((entry) => {
      if (entry.isSymbolicLink() || !entry.isFile()) throw new Error("bad license notice");
      return `LICENSES/${entry.name}`;
    }),
  );
  if (actual.size !== expected.size || [...actual].some((path) => !expected.has(path)))
    throw new Error("license set mismatch");
  for (const notice of manifest.license_notices) {
    await readTrustedFile(checkedChild(assetRoot, notice.path), assetRoot, { sha256: notice.sha256 });
  }
}

async function verifyDescriptor(manifest: Manifest): Promise<void> {
  const descriptor = await readTrustedFile(descriptorPath, assetRoot, {
    exactSize: expectedDescriptorSize,
    sha256: expectedDescriptorSha256,
  });
  assertDescriptorFileNames(descriptor, manifest.descriptor.file_names);
  await readTrustedFile(checkedChild(assetRoot, manifest.descriptor.sha256_file.path), assetRoot, {
    exactSize: 126,
    sha256: manifest.descriptor.sha256_file.sha256,
  });
}

async function verifyLoader(): Promise<void> {
  const descriptor = await readTrustedFile(descriptorPath, assetRoot, {
    exactSize: expectedDescriptorSize,
    sha256: expectedDescriptorSha256,
  });
  assertPackageVersions();
  const definition = protoLoader.loadFileDescriptorSetFromBuffer(descriptor, loaderOptions());
  if (definition["envoy.service.auth.v3.Authorization"] === undefined) throw new Error("missing package service");
  const loaded = grpc.loadPackageDefinition(definition) as Record<string, unknown>;
  const check = serviceCheck(loaded);
  if (check?.path !== expectedServicePath || check.requestStream !== false || check.responseStream !== false) {
    throw new Error("service assertion failed");
  }
  const request = {
    attributes: { request: { http: { headers: [{ key: "proxy-authorization", value: "cap" }], method: "GET" } } },
  };
  const roundRequest = object(check.requestDeserialize(check.requestSerialize(request)));
  const attributes = object(roundRequest.attributes);
  const req = object(attributes.request);
  const http = object(req.http);
  if (http.method !== "GET") throw new Error("request roundtrip failed");
  const response = { status: { code: 0, message: "", details: [] }, ok_response: { headers: [] } };
  const roundResponse = object(check.responseDeserialize(check.responseSerialize(response)));
  if (object(roundResponse.status).code !== 0) throw new Error("response roundtrip failed");
}

async function verifyRegeneration(manifest: Manifest): Promise<void> {
  if (platform() !== "linux" || arch() !== "x64") throw new Error("regeneration check requires linux x64");
  const temp = await mkdtemp(join(tmpdir(), "cogs-protoc-"));
  try {
    const archive = join(temp, basename(expectedProtocUrl));
    const unzipDir = join(temp, "protoc");
    await downloadBounded(expectedProtocUrl, archive, 0);
    const actual = createHash("sha256")
      .update(await readFile(archive))
      .digest("hex");
    if (actual !== expectedProtocSha256) throw new Error("protoc hash mismatch");
    await execFile("unzip", ["-q", archive, "-d", unzipDir]);
    const protoc = checkedChild(unzipDir, "bin/protoc");
    const version = await execFile(protoc, ["--version"]);
    if (version.stdout.trim() !== expectedProtocVersion) throw new Error("protoc version mismatch");
    const generated = join(temp, "ext_authz.descriptor.pb");
    await execFile(protoc, [
      "-I",
      protosRoot,
      "--include_imports",
      `--descriptor_set_out=${generated}`,
      manifest.root_proto,
    ]);
    const expected = await readTrustedFile(descriptorPath, assetRoot, {
      exactSize: expectedDescriptorSize,
      sha256: expectedDescriptorSha256,
    });
    const observed = await readFile(generated);
    assertDescriptorFileNames(expected, manifest.descriptor.file_names);
    assertDescriptorFileNames(observed, manifest.descriptor.file_names);
    if (!expected.equals(observed)) throw new Error("regenerated descriptor differs");
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

async function readTrustedFile(
  path: string,
  parent: string,
  bounds: { exactSize?: number; maxSize?: number; sha256?: string },
): Promise<Buffer> {
  const resolved = checkedChild(parent, relative(parent, path));
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error("not a file");
    if (bounds.exactSize !== undefined && stat.size !== bounds.exactSize) throw new Error("size mismatch");
    if (bounds.maxSize !== undefined && stat.size > bounds.maxSize) throw new Error("too large");
    const data = await handle.readFile();
    if (bounds.exactSize !== undefined && data.length !== bounds.exactSize) throw new Error("read size mismatch");
    if (bounds.maxSize !== undefined && data.length > bounds.maxSize) throw new Error("read too large");
    if (bounds.sha256 !== undefined && createHash("sha256").update(data).digest("hex") !== bounds.sha256) {
      throw new Error("hash mismatch");
    }
    return data;
  } finally {
    await handle.close();
  }
}

function checkedChild(parent: string, child: string): string {
  if (isAbsolute(child) || child.split(/[\\/]/u).includes("..")) throw new Error("bad relative path");
  const resolvedParent = resolve(parent);
  const resolved = resolve(resolvedParent, child);
  const rel = relative(resolvedParent, resolved);
  if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) throw new Error("path escaped root");
  return resolved;
}

async function listProtoFiles(directory: string, prefix = ""): Promise<string[]> {
  const entries = await readdir(join(directory, prefix), { withFileTypes: true });
  const output: string[] = [];
  for (const entry of entries) {
    const relativePath = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isSymbolicLink()) throw new Error(`symlink in proto tree: ${relativePath}`);
    if (entry.isDirectory()) output.push(...(await listProtoFiles(directory, relativePath)));
    else if (entry.isFile() && entry.name.endsWith(".proto")) output.push(relativePath);
    else if (entry.isFile()) throw new Error(`unexpected file in proto tree: ${relativePath}`);
  }
  return output.sort();
}

async function downloadBounded(url: string, destination: string, redirects: number): Promise<void> {
  if (redirects > 3) throw new Error("too many redirects");
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || (redirects === 0 && url !== expectedProtocUrl))
    throw new Error("bad download url");
  let settled = false;
  try {
    await new Promise<void>((resolvePromise, reject) => {
      const request = get(parsed, (response) => {
        const status = response.statusCode ?? 0;
        if ([301, 302, 303, 307, 308].includes(status)) {
          response.resume();
          const location = response.headers.location;
          if (location === undefined) reject(new Error("redirect without location"));
          else {
            const next = new URL(location, parsed);
            if (next.protocol !== "https:") reject(new Error("non-https redirect"));
            else downloadBounded(next.toString(), destination, redirects + 1).then(resolvePromise, reject);
          }
          return;
        }
        if (status !== 200) {
          response.resume();
          reject(new Error(`download failed ${status}`));
          return;
        }
        const output = createWriteStream(destination, { flags: "wx" });
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > maxProtocBytes) {
            request.destroy(new Error("download too large"));
            output.destroy(new Error("download too large"));
          }
        });
        response.pipe(output);
        output.on("finish", () => output.close((error) => (error ? reject(error) : resolvePromise())));
        output.on("error", reject);
      });
      request.setTimeout(30_000, () => request.destroy(new Error("download timeout")));
      request.on("error", reject);
    });
    settled = true;
  } finally {
    if (!settled) await unlink(destination).catch(() => undefined);
  }
}

function assertDescriptorFileNames(descriptor: Buffer, expected: readonly string[]): void {
  const decoded = decodeFileDescriptorSet(descriptor);
  const files = decoded.file;
  if (!Array.isArray(files)) throw new Error("bad descriptor file set");
  const actual = files.map((file) => {
    const descriptorFile = object(file);
    if (typeof descriptorFile.name !== "string") throw new Error("bad descriptor file name");
    return descriptorFile.name;
  });
  if (actual.length !== expected.length || actual.some((name, index) => name !== expected[index])) {
    throw new Error("descriptor file name mismatch");
  }
}

function decodeFileDescriptorSet(descriptor: Buffer): Record<string, unknown> {
  const protobufDescriptor = object(protoLoaderPackageRequire("protobufjs/ext/descriptor"));
  const fileDescriptorSet = callableObject(protobufDescriptor.FileDescriptorSet);
  const decode = fileDescriptorSet.decode;
  if (typeof decode !== "function") throw new Error("descriptor decoder unavailable");
  return object(decode.call(fileDescriptorSet, descriptor));
}

function serviceCheck(loaded: Record<string, unknown>): grpc.MethodDefinition<unknown, unknown> {
  const envoy = object(loaded.envoy);
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

function assertPackageVersions(): void {
  const grpcPackage = packageVersion("@grpc/grpc-js/package.json");
  const loaderPackage = packageVersion("@grpc/proto-loader/package.json");
  if (grpcPackage !== expectedGrpcVersion || loaderPackage !== expectedProtoLoaderVersion) {
    throw new Error("package version mismatch");
  }
}

function packageVersion(specifier: string): string {
  const loaded = grpcPackageRequire(specifier) as { version?: unknown };
  if (typeof loaded.version !== "string") throw new Error("bad package metadata");
  return loaded.version;
}

const grpcPackageRequire = (await import("node:module")).createRequire(import.meta.url);
const protoLoaderPackageRequire = (await import("node:module")).createRequire(
  grpcPackageRequire.resolve("@grpc/proto-loader/package.json"),
);

function assertManifest(manifest: Manifest): void {
  if (manifest.version !== expectedVersion) throw new Error("bad manifest");
  if (
    manifest.descriptor.sha256 !== expectedDescriptorSha256 ||
    manifest.descriptor.size_bytes !== expectedDescriptorSize ||
    manifest.descriptor.include_imports !== true ||
    manifest.descriptor.include_source_info !== false
  ) {
    throw new Error("bad descriptor manifest");
  }
  if (
    manifest.protoc.linux_x86_64_url !== expectedProtocUrl ||
    manifest.protoc.linux_x86_64_sha256 !== expectedProtocSha256 ||
    manifest.protoc.reported_version !== expectedProtocVersion
  ) {
    throw new Error("bad protoc manifest");
  }
  if (
    manifest.loader.grpc_js_version !== expectedGrpcVersion ||
    manifest.loader.proto_loader_version !== expectedProtoLoaderVersion ||
    manifest.loader.method !== "loadFileDescriptorSetFromBuffer" ||
    manifest.loader.service_path !== expectedServicePath ||
    manifest.loader.request_stream !== false ||
    manifest.loader.response_stream !== false ||
    manifest.loader.options.keepCase !== true ||
    manifest.loader.options.longs !== "String" ||
    manifest.loader.options.enums !== "String" ||
    manifest.loader.options.defaults !== false ||
    manifest.loader.options.oneofs !== true ||
    manifest.loader.options.json !== false ||
    manifest.loader.options.includeDirs.length !== 0
  ) {
    throw new Error("bad loader manifest");
  }
  if (
    manifest.descriptor.sha256_file.path !== "ext_authz.descriptor.sha256" ||
    manifest.descriptor.sha256_file.sha256 !== "e0e398f42a7444db961d6e0e0688a7704ef57f2ac3c73a3f6c1fe05f3b2292ad"
  ) {
    throw new Error("bad descriptor sha file manifest");
  }
  if (
    manifest.license_notices.length !== expectedLicenseNoticePaths.size ||
    manifest.license_notices.some((notice) => !expectedLicenseNoticePaths.has(notice.path))
  ) {
    throw new Error("bad license notices");
  }
  if (manifest.descriptor.file_names.length !== 25 || manifest.files.length !== 25) throw new Error("bad file count");
  if (manifest.descriptor.file_names.some((file, index) => file !== manifest.files[index]?.path)) {
    throw new Error("file order mismatch");
  }
}

interface Manifest {
  version: string;
  root_proto: string;
  descriptor: {
    path: string;
    sha256: string;
    size_bytes: number;
    include_imports: boolean;
    include_source_info: boolean;
    file_names: string[];
    sha256_file: { path: string; sha256: string };
  };
  protoc: { linux_x86_64_url: string; linux_x86_64_sha256: string; reported_version: string };
  loader: {
    grpc_js_version: string;
    proto_loader_version: string;
    method: string;
    service_path: string;
    request_stream: boolean;
    response_stream: boolean;
    options: {
      keepCase: boolean;
      longs: string;
      enums: string;
      defaults: boolean;
      oneofs: boolean;
      json: boolean;
      includeDirs: string[];
    };
  };
  sources: Array<{ id: string; name: string; license: string }>;
  files: Array<{ path: string; sha256: string; sourceId: string; license: string }>;
  license_notices: Array<{ path: string; sha256: string }>;
}

await main();
