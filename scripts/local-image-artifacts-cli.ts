import { createHash } from "node:crypto";
import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import {
  canonicalLocalImageBytes,
  classifyLocalImageArtifactPackage,
  compareOciLayouts,
  type ImageRole,
  imageLicenseInventory,
  type JsonValue,
  localProvenanceStatement,
  signatureAbsenceEvidence,
} from "./local-image-artifacts.ts";

function usage(): never {
  throw new Error(
    "usage: local-image-artifacts-cli.ts verify <worker|sandbox> <layout-a> <layout-b> <output> | licenses <worker|sandbox> <sbom> <output> | signature-absence <worker|sandbox> <output> | provenance <worker|sandbox> <graph> <source> <builder> <materials> <output> | classify <package> <artifact-root>",
  );
}

function role(value: string | undefined): ImageRole {
  if (value !== "worker" && value !== "sandbox") usage();
  return value;
}

function boundedBytes(path: string, maximum: number): Buffer {
  const state = lstatSync(path);
  if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1 || state.size < 1 || state.size > maximum) {
    throw new Error("bounded regular input file required");
  }
  return readFileSync(path);
}

function json(path: string): Record<string, unknown> {
  const value = JSON.parse(boundedBytes(path, 8 * 1024 * 1024).toString("utf8")) as unknown;
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("JSON object required");
  return value as Record<string, unknown>;
}

function output(path: string | undefined, value: JsonValue): void {
  if (path === undefined) usage();
  writeFileSync(path, canonicalLocalImageBytes(value), { flag: "wx", mode: 0o600 });
}

const [command, ...args] = process.argv.slice(2);
try {
  if (command === "verify") {
    const selectedRole = role(args[0]);
    if (args.length !== 4 || args[1] === undefined || args[2] === undefined) usage();
    output(args[3], compareOciLayouts(args[1], args[2], selectedRole) as unknown as JsonValue);
  } else if (command === "licenses") {
    const selectedRole = role(args[0]);
    if (args.length !== 3 || args[1] === undefined) usage();
    output(args[2], imageLicenseInventory(selectedRole, boundedBytes(args[1], 256 * 1024 * 1024)));
  } else if (command === "signature-absence") {
    const selectedRole = role(args[0]);
    if (args.length !== 2) usage();
    output(args[1], signatureAbsenceEvidence(selectedRole));
  } else if (command === "provenance") {
    const selectedRole = role(args[0]);
    if (
      args.length !== 6 ||
      args[1] === undefined ||
      args[2] === undefined ||
      args[3] === undefined ||
      args[4] === undefined
    )
      usage();
    const graphBytes = boundedBytes(args[1], 8 * 1024 * 1024);
    const graph = JSON.parse(graphBytes.toString("utf8")) as { attempt_a?: { oci_subject_manifest_digest?: unknown } };
    const source = json(args[2]) as {
      commit_sha: string;
      tree_sha: string;
      inventory_sha256: string;
      source_date_epoch: number;
    };
    const builder = json(args[3]) as { buildx_version: string; buildkit_version: string };
    const materials = json(args[4]) as {
      dockerfile: { path: string; sha256: string };
      base: { reference: string; index_digest: string; linux_amd64_manifest_digest: string };
    };
    const subject = graph.attempt_a?.oci_subject_manifest_digest;
    if (typeof subject !== "string") throw new Error("graph subject digest required");
    const graphSha = createHash("sha256").update(graphBytes).digest("hex");
    output(args[5], localProvenanceStatement(selectedRole, subject, source, graphSha, builder, materials));
  } else if (command === "classify") {
    if (args.length !== 2 || args[0] === undefined || args[1] === undefined) usage();
    const result = classifyLocalImageArtifactPackage(Uint8Array.from(boundedBytes(args[0], 8 * 1024 * 1024)), args[1]);
    process.stdout.write(Buffer.from(canonicalLocalImageBytes(result as unknown as JsonValue)));
    if (!result.valid) process.exitCode = 1;
  } else {
    usage();
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "local image artifact operation failed"}\n`);
  process.exitCode = 1;
}
