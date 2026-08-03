import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const PINNED_IMAGE = /^[^\s@]+(?:[^\s@]*)?@sha256:[0-9a-f]{64}$/u;
const HEX_SHA256 = /^[0-9a-f]{64}$/u;
const BUILDX_VERSION = /^v[0-9]+\.[0-9]+\.[0-9]+$/u;
const MANIFEST_KEYS = ["version", "tools"] as const;
const TOOL_KEYS = [
  "buildx_client",
  "buildkit_image",
  "syft_image",
  "trivy_image",
  "trivy_database",
  "trivy_java_database",
  "cosign_image",
] as const;
const BUILDX_KEYS = ["version", "linux_amd64_sha256"] as const;

export type ReleaseImageSetTools = Readonly<{
  buildx_client: Readonly<{
    version: string;
    linux_amd64_sha256: string;
  }>;
  buildkit_image: string;
  syft_image: string;
  trivy_image: string;
  trivy_database: string;
  trivy_java_database: string;
  cosign_image: string;
}>;

export type ReleaseImageSetPinsManifest = Readonly<{
  version: "cogs.release-image-set-pins/v1";
  tools: ReleaseImageSetTools;
}>;

type JsonObject = Record<string, unknown>;

function requireObject(value: unknown, label: string): JsonObject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label}: object required`);
  if (Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`${label}: plain object required`);
  return value as JsonObject;
}

function requireExactKeys(value: JsonObject, expected: readonly string[], label: string): void {
  const actual = Object.keys(value);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label}: exact ordered keys required`);
  }
}

function parseReleaseImageSetPinsManifest(source: string): ReleaseImageSetPinsManifest {
  const parsed = JSON.parse(source) as unknown;
  if (`${JSON.stringify(parsed, null, 2)}\n` !== source)
    throw new Error("release pin manifest: canonical JSON required");
  const manifest = requireObject(parsed, "release pin manifest");
  requireExactKeys(manifest, MANIFEST_KEYS, "release pin manifest");
  if (manifest.version !== "cogs.release-image-set-pins/v1") throw new Error("release pin manifest: version drift");

  const tools = requireObject(manifest.tools, "release pin manifest tools");
  requireExactKeys(tools, TOOL_KEYS, "release pin manifest tools");
  const buildx = requireObject(tools.buildx_client, "release pin manifest Buildx client");
  requireExactKeys(buildx, BUILDX_KEYS, "release pin manifest Buildx client");
  if (typeof buildx.version !== "string" || !BUILDX_VERSION.test(buildx.version)) {
    throw new Error("release pin manifest: invalid Buildx version");
  }
  if (typeof buildx.linux_amd64_sha256 !== "string" || !HEX_SHA256.test(buildx.linux_amd64_sha256)) {
    throw new Error("release pin manifest: invalid Buildx checksum");
  }
  for (const key of TOOL_KEYS.slice(1)) {
    if (typeof tools[key] !== "string" || !PINNED_IMAGE.test(tools[key] as string)) {
      throw new Error(`release pin manifest: invalid ${key}`);
    }
  }

  Object.freeze(buildx);
  Object.freeze(tools);
  return Object.freeze(manifest) as unknown as ReleaseImageSetPinsManifest;
}

export const RELEASE_IMAGE_SET_PINS_MANIFEST_PATH = "config/release-image-set-pins-v1.json";
const root = resolve(import.meta.dirname, "..");
export const RELEASE_IMAGE_SET_PINS = parseReleaseImageSetPinsManifest(
  readFileSync(resolve(root, RELEASE_IMAGE_SET_PINS_MANIFEST_PATH), "utf8"),
);

export const RELEASE_IMAGE_SET_PIN_ENVIRONMENT = Object.freeze({
  BUILDX_VERSION: RELEASE_IMAGE_SET_PINS.tools.buildx_client.version,
  BUILDX_LINUX_AMD64_SHA256: RELEASE_IMAGE_SET_PINS.tools.buildx_client.linux_amd64_sha256,
  BUILDKIT_IMAGE: RELEASE_IMAGE_SET_PINS.tools.buildkit_image,
  SYFT_IMAGE: RELEASE_IMAGE_SET_PINS.tools.syft_image,
  TRIVY_IMAGE: RELEASE_IMAGE_SET_PINS.tools.trivy_image,
  TRIVY_DATABASE: RELEASE_IMAGE_SET_PINS.tools.trivy_database,
  TRIVY_JAVA_DATABASE: RELEASE_IMAGE_SET_PINS.tools.trivy_java_database,
  COSIGN_IMAGE: RELEASE_IMAGE_SET_PINS.tools.cosign_image,
});

function releaseImageSetToolsSchema(tools: ReleaseImageSetTools): JsonObject {
  return {
    type: "object",
    additionalProperties: false,
    required: [...TOOL_KEYS],
    properties: {
      buildx_client: {
        type: "object",
        additionalProperties: false,
        required: [...BUILDX_KEYS],
        properties: {
          version: { const: tools.buildx_client.version },
          linux_amd64_sha256: { const: tools.buildx_client.linux_amd64_sha256 },
        },
      },
      buildkit_image: { const: tools.buildkit_image },
      syft_image: { const: tools.syft_image },
      trivy_image: { const: tools.trivy_image },
      trivy_database: { const: tools.trivy_database },
      trivy_java_database: { const: tools.trivy_java_database },
      cosign_image: { const: tools.cosign_image },
    },
  };
}

export function generateReleaseImageSetAssertionSchema(source: string): string {
  const startMarker = '    "tools": {';
  const endMarker = '    "images": {';
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0 || source.indexOf(startMarker, start + 1) >= 0 || source.indexOf(endMarker, end + 1) >= 0) {
    throw new Error("release assertion schema: unique tools/images boundaries required");
  }
  const renderedObject = JSON.stringify(releaseImageSetToolsSchema(RELEASE_IMAGE_SET_PINS.tools), null, 2)
    .replace(
      '      "required": [\n        "version",\n        "linux_amd64_sha256"\n      ]',
      '      "required": ["version", "linux_amd64_sha256"]',
    )
    .replaceAll("\n", "\n    ");
  return `${source.slice(0, start)}    "tools": ${renderedObject},\n${source.slice(end)}`;
}

const WORKFLOW_START_MARKER = "      # release-image-set-tool-pins:generated-start";
const WORKFLOW_END_MARKER = "      # release-image-set-tool-pins:generated-end";

export function generateReleaseImageSetWorkflowPins(source: string): string {
  const start = source.indexOf(WORKFLOW_START_MARKER);
  const end = source.indexOf(WORKFLOW_END_MARKER, start + WORKFLOW_START_MARKER.length);
  if (
    start < 0 ||
    end < 0 ||
    source.indexOf(WORKFLOW_START_MARKER, start + 1) >= 0 ||
    source.indexOf(WORKFLOW_END_MARKER, end + 1) >= 0
  ) {
    throw new Error("release workflow: unique generated pin markers required");
  }
  const environment = Object.entries(RELEASE_IMAGE_SET_PIN_ENVIRONMENT)
    .map(([key, value]) => `      ${key}: ${value}`)
    .join("\n");
  const replacement = `${WORKFLOW_START_MARKER}\n${environment}\n${WORKFLOW_END_MARKER}`;
  return `${source.slice(0, start)}${replacement}${source.slice(end + WORKFLOW_END_MARKER.length)}`;
}
