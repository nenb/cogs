import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  buildStage4RuntimeArtifactEvidence,
  canonicalStage4RuntimeArtifactBytes,
  classifyStage4RuntimeArtifactEvidence,
} from "./stage4-runtime-artifact-closure.ts";

const root = resolve(import.meta.dirname, "..");
const output = resolve(
  root,
  "docs/security-evidence/stage4-offline-readiness-artifacts/authenticated-runtime-artifacts.json",
);

if (process.argv.length !== 2 || realpathSync(process.argv[1] ?? "") !== realpathSync(import.meta.filename)) {
  throw new Error("STAGE4_RUNTIME_ARTIFACT_REGENERATE_ARGUMENTS_FORBIDDEN");
}

const bytes = canonicalStage4RuntimeArtifactBytes(buildStage4RuntimeArtifactEvidence());
const verdict = classifyStage4RuntimeArtifactEvidence(bytes);
if (verdict.reason_code !== "STAGE4_RUNTIME_ARTIFACT_CANDIDATE_CLOSED_AWS_BLOCKED") {
  throw new Error("STAGE4_RUNTIME_ARTIFACT_REGENERATE_INVALID");
}
writeFileSync(output, bytes);
if (!new Uint8Array(readFileSync(output)).every((byte, index) => byte === bytes[index])) {
  throw new Error("STAGE4_RUNTIME_ARTIFACT_REGENERATE_WRITE_MISMATCH");
}
