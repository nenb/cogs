import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const dockerfiles = ["images/worker/Dockerfile", "images/sandbox/Dockerfile", "dev/insecure-sandbox/Dockerfile"];
for (const relativePath of dockerfiles) {
  const content = readFileSync(resolve(import.meta.dirname, "..", relativePath), "utf8");
  const externalStages: string[] = [];
  const stageAliases = new Set<string>();
  const instructions: Array<{ line: number; text: string }> = [];
  let logical = "";
  let logicalStart = 0;

  for (const [index, physical] of content.split("\n").entries()) {
    if (logical === "") logicalStart = index + 1;
    const continued = /\\\s*$/.test(physical);
    const fragment = continued ? physical.replace(/\\\s*$/, "") : physical;
    logical += `${logical === "" ? "" : " "}${fragment.trim()}`;
    if (!continued) {
      instructions.push({ line: logicalStart, text: logical });
      logical = "";
    }
  }
  assert.equal(logical, "", `${relativePath}:${logicalStart} has an unterminated Dockerfile instruction`);

  for (const instruction of instructions) {
    if (!/^FROM\b/i.test(instruction.text)) continue;
    const match = instruction.text.match(/^FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+(\S+))?\s*$/i);
    assert.ok(match, `${relativePath}:${instruction.line} has an unsupported or invalid FROM instruction`);
    const image = match[1];
    const alias = match[2]?.toLowerCase();
    assert.ok(image, `${relativePath}:${instruction.line} has an invalid FROM instruction`);
    assert.doesNotMatch(image, /\$/, `${relativePath}:${instruction.line} must not derive a base image from ARG`);

    if (image !== "scratch" && !stageAliases.has(image.toLowerCase())) externalStages.push(image);
    if (alias) stageAliases.add(alias);
  }

  assert.ok(externalStages.length > 0, `${relativePath} has no external base image`);
  for (const image of externalStages) {
    assert.match(image, /@sha256:[a-f0-9]{64}$/, `${relativePath} external base ${image} must be pinned by digest`);
    assert.doesNotMatch(image, /:latest(?:@|$)/, `${relativePath} must not use latest tags`);
  }
}

console.log(`Verified external base-image digest pinning for ${dockerfiles.length} image definitions.`);
