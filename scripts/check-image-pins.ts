import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const dockerfiles = ["images/worker/Dockerfile", "images/sandbox/Dockerfile"];
for (const relativePath of dockerfiles) {
  const content = readFileSync(resolve(import.meta.dirname, "..", relativePath), "utf8");
  const externalStages: string[] = [];
  const stageAliases = new Set<string>();

  for (const [index, line] of content.split("\n").entries()) {
    const match = line.match(/^\s*FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+(\S+))?\s*$/i);
    if (!match) continue;
    const image = match[1];
    const alias = match[2]?.toLowerCase();
    assert.ok(image, `${relativePath}:${index + 1} has an invalid FROM instruction`);
    assert.doesNotMatch(image, /\$/, `${relativePath}:${index + 1} must not derive a base image from ARG`);

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
