import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  generateReleaseImageSetAssertionSchema,
  generateReleaseImageSetWorkflowPins,
} from "./release-image-set-pins.ts";

const root = resolve(import.meta.dirname, "..");
const targets = [
  {
    path: resolve(root, "schemas/release-image-set-assertion-v1.json"),
    generate: generateReleaseImageSetAssertionSchema,
  },
  {
    path: resolve(root, ".github/workflows/release-images.yml"),
    generate: generateReleaseImageSetWorkflowPins,
  },
] as const;

const operation = process.argv[2];
if (process.argv.length !== 3 || (operation !== "check" && operation !== "write")) {
  throw new Error("usage: release-image-set-pins-cli.ts <check|write>");
}

for (const target of targets) {
  const source = readFileSync(target.path, "utf8");
  const generated = target.generate(source);
  if (operation === "write") {
    writeFileSync(target.path, generated);
  } else if (source !== generated) {
    throw new Error(`release pin generated mirror drift: ${target.path}`);
  }
}
