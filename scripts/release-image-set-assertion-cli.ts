import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import {
  canonicalReleaseImageSetAssertionBytes,
  classifyReleaseImageSetAssertion,
  finalizeReleaseImageSetAssertion,
  type ReleaseImageSetAssertionJson,
} from "./release-image-set-assertion.ts";

function usage(): never {
  throw new Error(
    "usage: release-image-set-assertion-cli.ts finalize <draft.json> <assertion.json> | classify <assertion.json>",
  );
}

function boundedFile(path: string | undefined): Buffer {
  if (path === undefined) usage();
  const state = lstatSync(path);
  if (!state.isFile() || state.isSymbolicLink() || state.nlink !== 1 || state.size < 1 || state.size > 1024 * 1024) {
    throw new Error("bounded regular assertion file required");
  }
  return readFileSync(path);
}

const [command, inputPath, outputPath, ...extra] = process.argv.slice(2);
try {
  if (extra.length !== 0) usage();
  if (command === "finalize") {
    if (outputPath === undefined) usage();
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(boundedFile(inputPath))) as unknown;
    writeFileSync(outputPath, finalizeReleaseImageSetAssertion(parsed), { flag: "wx", mode: 0o600 });
    const result = classifyReleaseImageSetAssertion(Uint8Array.from(boundedFile(outputPath)));
    if (!result.record_valid) throw new Error("finalized assertion record did not classify as valid");
    process.stdout.write(
      Buffer.from(canonicalReleaseImageSetAssertionBytes(result as unknown as ReleaseImageSetAssertionJson)),
    );
  } else if (command === "classify") {
    if (outputPath !== undefined) usage();
    const result = classifyReleaseImageSetAssertion(Uint8Array.from(boundedFile(inputPath)));
    process.stdout.write(
      Buffer.from(canonicalReleaseImageSetAssertionBytes(result as unknown as ReleaseImageSetAssertionJson)),
    );
    if (!result.record_valid) process.exitCode = 1;
  } else {
    usage();
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : "image-set assertion operation failed"}\n`);
  process.exitCode = 1;
}
