import { execFileSync } from "node:child_process";
import { ENVOY_IMAGE } from "../dev/launcher/envoy-egress.ts";
import { OPENBAO_IMAGE } from "../dev/openbao-model-auth/image.ts";

export const LAUNCHER_DOCKER = "/usr/bin/docker" as const;
export const LAUNCHER_IMAGE_ENV = Object.freeze({ HOME: "/tmp" });
export const LAUNCHER_REQUIRED_IMAGES = Object.freeze([OPENBAO_IMAGE, ENVOY_IMAGE]);

function digestRef(image: string): string {
  const at = image.indexOf("@sha256:");
  if (at < 1 || !/^sha256:[a-f0-9]{64}$/u.test(image.slice(at + 1))) throw new Error("invalid launcher image pin");
  return `${image.slice(0, at).replace(/:[^/:@]+$/u, "")}@${image.slice(at + 1)}`;
}

export function verifyImageInspect(image: string, inspectJson: string): void {
  const expected = digestRef(image);
  const parsed = JSON.parse(inspectJson) as unknown;
  if (!Array.isArray(parsed) || parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== "object") {
    throw new Error("launcher image prerequisite failed");
  }
  const repoDigests = (parsed[0] as { RepoDigests?: unknown }).RepoDigests;
  if (!Array.isArray(repoDigests) || !repoDigests.every((item) => typeof item === "string")) {
    throw new Error("launcher image prerequisite failed");
  }
  if (!repoDigests.includes(expected)) throw new Error("launcher image prerequisite failed");
}

export function prepareLauncherImages(): void {
  for (const image of LAUNCHER_REQUIRED_IMAGES) {
    execFileSync(LAUNCHER_DOCKER, ["pull", image], {
      env: LAUNCHER_IMAGE_ENV,
      stdio: "ignore",
      shell: false,
      timeout: 300000,
    });
    const inspect = execFileSync(LAUNCHER_DOCKER, ["image", "inspect", image], {
      encoding: "utf8",
      env: LAUNCHER_IMAGE_ENV,
      maxBuffer: 1024 * 1024,
      shell: false,
      timeout: 30000,
    });
    verifyImageInspect(image, inspect);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    prepareLauncherImages();
  } catch {
    process.stderr.write("launcher image prerequisite failed\n");
    process.exitCode = 1;
  }
}
