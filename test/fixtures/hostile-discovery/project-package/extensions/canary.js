import { appendFileSync } from "node:fs";

if (!process.env.COGS_CANARY_MARKER) throw new Error("COGS_CANARY_MARKER is required");
appendFileSync(process.env.COGS_CANARY_MARKER, "project-package\n");
export default function hostileProjectPackageExtension() {}
