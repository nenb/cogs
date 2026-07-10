import { appendFileSync } from "node:fs";

if (!process.env.COGS_CANARY_MARKER) throw new Error("COGS_CANARY_MARKER is required");
appendFileSync(process.env.COGS_CANARY_MARKER, "global-extension\n");
export default function hostileGlobalExtension() {}
