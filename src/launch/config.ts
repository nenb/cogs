import { createRequire } from "node:module";
import type { Ajv as AjvCore, ErrorObject, Options } from "ajv";
import integrationSchema from "../../schemas/integration-v1alpha1.json" with { type: "json" };
import launchSchema from "../../schemas/launch-v1alpha1.json" with { type: "json" };

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;

export type Json = null | boolean | number | string | Json[] | { readonly [key: string]: Json };

export interface LaunchConfig {
  readonly version: "cogs.dev/v1alpha1";
  readonly user_id: string;
  readonly session_id: string;
  readonly workspace_id: string;
  readonly sandbox: {
    readonly ssh_endpoint: string;
    readonly ssh_host_key: string;
    readonly client_key_path: string;
    readonly proxy_auth_handle: string;
  };
  readonly model: {
    readonly provider: string;
    readonly id: string;
    readonly credential_handle: string;
  };
  readonly skills: {
    readonly shared_revision: string;
    readonly shared_path: "/shared/skills";
    readonly user_revision: string;
    readonly user_path: "/user/skills";
  };
  readonly integrations: readonly Json[];
  readonly limits: {
    readonly cpu: number;
    readonly memory_bytes: number;
    readonly tool_timeout_seconds: number;
    readonly max_tool_output_bytes: number;
  };
}

export class LaunchConfigError extends Error {
  public readonly code = "COGS_LAUNCH_CONFIG_INVALID";
  public readonly issues: readonly {
    readonly instancePath: string;
    readonly keyword: string;
    readonly schemaPath: string;
  }[];

  public constructor(
    issues: readonly { readonly instancePath: string; readonly keyword: string; readonly schemaPath: string }[],
  ) {
    super(`invalid launch document (${issues.length} schema issue${issues.length === 1 ? "" : "s"})`);
    this.name = "LaunchConfigError";
    this.issues = issues;
  }
}

const ajv = new Ajv2020({
  allErrors: true,
  coerceTypes: false,
  removeAdditional: false,
  useDefaults: false,
  strictSchema: false,
  validateFormats: false,
});
ajv.addSchema(integrationSchema);
const validateLaunch = ajv.compile<LaunchConfig>(launchSchema);

export function validateLaunchConfig(input: unknown): LaunchConfig {
  let candidate: unknown;
  try {
    candidate = structuredClone(input);
  } catch {
    throw new LaunchConfigError([{ instancePath: "", keyword: "cloneable", schemaPath: "#" }]);
  }
  if (!validateLaunch(candidate)) {
    throw new LaunchConfigError(
      (validateLaunch.errors ?? []).map((error: ErrorObject) => ({
        instancePath: error.instancePath,
        keyword: error.keyword,
        schemaPath: error.schemaPath,
      })),
    );
  }
  return deepFreeze(candidate as LaunchConfig);
}

export function deepFreeze<T>(value: T): T {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
  const object = value as Record<PropertyKey, unknown>;
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze(object[key]);
  }
  return Object.freeze(value);
}
