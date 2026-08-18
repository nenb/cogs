/* biome-ignore-all lint/suspicious/noExplicitAny: hostile schema mutations deliberately cross JSON types */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { test } from "node:test";
import type { Ajv as AjvCore, Options, ValidateFunction } from "ajv";

const root = process.cwd();
const portable = join(root, "test/aws-stage2-completion-local-result.py");
const producer = join(root, "deploy/aws-feasibility/remote/completion_local_full.py");
const schemaName = "stage2-workload-local-qualification-v2.json";
const schemaPath = join(root, "schemas", schemaName);
const fixture = (name: string): Record<string, any> =>
  JSON.parse(readFileSync(join(root, "test/fixtures/stage2-completion", name), "utf8")) as Record<string, any>;
const clone = (value: Record<string, any>): Record<string, any> => structuredClone(value);

const LOCAL_RESULT_SCHEMA_REGISTRY = [
  { version: "cogs.stage2-workload-local-qualification/v2", file: schemaName },
] as const;

function codecAccepts(value: unknown): boolean {
  const result = spawnSync("python3", ["-B", portable, "--probe"], {
    cwd: root,
    input: JSON.stringify(value),
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
  return result.status === 0;
}

function compile(): ValidateFunction {
  const require = createRequire(import.meta.url);
  const Ajv2020 = require("ajv/dist/2020.js") as new (options?: Options) => AjvCore;
  return new Ajv2020({ allErrors: true, strict: true, strictRequired: false, ownProperties: true }).compile(
    JSON.parse(readFileSync(schemaPath, "utf8")) as object,
  );
}

for (const optimized of [false, true]) {
  test(`local qualification result state machine is strict${optimized ? " under python -O" : ""}`, () => {
    const result = spawnSync("python3", [...(optimized ? ["-O"] : []), "-B", portable], {
      cwd: root,
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /completion local result codec tests passed/u);
  });
}

test("schema registry and codec accept the same canonical shared fixtures", () => {
  const validate = compile();
  assert.deepEqual(
    LOCAL_RESULT_SCHEMA_REGISTRY.map(({ file }) => file),
    [schemaName],
  );
  for (const entry of LOCAL_RESULT_SCHEMA_REGISTRY) {
    const schema = JSON.parse(readFileSync(join(root, "schemas", entry.file), "utf8")) as {
      properties: { version: { const: string } };
    };
    assert.equal(schema.properties.version.const, entry.version);
  }
  for (const name of ["local-result-v2-pass.json", "local-result-v2-failure.json"]) {
    const value = fixture(name);
    assert.equal(validate(value), true, `${name}: ${JSON.stringify(validate.errors)}`);
    assert.equal(codecAccepts(value), true, name);
  }
  const catalog = spawnSync("python3", ["-B", portable, "--catalog"], {
    cwd: root,
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });
  assert.equal(catalog.status, 0, catalog.stderr);
  for (const value of JSON.parse(catalog.stdout) as Record<string, any>[]) {
    assert.equal(codecAccepts(value), true, String(value.failure_code));
    assert.equal(validate(value), true, `${String(value.failure_code)}: ${JSON.stringify(validate.errors)}`);
  }
});

test("schema prefix structure and codec reject the same structural hostile matrix", () => {
  const validate = compile();
  const pass = fixture("local-result-v2-pass.json");
  const cases: Array<[string, (value: Record<string, any>) => void]> = [
    [
      "root extra",
      (value) => {
        value.extra = true;
      },
    ],
    [
      "row extra",
      (value) => {
        value.timings.git[0].extra = true;
      },
    ],
    [
      "ordinal duplicate",
      (value) => {
        value.timings.git[1].ordinal = 1;
      },
    ],
    [
      "ordinal reversed",
      (value) => {
        value.timings.git.reverse();
      },
    ],
    [
      "teardown duplicate",
      (value) => {
        value.teardown[1].phase = value.teardown[0].phase;
      },
    ],
    [
      "teardown reversed",
      (value) => {
        value.teardown.reverse();
      },
    ],
    [
      "missing timing",
      (value) => {
        value.timings.install.pop();
      },
    ],
    [
      "duration zero",
      (value) => {
        value.timings.git[0].duration_ns = 0;
      },
    ],
    [
      "duration overflow",
      (value) => {
        value.timings.git[0].duration_ns = 3_600_000_000_001;
      },
    ],
    [
      "duration float",
      (value) => {
        value.timings.git[0].duration_ns = 1.5;
      },
    ],
    [
      "duration boolean",
      (value) => {
        value.timings.git[0].duration_ns = true;
      },
    ],
    [
      "authority",
      (value) => {
        value.authority = "authoritative-local";
      },
    ],
    [
      "classification",
      (value) => {
        value.validation_classification = "schema-only";
      },
    ],
  ];
  for (const [name, mutate] of cases) {
    const value = clone(pass);
    mutate(value);
    assert.equal(validate(value), false, `schema accepted ${name}`);
    assert.equal(codecAccepts(value), false, `codec accepted ${name}`);
  }
});

test("schema-only semantic relations are explicitly classified and codec-required", () => {
  const validate = compile();
  const pass = fixture("local-result-v2-pass.json");
  const failure = fixture("local-result-v2-failure.json");
  const semanticCases: Array<[string, Record<string, any>]> = [];
  const add = (name: string, base: Record<string, any>, mutate: (value: Record<string, any>) => void): void => {
    const value = clone(base);
    mutate(value);
    semanticCases.push([name, value]);
  };
  add("mixed source", pass, (value) => {
    value.operation.source_head = "b".repeat(40);
  });
  add("unrecomputed binding", pass, (value) => {
    value.operation.operation_sha256 = "d".repeat(64);
  });
  add("unrecomputed summary", pass, (value) => {
    value.timing_summaries.git.total_ns = 1;
  });
  add("work without operation", failure, (value) => {
    value.timings.git[0] = {
      ordinal: 1,
      duration_ns: 1,
      outcome: "failure",
      deletion: "absent",
      binding_sha256: "d".repeat(64),
    };
  });
  add("SSH without KVM", pass, (value) => {
    value.result = "failure";
    value.qualified = false;
    value.failure_code = "kvm";
    value.admission.kvm = "failure";
  });
  add("install after failed build", pass, (value) => {
    value.result = "failure";
    value.qualified = false;
    value.failure_code = "build-sample";
    value.timings.build[0].outcome = "failure";
  });
  add("uncertainty retired and absent", pass, (value) => {
    value.result = "failure";
    value.qualified = false;
    value.failure_code = "uncertain";
    value.operation.status = "uncertain";
  });
  add("nonmonotonic teardown", pass, (value) => {
    value.result = "failure";
    value.qualified = false;
    value.failure_code = "cleanup";
    value.teardown[0].outcome = "not-reached";
  });
  add("wrong first failure", failure, (value) => {
    value.failure_code = "ssh";
  });
  for (const [name, value] of semanticCases) {
    assert.equal(validate(value), true, `schema unexpectedly encoded semantic relation ${name}`);
    assert.equal(codecAccepts(value), false, `codec accepted ${name}`);
    assert.equal(value.authority, "non-authoritative-local-qualification-report-data");
    assert.equal(
      value.validation_classification,
      "schema-insufficient-independent-semantics-and-private-receipt-required",
    );
    assert.ok(value.limitations.includes("requires-exact-private-receipt-and-custody-validation"));
  }
});

test("zero-argument stub remains blocked and correction stays within the global cap", () => {
  const source = readFileSync(producer, "utf8");
  for (const args of [[], ["report.json"], ["--qualified"]]) {
    const result = spawnSync("python3", ["-B", producer, ...args], {
      cwd: root,
      input: '{"qualified":true}\n',
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
    });
    assert.equal(result.status, 3);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
  }
  assert.match(source, /^def main\(\):$/mu);
  assert.doesNotMatch(source, /argparse|sys\.stdin|input\(|open_fixed_coordinator|run_fixed_local_qualification/u);
  assert.doesNotMatch(source, /boto|AWS_|requests|urllib|socket|subprocess|terraform|tofu/iu);
  const retained = spawnSync(
    "bash",
    [
      "-c",
      String.raw`find deploy/aws-feasibility -type f \( -name '*.py' -o -name '*.sh' -o -name '*.tf' \) -print0 | xargs -0 wc -l | tail -1`,
    ],
    { cwd: root, encoding: "utf8" },
  );
  assert.equal(retained.status, 0, retained.stderr);
  assert.ok(Number.parseInt(retained.stdout.trim(), 10) < 45_000, retained.stdout);
});
