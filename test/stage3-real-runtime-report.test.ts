import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { validateSecurityResultSemantics } from "../scripts/security-result-semantics.ts";

async function validator() {
  process.env.COGS_SOURCE_REVISION = "a".repeat(40);
  process.env.COGS_OPENBAO_ADDR = "http://127.0.0.1:8200";
  process.env.COGS_ENVOY_EXECUTABLE = "/tmp/envoy";
  process.env.COGS_ENVOY_IMAGE = `envoyproxy/envoy:v1.38.3@sha256:${"b".repeat(64)}`;
  process.env.COGS_ENVOY_IMAGE_DIGEST = `sha256:${"b".repeat(64)}`;
  process.env.COGS_OPENBAO_IMAGE = `quay.io/openbao/openbao:2.6.0@sha256:${"d".repeat(64)}`;
  process.env.COGS_OPENBAO_RUNTIME_VERSION = "OpenBao v2.6.0";
  process.env.COGS_TRUST_CERT_PATH = "/usr/local/share/ca-certificates/cogs-stage3-real-runtime.crt";
  const module = await import("./egress-conformance/stage3-real-runtime/harness.ts");
  const assertValidRealRuntimeSidecar: (value: unknown) => void = module.assertValidRealRuntimeSidecar;
  return assertValidRealRuntimeSidecar;
}

function validSidecar() {
  return {
    version: "cogs.stage3-real-runtime/v1alpha1",
    source_revision: "a".repeat(40),
    profile: "insecure-container",
    release_eligible: false,
    components: {
      envoy: { version: "1.38.3", image_digest: `sha256:${"b".repeat(64)}`, binary_sha256: `sha256:${"c".repeat(64)}` },
      openbao: { version: "2.6.0", image_digest: `sha256:${"d".repeat(64)}` },
      runtime_manager: { mode: "real" },
    },
    timings: {
      revocation_poll_interval_ms: 500,
      revocation_observation_bound_ms: 20_000,
      harness_replacement_ready_bound_ms: 40_000,
      credential_write_ms: 10,
      credential_changed_callback_ms: 1000,
      credential_changed_drain_probe_ms: 1200,
      harness_replacement_ready_ms: 5000,
      credential_delete_ms: 10,
      revoked_callback_ms: 1000,
      revoked_drain_probe_ms: 1200,
    },
    dependency_modes: {
      identity: "real",
      authorization: "real",
      audit: "real",
      revocation: "real",
      telemetry: "stubbed",
      network_enforcement: "not-applicable",
    },
    network_evidence: { mode: "not-applicable" },
    assertions: {
      openbao_loopback_only: true,
      credential_v1_injected: true,
      credential_v2_injected: true,
      baseline_wrong_capability_denied: true,
      baseline_wrong_path_denied: true,
      proxy_capability_stripped_upstream: true,
      wal_intents_preceded_upstream: true,
      completions_correlated: true,
      credential_change_callback_observed: true,
      revoked_callback_observed: true,
      harness_driven_replacement_after_callback: true,
      old_capability_denied_after_replacement: true,
      new_capability_invalidated_after_revocation: true,
      tmpfs_material_existed_in_scope: true,
      tmpfs_cleanup_verified: true,
      scoped_token_revoked: true,
      root_token_revoked: true,
      private_material_absent_from_reports: true,
      ca_private_key_not_returned: true,
      no_daemon_or_sandbox_replacement_claim: true,
    },
  };
}

test("Stage 3 real-runtime sidecar is strict, explicit, and redacted", async () => {
  const assertValidRealRuntimeSidecar = await validator();
  const sidecar = validSidecar();
  assertValidRealRuntimeSidecar(sidecar);
  assert.equal(JSON.stringify(sidecar).includes("PRIVATE KEY"), false);

  assert.throws(() => assertValidRealRuntimeSidecar({ ...sidecar, escaped: true }));
  assert.throws(() =>
    assertValidRealRuntimeSidecar({ ...sidecar, components: { ...sidecar.components, extra: true } }),
  );
  assert.throws(() =>
    assertValidRealRuntimeSidecar({
      ...sidecar,
      dependency_modes: { ...sidecar.dependency_modes, telemetry: "real" },
    }),
  );
  const kvmSidecar = structuredClone(sidecar) as ReturnType<typeof validSidecar> & {
    profile: "insecure-container" | "linux-kvm";
    dependency_modes: ReturnType<typeof validSidecar>["dependency_modes"] & {
      network_enforcement: "not-applicable" | "real";
    };
    network_evidence: Record<string, unknown> & { relay?: Record<string, unknown> };
    assertions: ReturnType<typeof validSidecar>["assertions"] & Record<string, boolean>;
  };
  kvmSidecar.profile = "linux-kvm";
  kvmSidecar.dependency_modes.network_enforcement = "real";
  Object.assign(kvmSidecar.assertions, {
    kvm_guest_proxy_allowed_v1: true,
    kvm_guest_proxy_allowed_v2: true,
    kvm_bypass_matrix_denied: true,
    kvm_relay_no_target_denied: true,
    kvm_relay_identity_verified: true,
    kvm_relay_cleanup_verified: true,
  });
  kvmSidecar.network_evidence = {
    mode: "linux-kvm",
    authority: "authoritative-local",
    guest_firewall_trusted: false,
    host_firewall_enforced: true,
    kvm: {
      kvm_present: true,
      kvm_enabled: true,
      guest_root: true,
      distinct_boot_ids: true,
      guest_kernel: "6.18.35",
      guest_image_sha512: "a".repeat(128),
      host_ip: "192.0.2.1",
      guest_ip: "192.0.2.2",
      proxy_port: 18080,
    },
    openbao_actual_port_denied: true,
    bypass_denials: {
      "unset-proxy": true,
      "direct-ipv4": true,
      "direct-ipv6": true,
      "udp-quic": true,
      "alternate-tcp": true,
      openbao: true,
      "cogs-api": true,
      "proxy-admin": true,
      "arbitrary-dns": true,
      "dns-over-https": true,
      "cloud-metadata": true,
    },
    relay: {
      bindHost: "192.0.2.1",
      bindPort: 18080,
      activeTarget: null,
      registeredTargets: [10001, 10002],
      acceptedConnections: 2,
      deniedConnections: 1,
      switchedTargets: 2,
      activeSockets: 0,
      maxActiveSockets: 32,
      ready: false,
      poisoned: false,
      closed: true,
    },
  };
  assertValidRealRuntimeSidecar(kvmSidecar);
  assert.throws(() =>
    assertValidRealRuntimeSidecar({
      ...kvmSidecar,
      network_evidence: {
        ...kvmSidecar.network_evidence,
        relay: { ...kvmSidecar.network_evidence.relay, bindPort: 18081 },
      },
    }),
  );
  const missing = structuredClone(sidecar);
  delete (missing.assertions as Partial<typeof missing.assertions>).tmpfs_cleanup_verified;
  assert.throws(() => assertValidRealRuntimeSidecar(missing));
  const falseAssertion = structuredClone(sidecar);
  falseAssertion.assertions.scoped_token_revoked = false;
  assert.throws(() => assertValidRealRuntimeSidecar(falseAssertion));
  const hostile = structuredClone(sidecar);
  (hostile.assertions as Record<string, unknown>)["tmpfs_cleanup_verified\nsecret"] = true;
  assert.throws(() => assertValidRealRuntimeSidecar(hostile));
  const hidden = structuredClone(sidecar);
  Object.defineProperty(hidden, "hidden", { value: true, enumerable: false });
  assert.throws(() => assertValidRealRuntimeSidecar(hidden));
  const symbolExtra = structuredClone(sidecar) as typeof sidecar & { [Symbol.toStringTag]?: string };
  symbolExtra[Symbol.toStringTag] = "hostile";
  assert.throws(() => assertValidRealRuntimeSidecar(symbolExtra));
});

test("Stage 3 real-runtime report result stays stubbed while telemetry is stubbed", () => {
  assert.deepEqual(
    validateSecurityResultSemantics({
      result: "stubbed",
      release_eligible: false,
      dependency_modes: {
        authorization: "real",
        audit: "real",
        identity: "real",
        revocation: "real",
        telemetry: "stubbed",
        network_enforcement: "not-applicable",
      },
    }),
    [],
  );
  assert.deepEqual(
    validateSecurityResultSemantics({
      result: "pass",
      release_eligible: false,
      dependency_modes: { revocation: "real", telemetry: "stubbed" },
    }),
    ["a passing test with a stubbed dependency requires result=stubbed"],
  );
});

test("Stage 3 real-runtime OpenBao PKI role is explicit least privilege", async () => {
  const harness = await readFile("test/egress-conformance/stage3-real-runtime/harness.ts", "utf8");
  assert.match(harness, /allowed_domains: \["localhost"\]/);
  assert.match(harness, /allow_bare_domains: true/);
  assert.match(harness, /allow_subdomains: false/);
  assert.match(harness, /allow_localhost: false/);
  assert.match(harness, /auth\/token\/revoke/);
  assert.match(harness, /path "model\/data\/\$\{secretHandle\}" \{ capabilities = \["read"\] \}/);
  assert.match(harness, /path "model\/metadata\/\$\{secretHandle\}" \{ capabilities = \["read"\] \}/);
  assert.doesNotMatch(harness, /model\/metadata\/\$\{secretHandle\}" \{ capabilities = \["read",/);
  assert.match(harness, /phase\("validate_sidecar"/);
  assert.match(harness, /phase\("validate_security_report"/);
  assert.match(harness, /phase\("validate_redaction"/);
  assert.match(harness, /result: "stubbed"/);
  assert.match(harness, /revocation: "real"/);
  assert.match(harness, /telemetry: "stubbed"/);
  assert.match(harness, /harness_driven_replacement_after_production_callback/);
  assert.match(harness, /daemon_or_sandbox_replacement_proven: false/);
  assert.match(harness, /revocationPollIntervalMs/);
  assert.match(harness, /revocationObservationBoundMs/);
  assert.doesNotMatch(harness, /revocationDiagnostics/);
  assert.match(harness, /host: "localhost"/);
  assert.match(harness, /ipv6\.listen\(\{ port: 0, host: "::1", ipv6Only: true \}, resolve\)/);
  assert.match(harness, /ipv4\.listen\(address\.port, "127\.0\.0\.1", resolve\)/);
  assert.match(harness, /Promise\.all\(\[closeServer\(ipv4\), closeServer\(ipv6\)\]\)/);
  assert.doesNotMatch(harness, /allowed_domains: "localhost"/);
});

test("Stage 3 real-runtime shell cleanup is ownership-armed", async () => {
  const script = await readFile("test/egress-conformance/stage3-real-runtime/ci-smoke.sh", "utf8");
  assert.match(script, /TRUST_CLEANUP_ARMED=0/);
  assert.match(script, /DIR_CREATED=0/);
  assert.match(script, /TMPFS_MOUNTED=0/);
  assert.match(script, /if \[ -e "\$\{TRUST_PATH\}" \]/);
  assert.match(script, /if \[ -e \/run\/cogs\/egress \]/);
  assert.match(script, /TRUST_CLEANUP_ARMED=1\nCOGS_ENVOY_EXECUTABLE/);
  assert.match(script, /if \[ "\$\{TRUST_CLEANUP_ARMED\}" = 1 \]/);
  assert.match(script, /if \[ "\$\{TMPFS_MOUNTED\}" = 1 \]/);
  assert.match(script, /if \[ "\$\{DIR_CREATED\}" = 1 \]/);
  assert.doesNotMatch(script, /docker ps[^\n]*\|\| true/);
  assert.doesNotMatch(script, /docker volume ls[^\n]*\|\| true/);
  assert.match(script, /record_cleanup_failure "labeled container inventory command failed"/);
  assert.match(script, /record_cleanup_failure "labeled volume inventory command failed"/);
});
