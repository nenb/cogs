import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const yaml = require("yaml") as {
  parse(source: string): unknown;
  parseAllDocuments(source: string): Array<{ errors: unknown[]; contents: unknown; toJSON(): unknown }>;
};
const root = resolve(import.meta.dirname, "..");
const chart = resolve(root, "deploy/helm/cogs");
const fixture = resolve(root, "test/fixtures/helm/stage4-notes-source-shapes-valid.yaml");
const release = "stage4";
const namespace = "static-preparation";
const envoyPin = "envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb";
const retiredDiscoveryCapability = "cogs.dev/static-preparation-render-only/v1";
const notesBegin = "# COGS NOTES-ONLY STATIC SOURCE SHAPES BEGIN:";
const notesEnd = "# COGS NOTES-ONLY STATIC SOURCE SHAPES END:";

interface Placement {
  nodeSelector: Record<string, string>;
  tolerations: Array<Record<string, unknown>>;
}

interface Peer {
  namespaceLabels: Record<string, string>;
  podLabels: Record<string, string>;
  port: number;
}

interface ResourceValues {
  requests: { cpu: string; memory: string; "ephemeral-storage": string };
  limits: { cpu: string; memory: string; "ephemeral-storage": string };
}

interface ValuesFile {
  stage4Preparation: {
    enabled: boolean;
    nonProductionAcknowledgement: boolean;
    sessionIdentity: string;
    runtimeClassName: string;
    images: { worker: string; proxy: string; sandbox: string };
    placement: { trusted: Placement; sandbox: Placement };
    storage: {
      workspaceStorageClass: string;
      workspaceSize: string;
      workspaceAccessMode: string;
      sessionStateStorageClass: string;
      sessionStateSize: string;
      sessionStateAccessMode: string;
    };
    openBao: {
      endpoint: string;
      kubernetesAuthMount: string;
      kubernetesAuthRole: string;
      pkiPath: string;
      tokenAudience: string;
      peer: Peer;
    };
    otlp: { endpoint: string; protocol: string; peer: Peer };
    proxyIdentity: { capabilityAudience: string; sourceBindingRequired: boolean };
    resourceProfile: string;
    lifecycle: { idleSeconds: number; hardSeconds: number; terminationGraceSeconds: number };
    auditWalMaxBytes: number;
    publicEgressCaConfigMap: string;
  };
}

interface Container {
  name: string;
  image: string;
  env?: Array<{ name: string; value?: string }>;
  ports?: Array<{ name: string; containerPort: number; protocol: string; hostPort?: number }>;
  securityContext: Record<string, unknown>;
  resources: ResourceValues;
  volumeMounts: Array<{ name: string; mountPath: string; readOnly?: boolean }>;
}

interface PodSpec {
  serviceAccountName: string;
  automountServiceAccountToken: boolean;
  enableServiceLinks: boolean;
  activeDeadlineSeconds: number;
  terminationGracePeriodSeconds: number;
  runtimeClassName?: string;
  nodeSelector: Record<string, string>;
  tolerations: Array<Record<string, unknown>>;
  securityContext: Record<string, unknown>;
  containers: Container[];
  volumes: Array<Record<string, unknown>>;
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  initContainers?: Container[];
}

interface KubeObject {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    namespace: string;
    labels: Record<string, string>;
    annotations?: Record<string, string>;
  };
  automountServiceAccountToken?: boolean;
  immutable?: boolean;
  data?: Record<string, string>;
  spec?: Record<string, unknown>;
  template?: { metadata: { labels: Record<string, string>; annotations?: Record<string, string> }; spec: PodSpec };
}

interface HelmResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: Error;
}

function helm(arguments_: string[]): HelmResult {
  assert.ok(arguments_[0] === "lint" || arguments_[0] === "template", "tests may invoke only helm lint/template");
  return spawnSync("helm", arguments_, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, HELM_DEBUG: "false" },
    timeout: 20_000,
    maxBuffer: 2 * 1024 * 1024,
  });
}

function assertHelmSuccess(result: HelmResult): void {
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr);
}

function assertEmptyManifestStream(result: HelmResult): void {
  assertHelmSuccess(result);
  // Helm 4 adds one CLI framing newline even for a chart with no templates; Helm 3 emits exact zero bytes.
  assert.equal(result.stdout.replace(/^\n$/u, ""), "", "render must contain no Kubernetes manifest bytes");
}

function validValues(): ValuesFile {
  return structuredClone(yaml.parse(readFileSync(fixture, "utf8")) as ValuesFile);
}

function renderNotesResult(valuesPath = fixture, additionalArguments: string[] = []): HelmResult {
  const help = helm(["template", "--help"]);
  assertHelmSuccess(help);
  if (/^\s*--notes\b/mu.test(help.stdout)) {
    return helm([
      "template",
      release,
      chart,
      "--notes",
      "--namespace",
      namespace,
      "-f",
      valuesPath,
      ...additionalArguments,
    ]);
  }

  // Helm 4 removed the historical --notes flag. For review tests only, copy the
  // chart and place the same named NOTES payload in one temporary ConfigMap field.
  // This preserves document order for parsing and never touches a cluster.
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "cogs-stage4-notes-review-"));
  try {
    const reviewChart = join(temporaryDirectory, "cogs");
    cpSync(chart, reviewChart, { recursive: true });
    writeFileSync(
      join(reviewChart, "templates/notes-review.yaml"),
      `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cogs-notes-review-wrapper\ndata:\n  payload: |-\n{{ include "cogs.stage4.notes.payload" . | nindent 4 }}\n`,
    );
    return helm(["template", release, reviewChart, "--namespace", namespace, "-f", valuesPath, ...additionalArguments]);
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

function renderedNotes(
  valuesPath = fixture,
  additionalArguments: string[] = [],
): { stdout: string; payload: string; objects: KubeObject[] } {
  const result = renderNotesResult(valuesPath, additionalArguments);
  assertHelmSuccess(result);
  const renderedDocuments = yaml
    .parseAllDocuments(result.stdout)
    .filter((document) => document.contents !== null)
    .map((document) => document.toJSON() as KubeObject);
  const reviewWrapper = renderedDocuments.find((object) => object.metadata?.name === "cogs-notes-review-wrapper");
  let payload = reviewWrapper?.data?.payload;
  if (payload === undefined) {
    const begin = result.stdout.indexOf(notesBegin);
    const end = result.stdout.indexOf(notesEnd);
    assert.ok(begin >= 0, "begin warning bounds the NOTES payload");
    assert.ok(end > begin, "end warning bounds the NOTES payload");
    const endOfLine = result.stdout.indexOf("\n", end);
    payload = result.stdout.slice(begin, endOfLine < 0 ? undefined : endOfLine + 1);
  }
  assert.equal(typeof payload, "string");
  payload = payload.trim();
  const objects = yaml
    .parseAllDocuments(payload)
    .filter((document) => document.contents !== null)
    .map((document) => {
      assert.deepEqual(document.errors, []);
      return document.toJSON() as KubeObject;
    });
  return { stdout: result.stdout, payload, objects };
}

function byName(objects: KubeObject[], name: string): KubeObject {
  const found = objects.find((object) => object.metadata.name === name);
  assert.ok(found, `rendered object ${name}`);
  return found;
}

function container(spec: PodSpec, name: string): Container {
  const found = spec.containers.find((item) => item.name === name);
  assert.ok(found, `container ${name}`);
  return found;
}

function projectedTokenVolumes(spec: PodSpec): Array<Record<string, unknown>> {
  return spec.volumes.filter((volume) => "projected" in volume);
}

function assertStrictContainerSecurity(item: Container, readOnlyRootFilesystem: boolean): void {
  assert.deepEqual(item.securityContext, {
    privileged: false,
    allowPrivilegeEscalation: false,
    readOnlyRootFilesystem,
    capabilities: { drop: ["ALL"] },
    ...(item.name === "sandbox" ? { runAsUser: 0, runAsGroup: 0 } : {}),
  });
}

function writeTemporaryValues(values: ValuesFile): { directory: string; path: string } {
  const directory = mkdtempSync(join(tmpdir(), "cogs-stage4-helm-"));
  const path = join(directory, "values.json");
  writeFileSync(path, `${JSON.stringify(values)}\n`, { mode: 0o600 });
  return { directory, path };
}

function escapePattern(value: string): RegExp {
  return new RegExp(value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&"), "iu");
}

test("lint and normal install-like templates produce zero manifests for default, enabled, and capability values", () => {
  assertHelmSuccess(helm(["lint", chart]));
  assertHelmSuccess(helm(["lint", chart, "-f", fixture]));
  const renderArguments = [
    [],
    ["-f", fixture],
    ["-f", fixture, "--is-upgrade"],
    ["-f", fixture, "--api-versions", retiredDiscoveryCapability],
    ["-f", fixture, "--api-versions", `${retiredDiscoveryCapability}/DiscoveryCollision`],
    ["-f", fixture, "--skip-schema-validation", "--api-versions", retiredDiscoveryCapability],
    ["-f", fixture, "--api-versions", "cogs.dev/v1", "--kube-version", "1.35.0"],
  ];
  for (const arguments_ of renderArguments) {
    assertEmptyManifestStream(helm(["template", "cogs", chart, ...arguments_]));
  }

  const values = validValues();
  values.stage4Preparation.enabled = false;
  const temporary = writeTemporaryValues(values);
  try {
    assertEmptyManifestStream(
      helm(["template", "cogs", chart, "--api-versions", retiredDiscoveryCapability, "-f", temporary.path]),
    );
  } finally {
    rmSync(temporary.directory, { recursive: true, force: true });
  }
});

test("enabled NOTES emit nine warning-bounded, unsafe, unqualified static source shapes", () => {
  const { payload, objects } = renderedNotes();
  assert.equal(objects.length, 9);
  assert.deepEqual(
    Object.fromEntries(
      [...new Set(objects.map((object) => object.kind))]
        .sort()
        .map((kind) => [kind, objects.filter((object) => object.kind === kind).length]),
    ),
    { ConfigMap: 1, NetworkPolicy: 3, PodTemplate: 2, Service: 1, ServiceAccount: 2 },
  );
  assert.deepEqual(objects.map((object) => object.metadata.name).sort(), [
    "stage4-cogs-contract",
    "stage4-cogs-default-deny",
    "stage4-cogs-proxy",
    "stage4-cogs-sandbox",
    "stage4-cogs-sandbox-allow",
    "stage4-cogs-sandbox-template",
    "stage4-cogs-trusted",
    "stage4-cogs-trusted-allow",
    "stage4-cogs-trusted-template",
  ]);

  const forbiddenKinds = new Set([
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "Job",
    "CronJob",
    "PersistentVolumeClaim",
    "PersistentVolume",
    "Secret",
    "Role",
    "RoleBinding",
    "ClusterRole",
    "ClusterRoleBinding",
    "RuntimeClass",
    "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration",
    "CustomResourceDefinition",
    "Namespace",
  ]);
  for (const object of objects) {
    assert.equal(object.metadata.namespace, namespace);
    assert.equal(forbiddenKinds.has(object.kind), false, object.kind);
    assert.equal(object.metadata.labels["app.kubernetes.io/instance"], release);
    assert.equal(object.metadata.labels["app.kubernetes.io/part-of"], "cogs");
    assert.equal(object.metadata.labels["dev.cogs/stage"], "4-preparation");
    assert.equal(object.metadata.labels["dev.cogs/session"], "static-test-session");
    assert.equal(object.metadata.labels["dev.cogs/security-claim"], "none");
    assert.equal(object.metadata.labels["dev.cogs/qualification"], "none");
    assert.equal(object.metadata.labels["dev.cogs/production-ready"], "false");
    assert.equal(object.metadata.annotations?.["helm.sh/hook"], undefined);
  }
  assert.ok(payload.startsWith(notesBegin));
  assert.ok(payload.endsWith("WARNING — UNSAFE TO APPLY; UNQUALIFIED"));
  assert.match(payload, /unsafe to apply/iu);
  assert.match(payload, /unqualified/iu);
  for (const account of objects.filter((object) => object.kind === "ServiceAccount")) {
    assert.equal(account.automountServiceAccountToken, false);
  }
});

test("immutable configuration and Service expose references and no secret or CA bytes", () => {
  const { payload, objects } = renderedNotes();
  const contract = byName(objects, "stage4-cogs-contract");
  assert.equal(contract.immutable, true);
  assert.equal(contract.data?.status, "NOTES_ONLY_STATIC_SOURCE_SHAPE");
  assert.equal(contract.data?.applySafety, "UNSAFE_TO_APPLY_UNQUALIFIED");
  assert.equal(contract.data?.productionReady, "false");
  assert.equal(contract.data?.proxyImage, envoyPin);
  assert.equal(contract.data?.ephemeralProxyCapability, "ABSENT_FUTURE_TRUSTED_LAUNCHER_ONLY");
  assert.equal(contract.data?.publicEgressCaConfigMapReference, "synthetic-public-egress-ca");
  for (const check of ["RuntimeClass", "KVM", "CNI", "CSI", "OpenBao", "image availability", "per-session", "EKS"]) {
    assert.match(contract.data?.unresolvedChecks ?? "", escapePattern(check));
  }
  const service = byName(objects, "stage4-cogs-proxy");
  const serviceSpec = service.spec as {
    type: string;
    selector: Record<string, string>;
    ports: Array<Record<string, unknown>>;
  };
  assert.equal(serviceSpec.type, "ClusterIP");
  assert.deepEqual(serviceSpec.selector, {
    "app.kubernetes.io/instance": release,
    "dev.cogs/session": "static-test-session",
    "dev.cogs/role": "trusted",
    "dev.cogs/proxy": "true",
  });
  assert.deepEqual(serviceSpec.ports, [{ name: "proxy", protocol: "TCP", port: 15001, targetPort: "proxy" }]);

  assert.doesNotMatch(payload, /^kind: Secret$/mu);
  assert.doesNotMatch(
    payload,
    /secretKeyRef|envFrom|BEGIN (?:CERTIFICATE|[^\n]*PRIVATE KEY)|production-ready:\s*["']?true/iu,
  );
  assert.doesNotMatch(payload, /(?:password|clientSecret|apiKey|accessToken):/iu);
  assert.match(payload, /@sha256:[a-f0-9]{64}/u);
});

test("trusted and sandbox PodTemplate source shapes preserve placement, security, storage, and token separation", () => {
  const values = validValues().stage4Preparation;
  const { objects } = renderedNotes();
  const trustedObject = byName(objects, "stage4-cogs-trusted-template");
  const sandboxObject = byName(objects, "stage4-cogs-sandbox-template");
  const trustedTemplate = trustedObject.template;
  const sandboxTemplate = sandboxObject.template;
  assert.ok(trustedTemplate);
  assert.ok(sandboxTemplate);
  const trusted = trustedTemplate.spec;
  const sandbox = sandboxTemplate.spec;

  assert.equal(trusted.serviceAccountName, "stage4-cogs-trusted");
  assert.equal(trusted.automountServiceAccountToken, false);
  assert.equal(trusted.enableServiceLinks, false);
  assert.equal(trusted.activeDeadlineSeconds, 28800);
  assert.equal(trusted.terminationGracePeriodSeconds, 30);
  assert.equal(trusted.runtimeClassName, undefined);
  assert.deepEqual(trusted.nodeSelector, values.placement.trusted.nodeSelector);
  assert.equal(trusted.nodeSelector["cogs.dev/node-domain"], "trusted");
  assert.equal(
    trusted.tolerations.some((toleration) => toleration.key === "cogs.dev/sandbox"),
    false,
  );
  assert.deepEqual(trusted.securityContext, {
    runAsNonRoot: true,
    runAsUser: 10001,
    runAsGroup: 10001,
    fsGroup: 10001,
    seccompProfile: { type: "RuntimeDefault" },
  });
  assert.equal(trusted.hostNetwork, undefined);
  assert.equal(trusted.hostPID, undefined);
  assert.equal(trusted.hostIPC, undefined);
  assert.equal(trusted.initContainers, undefined);
  assert.deepEqual(
    trusted.containers.map((item) => item.name),
    ["worker", "envoy"],
  );

  const worker = container(trusted, "worker");
  const proxy = container(trusted, "envoy");
  assert.equal(worker.image, values.images.worker);
  assert.equal(proxy.image, envoyPin);
  assert.deepEqual(worker.resources, {
    requests: { cpu: "500m", memory: "512Mi", "ephemeral-storage": "1Gi" },
    limits: { cpu: "2", memory: "2Gi", "ephemeral-storage": "4Gi" },
  });
  assert.deepEqual(proxy.resources, {
    requests: { cpu: "100m", memory: "128Mi", "ephemeral-storage": "256Mi" },
    limits: { cpu: "1", memory: "512Mi", "ephemeral-storage": "1Gi" },
  });
  assertStrictContainerSecurity(worker, true);
  assertStrictContainerSecurity(proxy, true);
  assert.deepEqual(proxy.ports, [{ name: "proxy", containerPort: 15001, protocol: "TCP" }]);
  assert.equal(
    worker.volumeMounts.some((mount) => mount.name === "openbao-token" && mount.readOnly === true),
    true,
  );
  assert.equal(
    proxy.volumeMounts.some((mount) => mount.name === "openbao-token"),
    false,
  );
  assert.equal(
    worker.volumeMounts.some((mount) => mount.name === "session-state"),
    true,
  );
  assert.equal(
    proxy.volumeMounts.some((mount) => mount.name === "session-state"),
    false,
  );
  for (const item of [worker, proxy]) {
    for (const name of ["preparation-contract", "public-egress-ca"]) {
      assert.equal(
        item.volumeMounts.some((mount) => mount.name === name && mount.readOnly === true),
        true,
        `${item.name}: read-only ${name}`,
      );
    }
  }

  const tokenVolumes = projectedTokenVolumes(trusted);
  assert.equal(tokenVolumes.length, 1);
  const projected = tokenVolumes[0]?.projected as {
    defaultMode: number;
    sources: Array<{ serviceAccountToken: { audience: string; expirationSeconds: number; path: string } }>;
  };
  assert.equal(projected.defaultMode, 256);
  assert.deepEqual(projected.sources, [
    { serviceAccountToken: { audience: values.openBao.tokenAudience, expirationSeconds: 600, path: "token" } },
  ]);
  const tokenSource = projected.sources[0];
  assert.ok(tokenSource);
  assert.ok(tokenSource.serviceAccountToken.expirationSeconds <= 900);
  for (const volume of trusted.volumes.filter((item) => "emptyDir" in item)) {
    const emptyDir = volume.emptyDir as Record<string, unknown>;
    assert.equal(emptyDir.medium, "Memory");
    assert.match(String(emptyDir.sizeLimit), /^[1-9][0-9]*Mi$/u);
  }
  assert.deepEqual(trusted.volumes.find((volume) => volume.name === "session-state")?.persistentVolumeClaim, {
    claimName: "replace-per-session-state-pvc",
    readOnly: false,
  });
  assert.deepEqual(trusted.volumes.find((volume) => volume.name === "public-egress-ca")?.configMap, {
    name: values.publicEgressCaConfigMap,
    optional: false,
  });
  assert.equal(JSON.stringify(trusted.volumes).includes("secret"), false);

  assert.equal(sandbox.serviceAccountName, "stage4-cogs-sandbox");
  assert.equal(sandbox.automountServiceAccountToken, false);
  assert.equal(sandbox.enableServiceLinks, false);
  assert.equal(sandbox.activeDeadlineSeconds, 28800);
  assert.equal(sandbox.terminationGracePeriodSeconds, 30);
  assert.equal(sandbox.runtimeClassName, values.runtimeClassName);
  assert.deepEqual(sandbox.nodeSelector, values.placement.sandbox.nodeSelector);
  assert.equal(sandbox.nodeSelector["cogs.dev/node-domain"], "sandbox-kata");
  assert.deepEqual(sandbox.tolerations, [
    { key: "cogs.dev/sandbox", operator: "Equal", value: "kata", effect: "NoSchedule" },
  ]);
  assert.deepEqual(sandbox.securityContext, {
    runAsUser: 0,
    runAsGroup: 0,
    seccompProfile: { type: "RuntimeDefault" },
  });
  assert.equal(sandbox.containers.length, 1);
  const guest = container(sandbox, "sandbox");
  assert.equal(guest.image, values.images.sandbox);
  assert.deepEqual(guest.resources, {
    requests: { cpu: "2", memory: "4Gi", "ephemeral-storage": "8Gi" },
    limits: { cpu: "2", memory: "4Gi", "ephemeral-storage": "16Gi" },
  });
  assertStrictContainerSecurity(guest, false);
  assert.deepEqual(guest.ports, [{ name: "ssh", containerPort: 22, protocol: "TCP" }]);
  assert.equal(
    guest.ports?.some((port) => port.hostPort !== undefined),
    false,
  );
  assert.deepEqual(
    guest.env?.map((entry) => entry.name),
    ["HTTP_PROXY", "HTTPS_PROXY", "SSL_CERT_FILE"],
  );
  assert.equal(projectedTokenVolumes(sandbox).length, 0);
  assert.doesNotMatch(
    JSON.stringify({
      annotations: sandboxTemplate.metadata.annotations,
      env: guest.env,
      volumeMounts: guest.volumeMounts,
      volumes: sandbox.volumes,
    }),
    /capability|handle|openbao|token|secret-store|sessions\//iu,
  );
  assert.equal(JSON.stringify(sandbox.volumes).includes("secret"), false);
  assert.equal(
    guest.volumeMounts.some((mount) => mount.name === "public-egress-ca" && mount.readOnly === true),
    true,
  );
  assert.doesNotMatch(JSON.stringify([trusted, sandbox]), /hostPath|hostPort|imagePullSecrets|secretKeyRef|envFrom/u);
  assert.deepEqual(sandbox.volumes.find((volume) => volume.name === "workspace")?.persistentVolumeClaim, {
    claimName: "replace-per-session-workspace-pvc",
    readOnly: false,
  });
  assert.deepEqual(sandbox.volumes.find((volume) => volume.name === "public-egress-ca")?.configMap, {
    name: values.publicEgressCaConfigMap,
    optional: false,
  });
  assert.match(sandboxTemplate.metadata.annotations?.["dev.cogs/notice"] ?? "", /guest-uid-0-is-untrusted-vm-root/u);

  const contract = byName(objects, "stage4-cogs-contract");
  assert.equal(contract.data?.workspaceSize, "20Gi");
  assert.equal(contract.data?.workspaceAccessMode, "ReadWriteOncePod");
  assert.equal(contract.data?.sessionStateSize, "5Gi");
  assert.equal(contract.data?.sessionStateAccessMode, "ReadWriteOncePod");
  assert.equal(contract.data?.idleSeconds, "1800");
  assert.equal(contract.data?.hardSeconds, "28800");
  assert.equal(contract.data?.terminationGraceSeconds, "30");
  assert.equal(contract.data?.auditWalMaxBytes, "268435456");
  assert.equal(
    objects.some((object) => object.kind === "PersistentVolumeClaim"),
    false,
  );
});

test("NetworkPolicy NOTES shapes preserve intended static TCP policy without claiming enforcement", () => {
  const { objects } = renderedNotes();
  const policies = objects.filter((object) => object.kind === "NetworkPolicy");
  assert.equal(policies.length, 3);
  const serialized = JSON.stringify(policies);
  assert.doesNotMatch(serialized, /ipBlock|0\.0\.0\.0|::\/0|169\.254\.169\.254|UDP|DNS/iu);

  for (const policy of policies) {
    const spec = policy.spec as {
      podSelector: { matchLabels: Record<string, string>; matchExpressions?: unknown[] };
      policyTypes: string[];
      ingress?: Array<Record<string, unknown>>;
      egress?: Array<Record<string, unknown>>;
    };
    assert.deepEqual(spec.policyTypes, ["Ingress", "Egress"]);
    assert.equal(spec.podSelector.matchLabels["dev.cogs/session"], "static-test-session");
    assert.ok(
      spec.podSelector.matchLabels["dev.cogs/role"] || spec.podSelector.matchExpressions,
      `${policy.metadata.name}: role selector`,
    );
    for (const rule of [...(spec.ingress ?? []), ...(spec.egress ?? [])]) {
      const ports = rule.ports as Array<{ protocol: string; port: number }>;
      assert.ok(ports.length > 0);
      assert.equal(
        ports.every((port) => port.protocol === "TCP"),
        true,
      );
      const peers = (rule.from ?? rule.to) as Array<Record<string, unknown>>;
      assert.ok(peers.length > 0);
      for (const peer of peers) {
        assert.ok(Object.keys(peer).length > 0, `${policy.metadata.name}: no empty peer`);
        assert.ok("podSelector" in peer, `${policy.metadata.name}: no namespace-only peer`);
        const podSelector = peer.podSelector as { matchLabels?: Record<string, string> };
        assert.ok(podSelector.matchLabels && Object.keys(podSelector.matchLabels).length > 0, "no wildcard pod peer");
        if ("namespaceSelector" in peer) {
          const selector = peer.namespaceSelector as { matchLabels?: Record<string, string> };
          assert.ok(selector.matchLabels && Object.keys(selector.matchLabels).length > 0, "no wildcard namespace peer");
        }
      }
    }
  }

  const deny = byName(policies, "stage4-cogs-default-deny").spec as Record<string, unknown>;
  assert.equal(deny.ingress, undefined);
  assert.equal(deny.egress, undefined);
  const trusted = byName(policies, "stage4-cogs-trusted-allow").spec as {
    ingress: Array<Record<string, unknown>>;
    egress: Array<Record<string, unknown>>;
  };
  const sandbox = byName(policies, "stage4-cogs-sandbox-allow").spec as {
    ingress: Array<Record<string, unknown>>;
    egress: Array<Record<string, unknown>>;
  };
  const trustedIngress = trusted.ingress[0];
  const sandboxIngress = sandbox.ingress[0];
  const sandboxEgress = sandbox.egress[0];
  assert.ok(trustedIngress);
  assert.ok(sandboxIngress);
  assert.ok(sandboxEgress);
  assert.deepEqual((trustedIngress.ports as Array<Record<string, unknown>>)[0], { protocol: "TCP", port: 15001 });
  assert.deepEqual(
    trusted.egress.flatMap((rule) => rule.ports as Array<{ protocol: string; port: number }>).map((port) => port.port),
    [22, 8200, 4317],
  );
  assert.deepEqual((sandboxIngress.ports as Array<Record<string, unknown>>)[0], { protocol: "TCP", port: 22 });
  assert.deepEqual((sandboxEgress.ports as Array<Record<string, unknown>>)[0], { protocol: "TCP", port: 15001 });
});

test("chart mechanically confines every Kubernetes YAML source shape to NOTES and underscore helpers", () => {
  const templates = resolve(chart, "templates");
  const templateNames = readdirSync(templates).sort();
  assert.deepEqual(
    templateNames.filter((name) => !name.startsWith("_")),
    ["NOTES.txt"],
  );
  assert.deepEqual(
    templateNames.filter((name) => name.endsWith(".yaml") || name.endsWith(".yml")),
    [],
  );
  const notesSource = readFileSync(resolve(templates, "NOTES.txt"), "utf8");
  const payloadSource = readFileSync(resolve(templates, "_notes.tpl"), "utf8");
  const helperNames = ["configmap", "serviceaccounts", "service", "networkpolicies", "podtemplates"];
  const helperSource = templateNames
    .filter((name) => name.startsWith("_"))
    .map((name) => readFileSync(resolve(templates, name), "utf8"))
    .join("\n");
  assert.equal(notesSource.trim(), '{{- include "cogs.stage4.notes.payload" . -}}');
  for (const name of helperNames) {
    assert.equal(payloadSource.includes(`include "cogs.stage4.notes.${name}"`), true);
    assert.equal(helperSource.includes(`define "cogs.stage4.notes.${name}"`), true);
  }
  assert.doesNotMatch(`${notesSource}\n${helperSource}`, /\.Capabilities|\blookup\b|helm\.sh\/hook/iu);
  assert.equal(existsSync(resolve(chart, "crds")), false);
  assert.equal(existsSync(resolve(chart, "charts")), false);
  const chartSource = readFileSync(resolve(chart, "Chart.yaml"), "utf8");
  assert.doesNotMatch(chartSource, /^dependencies:/mu);
  const valuesSource = readFileSync(resolve(chart, "values.yaml"), "utf8");
  assert.doesNotMatch(valuesSource, /extraEnv|imagePullSecrets|extraObjects|podSpec|annotations:|publicEgressCa:/iu);
  assert.doesNotMatch(`${notesSource}\n${helperSource}\n${valuesSource}`, /BEGIN CERTIFICATE|BEGIN [^\n]*PRIVATE KEY/u);
});

test("enabled values fail closed for missing, unsafe, or extensible inputs", () => {
  type NegativeCase = { name: string; key: string; mutate(values: ValuesFile): void };
  const cases: NegativeCase[] = [
    {
      name: "acknowledgement",
      key: "nonProductionAcknowledgement",
      mutate: (v) => (v.stage4Preparation.nonProductionAcknowledgement = false),
    },
    { name: "empty RuntimeClass", key: "runtimeClassName", mutate: (v) => (v.stage4Preparation.runtimeClassName = "") },
    {
      name: "runc RuntimeClass",
      key: "runtimeClassName",
      mutate: (v) => (v.stage4Preparation.runtimeClassName = "runc"),
    },
    {
      name: "trusted selector",
      key: "nodeSelector",
      mutate: (v) => (v.stage4Preparation.placement.trusted.nodeSelector = {}),
    },
    {
      name: "sandbox selector",
      key: "nodeSelector",
      mutate: (v) => (v.stage4Preparation.placement.sandbox.nodeSelector = {}),
    },
    {
      name: "identical selectors",
      key: "nodeSelector",
      mutate: (v) =>
        (v.stage4Preparation.placement.sandbox.nodeSelector = structuredClone(
          v.stage4Preparation.placement.trusted.nodeSelector,
        )),
    },
    {
      name: "sandbox toleration",
      key: "tolerations",
      mutate: (v) => (v.stage4Preparation.placement.sandbox.tolerations = []),
    },
    {
      name: "unknown toleration field",
      key: "unexpected",
      mutate: (v) => {
        const toleration = v.stage4Preparation.placement.sandbox.tolerations[0];
        assert.ok(toleration);
        toleration.unexpected = true;
      },
    },
    { name: "worker image", key: "worker", mutate: (v) => (v.stage4Preparation.images.worker = "") },
    { name: "proxy image", key: "proxy", mutate: (v) => (v.stage4Preparation.images.proxy = "") },
    { name: "sandbox image", key: "sandbox", mutate: (v) => (v.stage4Preparation.images.sandbox = "") },
    {
      name: "tag-only image",
      key: "worker",
      mutate: (v) => (v.stage4Preparation.images.worker = "registry.example.invalid/cogs/worker:latest"),
    },
    {
      name: "wrong Envoy pin",
      key: "proxy",
      mutate: (v) => (v.stage4Preparation.images.proxy = `envoyproxy/envoy:v1.38.3@sha256:${"0".repeat(64)}`),
    },
    {
      name: "workspace class",
      key: "workspaceStorageClass",
      mutate: (v) => (v.stage4Preparation.storage.workspaceStorageClass = ""),
    },
    {
      name: "session class",
      key: "sessionStateStorageClass",
      mutate: (v) => (v.stage4Preparation.storage.sessionStateStorageClass = ""),
    },
    {
      name: "identical classes",
      key: "StorageClass",
      mutate: (v) =>
        (v.stage4Preparation.storage.sessionStateStorageClass = v.stage4Preparation.storage.workspaceStorageClass),
    },
    {
      name: "malformed storage class",
      key: "workspaceStorageClass",
      mutate: (v) => (v.stage4Preparation.storage.workspaceStorageClass = "synthetic..workspace"),
    },
    { name: "OpenBao endpoint", key: "endpoint", mutate: (v) => (v.stage4Preparation.openBao.endpoint = "") },
    {
      name: "OpenBao auth mount",
      key: "kubernetesAuthMount",
      mutate: (v) => (v.stage4Preparation.openBao.kubernetesAuthMount = ""),
    },
    {
      name: "OpenBao role",
      key: "kubernetesAuthRole",
      mutate: (v) => (v.stage4Preparation.openBao.kubernetesAuthRole = ""),
    },
    { name: "OpenBao PKI", key: "pkiPath", mutate: (v) => (v.stage4Preparation.openBao.pkiPath = "") },
    { name: "OpenBao audience", key: "tokenAudience", mutate: (v) => (v.stage4Preparation.openBao.tokenAudience = "") },
    {
      name: "OpenBao namespace peer",
      key: "namespaceLabels",
      mutate: (v) => (v.stage4Preparation.openBao.peer.namespaceLabels = {}),
    },
    { name: "OpenBao pod peer", key: "podLabels", mutate: (v) => (v.stage4Preparation.openBao.peer.podLabels = {}) },
    { name: "OpenBao port", key: "port", mutate: (v) => (v.stage4Preparation.openBao.peer.port = 0) },
    {
      name: "OpenBao HTTP",
      key: "endpoint",
      mutate: (v) => (v.stage4Preparation.openBao.endpoint = "http://openbao.static-test.invalid"),
    },
    {
      name: "OpenBao credentials",
      key: "endpoint",
      mutate: (v) => (v.stage4Preparation.openBao.endpoint = "https://user@example.invalid"),
    },
    {
      name: "OpenBao query",
      key: "endpoint",
      mutate: (v) => (v.stage4Preparation.openBao.endpoint = "https://openbao.static-test.invalid?unsafe=true"),
    },
    { name: "OTLP endpoint", key: "endpoint", mutate: (v) => (v.stage4Preparation.otlp.endpoint = "") },
    { name: "OTLP protocol", key: "protocol", mutate: (v) => (v.stage4Preparation.otlp.protocol = "") },
    {
      name: "OTLP namespace peer",
      key: "namespaceLabels",
      mutate: (v) => (v.stage4Preparation.otlp.peer.namespaceLabels = {}),
    },
    { name: "OTLP pod peer", key: "podLabels", mutate: (v) => (v.stage4Preparation.otlp.peer.podLabels = {}) },
    { name: "OTLP port", key: "port", mutate: (v) => (v.stage4Preparation.otlp.peer.port = 0) },
    {
      name: "OTLP unsupported protocol",
      key: "protocol",
      mutate: (v) => (v.stage4Preparation.otlp.protocol = "http/json"),
    },
    {
      name: "OTLP HTTP",
      key: "endpoint",
      mutate: (v) => (v.stage4Preparation.otlp.endpoint = "http://otlp.static-test.invalid"),
    },
    {
      name: "OTLP credentials",
      key: "endpoint",
      mutate: (v) => (v.stage4Preparation.otlp.endpoint = "https://user@example.invalid"),
    },
    {
      name: "OTLP fragment",
      key: "endpoint",
      mutate: (v) => (v.stage4Preparation.otlp.endpoint = "https://otlp.static-test.invalid#unsafe"),
    },
    { name: "session identity", key: "sessionIdentity", mutate: (v) => (v.stage4Preparation.sessionIdentity = "") },
    {
      name: "capability audience",
      key: "capabilityAudience",
      mutate: (v) => (v.stage4Preparation.proxyIdentity.capabilityAudience = ""),
    },
    {
      name: "forbidden handle prefix",
      key: "capabilityHandlePrefix",
      mutate: (v) =>
        ((v.stage4Preparation.proxyIdentity as unknown as Record<string, unknown>).capabilityHandlePrefix = "sessions"),
    },
    {
      name: "source binding",
      key: "sourceBindingRequired",
      mutate: (v) => (v.stage4Preparation.proxyIdentity.sourceBindingRequired = false),
    },
    {
      name: "public CA ConfigMap reference",
      key: "publicEgressCaConfigMap",
      mutate: (v) => (v.stage4Preparation.publicEgressCaConfigMap = ""),
    },
    {
      name: "malformed public CA ConfigMap reference",
      key: "publicEgressCaConfigMap",
      mutate: (v) => (v.stage4Preparation.publicEgressCaConfigMap = "NOT_DNS_SAFE"),
    },
    {
      name: "OpenBao token escape",
      key: "token",
      mutate: (v) => ((v.stage4Preparation.openBao as unknown as Record<string, unknown>).token = "forbidden"),
    },
    {
      name: "capability escape",
      key: "capability",
      mutate: (v) =>
        ((v.stage4Preparation.proxyIdentity as unknown as Record<string, unknown>).capability = "forbidden"),
    },
    {
      name: "top-level secret",
      key: "secret",
      mutate: (v) => ((v as unknown as Record<string, unknown>).secret = "forbidden"),
    },
    {
      name: "extra environment",
      key: "extraEnv",
      mutate: (v) => ((v.stage4Preparation as unknown as Record<string, unknown>).extraEnv = []),
    },
    {
      name: "pull secrets",
      key: "imagePullSecrets",
      mutate: (v) => ((v.stage4Preparation as unknown as Record<string, unknown>).imagePullSecrets = []),
    },
    {
      name: "pod fragment",
      key: "podTemplate",
      mutate: (v) => ((v.stage4Preparation as unknown as Record<string, unknown>).podTemplate = {}),
    },
    {
      name: "legacy zero resources",
      key: "resources",
      mutate: (v) =>
        ((v.stage4Preparation as unknown as Record<string, unknown>).resources = {
          worker: { requests: { cpu: "0", memory: "0", "ephemeral-storage": "0" } },
        }),
    },
    {
      name: "workspace size",
      key: "workspaceSize",
      mutate: (v) => (v.stage4Preparation.storage.workspaceSize = "0"),
    },
    {
      name: "hard lifetime",
      key: "hardSeconds",
      mutate: (v) => (v.stage4Preparation.lifecycle.hardSeconds = 0),
    },
    {
      name: "WAL bound",
      key: "auditWalMaxBytes",
      mutate: (v) => (v.stage4Preparation.auditWalMaxBytes = 0),
    },
  ];

  for (const negative of cases) {
    const values = validValues();
    negative.mutate(values);
    const temporary = writeTemporaryValues(values);
    try {
      const result = helm(["template", release, chart, "--namespace", namespace, "-f", temporary.path]);
      assert.equal(result.error, undefined, `${negative.name}: ${result.error?.message}`);
      assert.notEqual(result.status, 0, `${negative.name}: unexpectedly rendered`);
      assert.doesNotMatch(result.stdout, /^apiVersion:/mu, `${negative.name}: no usable manifest stream`);
      assert.match(result.stderr, escapePattern(negative.key), `${negative.name}: bounded error category`);
    } finally {
      rmSync(temporary.directory, { recursive: true, force: true });
    }
  }
});

test("template validation rejects hostile security inputs with schema validation skipped", () => {
  type HostileCase = { name: string; key: string; mutate(values: ValuesFile): void };
  const cases: HostileCase[] = [
    {
      name: "legacy zero resource quantities",
      key: "resources",
      mutate: (v) =>
        ((v.stage4Preparation as unknown as Record<string, unknown>).resources = {
          worker: {
            requests: { cpu: "0", memory: "0", "ephemeral-storage": "0" },
            limits: { cpu: "0", memory: "0", "ephemeral-storage": "0" },
          },
        }),
    },
    {
      name: "removed inline public CA field",
      key: "publicEgressCa",
      mutate: (v) =>
        ((v.stage4Preparation as unknown as Record<string, unknown>).publicEgressCa = "forbidden-inline-ca-data"),
    },
    {
      name: "malformed public CA ConfigMap reference",
      key: "publicEgressCaConfigMap",
      mutate: (v) => (v.stage4Preparation.publicEgressCaConfigMap = "wildcard/*"),
    },
    {
      name: "port above range",
      key: "port",
      mutate: (v) => (v.stage4Preparation.openBao.peer.port = 65536),
    },
    {
      name: "non-integer port",
      key: "port",
      mutate: (v) => ((v.stage4Preparation.otlp.peer as unknown as Record<string, unknown>).port = "4317"),
    },
    {
      name: "endpoint port above range",
      key: "endpoint",
      mutate: (v) => (v.stage4Preparation.openBao.endpoint = "https://openbao.static-test.invalid:99999"),
    },
    {
      name: "malformed selector label",
      key: "label value",
      mutate: (v) => (v.stage4Preparation.otlp.peer.podLabels = { "app.kubernetes.io/name": "bad value" }),
    },
    {
      name: "trusted selector overlap",
      key: "trusted.nodeSelector",
      mutate: (v) => (v.stage4Preparation.placement.trusted.nodeSelector["cogs.dev/node-domain"] = "sandbox-kata"),
    },
    {
      name: "sandbox unrelated toleration",
      key: "sandbox.tolerations",
      mutate: (v) =>
        (v.stage4Preparation.placement.sandbox.tolerations = [
          { key: "unrelated", operator: "Equal", value: "kata", effect: "NoSchedule" },
        ]),
    },
    {
      name: "trusted sandbox taint toleration",
      key: "trusted.tolerations",
      mutate: (v) =>
        (v.stage4Preparation.placement.trusted.tolerations = [
          { key: "cogs.dev/sandbox", operator: "Equal", value: "kata", effect: "NoSchedule" },
        ]),
    },
    {
      name: "trusted wildcard toleration",
      key: "trusted.tolerations",
      mutate: (v) =>
        (v.stage4Preparation.placement.trusted.tolerations = [{ operator: "Exists", effect: "NoSchedule" }]),
    },
    {
      name: "resource profile",
      key: "resourceProfile",
      mutate: (v) => (v.stage4Preparation.resourceProfile = "custom"),
    },
    {
      name: "workspace size",
      key: "workspace",
      mutate: (v) => (v.stage4Preparation.storage.workspaceSize = "0"),
    },
    {
      name: "session access mode",
      key: "session-state",
      mutate: (v) => (v.stage4Preparation.storage.sessionStateAccessMode = "ReadWriteMany"),
    },
    {
      name: "idle lifetime",
      key: "idleSeconds",
      mutate: (v) => (v.stage4Preparation.lifecycle.idleSeconds = 0),
    },
    {
      name: "fractional idle lifetime",
      key: "idleSeconds",
      mutate: (v) => (v.stage4Preparation.lifecycle.idleSeconds = 1800.5),
    },
    {
      name: "string idle lifetime",
      key: "idleSeconds",
      mutate: (v) => ((v.stage4Preparation.lifecycle as unknown as Record<string, unknown>).idleSeconds = "1800"),
    },
    {
      name: "hard lifetime",
      key: "hardSeconds",
      mutate: (v) => (v.stage4Preparation.lifecycle.hardSeconds = 28801),
    },
    {
      name: "fractional hard lifetime",
      key: "hardSeconds",
      mutate: (v) => (v.stage4Preparation.lifecycle.hardSeconds = 28800.5),
    },
    {
      name: "termination grace",
      key: "terminationGraceSeconds",
      mutate: (v) => (v.stage4Preparation.lifecycle.terminationGraceSeconds = 0),
    },
    {
      name: "fractional termination grace",
      key: "terminationGraceSeconds",
      mutate: (v) => (v.stage4Preparation.lifecycle.terminationGraceSeconds = 30.5),
    },
    {
      name: "WAL below bound",
      key: "auditWalMaxBytes",
      mutate: (v) => (v.stage4Preparation.auditWalMaxBytes = 0),
    },
    {
      name: "WAL above bound",
      key: "auditWalMaxBytes",
      mutate: (v) => (v.stage4Preparation.auditWalMaxBytes = 1073741825),
    },
    {
      name: "fractional WAL",
      key: "auditWalMaxBytes",
      mutate: (v) => (v.stage4Preparation.auditWalMaxBytes = 268435456.5),
    },
    {
      name: "capability source binding",
      key: "sourceBindingRequired",
      mutate: (v) => (v.stage4Preparation.proxyIdentity.sourceBindingRequired = false),
    },
  ];

  for (const hostile of cases) {
    const values = validValues();
    hostile.mutate(values);
    const temporary = writeTemporaryValues(values);
    try {
      const result = renderNotesResult(temporary.path, ["--skip-schema-validation"]);
      assert.equal(result.error, undefined, `${hostile.name}: ${result.error?.message}`);
      assert.notEqual(result.status, 0, `${hostile.name}: unexpectedly rendered`);
      assert.doesNotMatch(result.stdout, /^apiVersion:/mu, `${hostile.name}: no usable manifest stream`);
      assert.match(result.stderr, escapePattern(hostile.key), `${hostile.name}: bounded template error`);
    } finally {
      rmSync(temporary.directory, { recursive: true, force: true });
    }
  }
});
