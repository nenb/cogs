import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const dockerfilePath = resolve(root, "images/sandbox/Dockerfile");
const entrypointPath = resolve(root, "images/sandbox/entrypoint.sh");
const sshdConfigPath = resolve(root, "images/sandbox/sshd_config");
const dockerfile = readFileSync(dockerfilePath, "utf8");
const entrypoint = readFileSync(entrypointPath, "utf8");
const sshdConfig = readFileSync(sshdConfigPath, "utf8");

const packages = [
  "bash=5.2.37-2+b9",
  "bind9-dnsutils=1:9.20.26-1~deb13u1",
  "ca-certificates=20250419",
  "curl=8.14.1-2+deb13u4",
  "git=1:2.47.3-0+deb13u1",
  "iproute2=6.15.0-1",
  "iptables=1.8.11-2",
  "libexpat1=2.8.2-1~deb13u1",
  "netcat-openbsd=1.229-1",
  "nftables=1.1.3-1",
  "nodejs=20.19.2+dfsg-1+deb13u2",
  "npm=9.2.0~ds1-3",
  "openjdk-21-jre-headless=21.0.11+10-1~deb13u2",
  "openssh-client=1:10.0p1-7+deb13u2",
  "openssh-server=1:10.0p1-7+deb13u2",
  "openssl=3.5.6-1~deb13u2",
  "python3=3.13.5-1",
  "python3-httpx=0.28.1-1",
  "python3-pip=25.1.1+dfsg-1",
  "python3-requests=2.32.3+dfsg-5+deb13u1",
  "socat=1.8.0.3-1",
] as const;

function directive(name: string): string[] {
  return sshdConfig
    .split("\n")
    .filter((line) => line.startsWith(`${name} `))
    .map((line) => line.slice(name.length + 1));
}

function source(command: string) {
  return spawnSync("bash", ["-c", `source "$1"; ${command}`, "sandbox-entrypoint-test", entrypointPath], {
    encoding: "utf8",
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
  });
}

test("sandbox image uses the reviewed Debian base, immutable snapshots, and exact package policy", () => {
  assert.match(
    dockerfile,
    /^FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd$/mu,
  );
  assert.match(dockerfile, /URIs: https:\/\/snapshot\.debian\.org\/archive\/debian\/20260713T000000Z\//u);
  assert.match(dockerfile, /URIs: https:\/\/snapshot\.debian\.org\/archive\/debian-security\/20260731T000000Z\//u);
  assert.doesNotMatch(dockerfile, /\bARG\s+DEBIAN_|\$\{?DEBIAN_/u);
  const install = dockerfile.match(/apt-get install --yes --no-install-recommends \\\n([\s\S]*?)\n {4}&& rm -rf/u)?.[1];
  assert.ok(install);
  assert.deepEqual(
    install
      .split("\n")
      .map((line) => line.trim().replace(/ \\$/u, ""))
      .filter(Boolean),
    packages,
  );
  assert.doesNotMatch(install, /(?:aws|azure|google-cloud|kubectl|kubernetes|openbao|vault)/iu);
  assert.match(dockerfile, /rm -f \/etc\/ssh\/ssh_host_\*/u);
  assert.match(dockerfile, /USER 0:0/u);
});

test("sandbox labels describe an external Kata requirement without claiming isolation from image bytes", () => {
  for (const label of [
    'dev.cogs.profile="kata-sandbox-guest"',
    'dev.cogs.package-policy="debian-trixie-snapshots-20260713-20260731-v1"',
    'dev.cogs.isolation-authority="external-runtime-required"',
    'dev.cogs.credentials="proxy-capability-only-no-upstream-secrets"',
    'dev.cogs.skills-inputs="external-read-only"',
  ]) {
    assert.ok(dockerfile.includes(label), label);
  }
  assert.doesNotMatch(dockerfile, /stage0-scaffold|isolation-authority="image"|vm-isolated|production-ready="true"/iu);
  assert.match(dockerfile, /supplies no VM, network, storage, or tenant-isolation claim by itself/u);
});

test("sshd permits only Ed25519 public-key root access and disables forwarding, tunnels, passwords, and PAM", () => {
  const exact = new Map<string, string>([
    ["AllowUsers", "root"],
    ["PermitRootLogin", "prohibit-password"],
    ["AuthenticationMethods", "publickey"],
    ["HostKeyAlgorithms", "ssh-ed25519"],
    ["PubkeyAcceptedAlgorithms", "ssh-ed25519"],
    ["PasswordAuthentication", "no"],
    ["KbdInteractiveAuthentication", "no"],
    ["ChallengeResponseAuthentication", "no"],
    ["UsePAM", "no"],
    ["DisableForwarding", "yes"],
    ["AllowAgentForwarding", "no"],
    ["AllowTcpForwarding", "no"],
    ["AllowStreamLocalForwarding", "no"],
    ["GatewayPorts", "no"],
    ["PermitOpen", "none"],
    ["PermitListen", "none"],
    ["PermitTunnel", "no"],
    ["X11Forwarding", "no"],
    ["PermitUserEnvironment", "no"],
    ["PermitUserRC", "no"],
  ]);
  for (const [name, value] of exact) assert.deepEqual(directive(name), [value], name);
  assert.deepEqual(directive("HostKey"), ["/run/cogs-runtime/ssh_host_ed25519_key"]);
  assert.deepEqual(directive("AuthorizedKeysFile"), ["/run/cogs-runtime/authorized_keys"]);
  assert.deepEqual(directive("Subsystem"), ["sftp internal-sftp"]);
  assert.equal(sshdConfig.includes("AcceptEnv"), false);
});

test("entrypoint is valid Bash and exposes bounded pure capability and literal-endpoint validators", () => {
  const syntax = spawnSync("bash", ["-n", entrypointPath], { encoding: "utf8" });
  assert.equal(syntax.status, 0, syntax.stderr);

  const valid = source(
    "validate_capability AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA && " +
      'test "$(validate_proxy_endpoint http://192.0.2.1:15001)" = http://192.0.2.1:15001 && ' +
      'test "$(validate_proxy_endpoint http://[2001:db8::1]:15001)" = "http://[2001:db8::1]:15001"',
  );
  assert.equal(valid.status, 0, valid.stderr);

  for (const hostile of [
    "validate_capability short",
    `validate_capability ${"A".repeat(129)}`,
    "validate_capability 'A capability containing spaces'",
    "validate_proxy_endpoint http://proxy.internal:15001",
    "validate_proxy_endpoint http://192.0.2.1",
    "validate_proxy_endpoint http://user@192.0.2.1:15001",
    "validate_proxy_endpoint https://192.0.2.1:15001",
    "validate_proxy_endpoint http://192.0.2.1:15001/path",
  ]) {
    const result = source(hostile);
    assert.notEqual(result.status, 0, hostile);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
  }
});

test("entrypoint requires stable injected identities and emits only capability-bearing standard proxy URLs", () => {
  assert.match(entrypoint, /readonly INPUT_ROOT=\/run\/cogs-input/u);
  for (const name of [
    "ssh_host_ed25519_key",
    "ssh_host_ed25519_key.pub",
    "client_ed25519_key.pub",
    "egress-ca.crt",
    "proxy-capability",
  ]) {
    assert.ok(entrypoint.includes(`$INPUT_ROOT/${name}`), name);
  }
  assert.match(entrypoint, /stat -c '%d:%i:%s:%u:%g:%a:%h:%F'/u);
  assert.match(entrypoint, /realpath -e/u);
  assert.match(entrypoint, /single-link regular file/u);
  assert.match(entrypoint, /ssh-keygen -y -f/u);
  assert.match(entrypoint, /\[\[ "\$derived" == "\$provided" \]\]/u);
  assert.match(entrypoint, /client_lines.*== 1/u);
  assert.match(entrypoint, /printf 'restrict %s %s\\n'/u);
  assert.doesNotMatch(entrypoint, /ssh-keygen\s+(?:-[^\n ]+\s+)*-(?:A|t)\b/u);
  assert.match(entrypoint, /proxy_url="http:\/\/cogs:\$\{capability\}@\$\{endpoint#http:\/\/\}"/u);
  assert.doesNotMatch(entrypoint, /Proxy-Authorization|upstream.*(?:token|password|secret)/iu);
  assert.match(entrypoint, /exec \/usr\/bin\/env -i/u);
});

test("SSH sessions receive uppercase and lowercase proxy/trust compatibility variables", () => {
  for (const name of [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "AWS_CA_BUNDLE",
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "ssl_cert_file",
    "requests_ca_bundle",
    "curl_ca_bundle",
    "node_extra_ca_certs",
    "aws_ca_bundle",
    "grpc_default_ssl_roots_file_path",
    "git_ssl_cainfo",
    "pip_cert",
  ]) {
    assert.match(entrypoint, new RegExp(`SetEnv [^\\n]*\\b${name}=`, "u"), name);
  }
  assert.match(entrypoint, /SetEnv COGS_PROFILE=kata-sandbox-guest/u);
});

test("sandbox rejects standard workload credentials and keeps skills as external read-only inputs", () => {
  for (const marker of [
    "AWS_SECRET_ACCESS_KEY",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "VAULT_TOKEN",
    "BAO_TOKEN",
    "/var/run/secrets/kubernetes.io/serviceaccount",
  ]) {
    assert.ok(entrypoint.includes(marker), marker);
  }
  assert.match(dockerfile, /-m 0555 \/shared\/skills \/user\/skills/u);
  assert.match(entrypoint, /exact_directory \/shared\/skills 555/u);
  assert.match(entrypoint, /read_only_path \/shared\/skills/u);
  assert.match(entrypoint, /exact_directory \/user\/skills 555/u);
  assert.match(entrypoint, /read_only_path \/user\/skills/u);
  assert.match(entrypoint, /read_only_path "\$INPUT_ROOT"/u);
  assert.match(entrypoint, /findmnt --noheadings --output VFS-OPTIONS --target/u);
  assert.doesNotMatch(entrypoint, /chmod[^\n]*(?:\/shared\/skills|\/user\/skills)/u);
});
