import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(import.meta.dirname, "..");
const dockerfilePath = resolve(root, "images/sandbox/Dockerfile");
const insecureDockerfilePath = resolve(root, "dev/insecure-sandbox/Dockerfile");
const entrypointPath = resolve(root, "images/sandbox/entrypoint.sh");
const captureInputsPath = resolve(root, "images/sandbox/capture-inputs.py");
const sshdConfigPath = resolve(root, "images/sandbox/sshd_config");
const dockerfile = readFileSync(dockerfilePath, "utf8");
const insecureDockerfile = readFileSync(insecureDockerfilePath, "utf8");
const entrypoint = readFileSync(entrypointPath, "utf8");
const captureInputs = readFileSync(captureInputsPath, "utf8");
const sshdConfig = readFileSync(sshdConfigPath, "utf8");

const packages = [
  "bash=5.2.21-2ubuntu4",
  "ca-certificates=20260601~24.04.1",
  "git=1:2.43.0-1ubuntu7.3",
  "openssh-client=1:9.6p1-3ubuntu13.18",
  "openssh-server=1:9.6p1-3ubuntu13.18",
  "openssl=3.0.13-0ubuntu3.12",
  "python3=3.12.3-0ubuntu2.1",
] as const;

const bootstrapArtifacts = [
  {
    package: "openssl",
    version: "3.0.13-0ubuntu3.12",
    architecture: "amd64",
    sha256: "321b30ad5a1c3783cb3d73ae439f824f6d3874d76a93a62f4a984959b490aa7b",
    path: "pool/main/o/openssl/openssl_3.0.13-0ubuntu3.12_amd64.deb",
  },
  {
    package: "ca-certificates",
    version: "20260601~24.04.1",
    architecture: "all",
    sha256: "6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50",
    path: "pool/main/c/ca-certificates/ca-certificates_20260601~24.04.1_all.deb",
  },
] as const;

const removedProductionRoots = [
  "bind9-dnsutils",
  "curl",
  "iproute2",
  "iptables",
  "libexpat1",
  "netcat-openbsd",
  "nftables",
  "nodejs",
  "npm",
  "openjdk-21-jre-headless",
  "openssh-sftp-server",
  "python3-httpx",
  "python3-pip",
  "python3-requests",
  "socat",
] as const;

const forbiddenProductionClosure = [
  "bind9-dnsutils",
  "curl",
  "iproute2",
  "iptables",
  "netcat-openbsd",
  "nftables",
  "nodejs",
  "npm",
  "openjdk-21-jre-headless",
  "python3-httpx",
  "python3-pip",
  "python3-requests",
  "socat",
] as const;

const insecureConformanceRoots = [
  "curl",
  "dnsutils",
  "iproute2",
  "iptables",
  "netcat-openbsd",
  "nftables",
  "nodejs",
  "npm",
  "openjdk-21-jre-headless",
  "python3-httpx",
  "python3-pip",
  "python3-requests",
  "socat",
] as const;

function installPackages(source: string): string[] {
  const install = source.match(/apt-get install --yes --no-install-recommends \\\n([\s\S]*?)\n {4}&&/u)?.[1];
  assert.ok(install);
  return install
    .split("\n")
    .map((line) => line.trim().replace(/ \\$/u, ""))
    .filter(Boolean);
}

function packageName(specification: string): string {
  return specification.split("=")[0] ?? "";
}

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

test("sandbox image uses the exact amd64 Ubuntu 24.04 base and signed fixed snapshot package policy", () => {
  assert.match(
    dockerfile,
    /^FROM --platform=linux\/amd64 ubuntu:24\.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90$/mu,
  );
  assert.match(dockerfile, /URIs: http:\/\/archive\.ubuntu\.com\/ubuntu\//u);
  assert.match(dockerfile, /Suites: noble noble-updates/u);
  assert.match(dockerfile, /URIs: http:\/\/security\.ubuntu\.com\/ubuntu\//u);
  assert.match(dockerfile, /Suites: noble-security/u);
  assert.equal((dockerfile.match(/Components: main universe/gu) ?? []).length, 2);
  assert.equal((dockerfile.match(/Snapshot: 20260801T000000Z/gu) ?? []).length, 2);
  assert.equal((dockerfile.match(/Signed-By: \/usr\/share\/keyrings\/ubuntu-archive-keyring\.gpg/gu) ?? []).length, 2);
  assert.match(dockerfile, /APT::Snapshot "20260801T000000Z";/u);
  assert.match(dockerfile, /APT::Update::Error-Mode=any/u);
  assert.match(dockerfile, /Acquire::Retries "0";/u);
  assert.match(dockerfile, /Acquire::AllowInsecureRepositories "false";/u);
  assert.match(dockerfile, /Acquire::AllowDowngradeToInsecureRepositories "false";/u);
  assert.match(dockerfile, /APT::Get::AllowUnauthenticated "false";/u);
  assert.doesNotMatch(dockerfile, /noble-backports|\b(?:restricted|multiverse)\b/iu);
  assert.doesNotMatch(dockerfile, /\bARG\s+(?:UBUNTU|SNAPSHOT)_|\$\{?(?:UBUNTU|SNAPSHOT)_/u);

  for (const artifact of bootstrapArtifacts) {
    assert.ok(
      dockerfile.includes(
        `ADD --checksum=sha256:${artifact.sha256} \\\n  https://snapshot.ubuntu.com/ubuntu/20260801T000000Z/${artifact.path}`,
      ),
      artifact.package,
    );
    assert.ok(dockerfile.includes(`Package)" = ${artifact.package}`), artifact.package);
    assert.match(
      dockerfile,
      new RegExp(`Version\\)" = '?${artifact.version.replaceAll(".", "\\.").replaceAll("+", "\\+")}'?`, "u"),
      artifact.package,
    );
    assert.ok(dockerfile.includes(`Architecture)" = ${artifact.architecture}`), artifact.package);
  }
  assert.match(
    dockerfile,
    /dpkg --unpack \/tmp\/cogs-bootstrap-openssl\.deb \/tmp\/cogs-bootstrap-ca-certificates\.deb/u,
  );
  assert.match(dockerfile, /update-ca-certificates --fresh/u);
  assert.match(dockerfile, /test -s \/etc\/ssl\/certs\/ca-certificates\.crt/u);

  const install = installPackages(dockerfile);
  assert.deepEqual(install, packages);
  assert.doesNotMatch(install.join("\n"), /(?:aws|azure|google-cloud|kubectl|kubernetes|openbao|vault)/iu);
  assert.match(dockerfile, /test -z "\$\(dpkg --audit\)"/u);
  assert.doesNotMatch(dockerfile, /rm -rf \/var\/lib\/(?:apt|dpkg)|rm -rf \/etc\/apt/u);
  assert.match(dockerfile, /rm -f \/etc\/ssh\/ssh_host_\*/u);
  for (const generatedIdentity of ["/etc/machine-id", "/var/lib/dbus/machine-id", "/var/lib/systemd/random-seed"]) {
    assert.ok(dockerfile.includes(generatedIdentity), generatedIdentity);
  }
  assert.match(dockerfile, /USER 0:0/u);
});

test("conformance clients and network probes cannot re-enter production and remain in the labelled insecure profile", () => {
  const productionNames = new Set(installPackages(dockerfile).map(packageName));
  for (const name of removedProductionRoots) assert.equal(productionNames.has(name), false, name);

  const closureGuard = dockerfile.match(/readonly forbidden_packages=\(([^)]+)\)/u)?.[1]?.split(/\s+/u);
  assert.deepEqual(closureGuard, forbiddenProductionClosure);
  assert.match(dockerfile, /dpkg-query -W -f='\$\{db:Status-Status\}' "\$package"/u);
  assert.match(dockerfile, /\[\[ "\$\(dpkg-query[^\n]+\)" == installed \]\]/u);

  const insecureNames = new Set(installPackages(insecureDockerfile).map(packageName));
  for (const name of insecureConformanceRoots) assert.equal(insecureNames.has(name), true, name);
  for (const label of [
    'dev.cogs.profile="insecure-container"',
    'dev.cogs.authority="functional-only"',
    'dev.cogs.package-policy="debian-trixie-snapshots-20260713-20260811-insecure-conformance-v2"',
  ]) {
    assert.ok(insecureDockerfile.includes(label), label);
  }
});

test("sandbox labels describe an external Kata requirement without claiming isolation from image bytes", () => {
  for (const label of [
    'dev.cogs.profile="kata-sandbox-guest"',
    'dev.cogs.package-policy="ubuntu-noble-snapshot-20260801-production-core-v1"',
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
    `validate_capability ${"A".repeat(31)}`,
    `validate_capability ${"A".repeat(129)}`,
    "validate_capability 'A capability containing spaces'",
    `validate_capability ${"A".repeat(31)}+`,
    `validate_capability ${"A".repeat(31)}=`,
    `validate_capability ${"A".repeat(31)}:`,
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

test("entrypoint consumes only stable private copies of injected inputs", () => {
  assert.match(entrypoint, /readonly INPUT_ROOT=\/run\/cogs-input/u);
  assert.match(entrypoint, /readonly INPUT_CAPTURE=\/usr\/local\/libexec\/cogs-capture-inputs/u);
  assert.match(entrypoint, /python3 -I "\$INPUT_CAPTURE" "\$INPUT_ROOT" "\$RUNTIME_ROOT"/u);
  assert.doesNotMatch(entrypoint, /"\$INPUT_ROOT\/(?:ssh_|client_|egress-ca|proxy-capability)/u);
  for (const name of [
    "ssh_host_ed25519_key",
    "ssh_host_ed25519_key.pub",
    "client_ed25519_key.pub",
    "egress-ca.crt",
    "proxy-capability",
  ]) {
    assert.ok(captureInputs.includes(`"${name}"`), name);
    assert.ok(entrypoint.includes(`$RUNTIME_ROOT/${name}`), name);
  }
  assert.match(entrypoint, /stat -c '%d:%i:%s:%u:%g:%a:%h:%Y:%Z:%F'/u);
  assert.match(entrypoint, /realpath -e/u);
  assert.match(entrypoint, /ssh-keygen -y -f/u);
  assert.match(entrypoint, /derived_fields.*== 2.*derived_fields.*== 3/u);
  assert.match(entrypoint, /derived=.*awk 'NR == 1 \{ print \$1 " " \$2 \}'/u);
  assert.match(entrypoint, /\[\[ "\$derived" == "\$provided" \]\]/u);
  assert.match(entrypoint, /client_lines.*== 1/u);
  assert.match(entrypoint, /printf 'restrict %s %s\\n'/u);
  assert.doesNotMatch(entrypoint, /ssh-keygen\s+(?:-[^\n ]+\s+)*-(?:A|t)\b/u);
  assert.match(entrypoint, /proxy_url="http:\/\/cogs:\$\{capability\}@\$\{endpoint#http:\/\/\}"/u);
  assert.doesNotMatch(entrypoint, /Proxy-Authorization|upstream.*(?:token|password|secret)/iu);
  assert.match(entrypoint, /exec \/usr\/bin\/env -i/u);
  assert.match(dockerfile, /capture-inputs\.py \/usr\/local\/libexec\/cogs-capture-inputs/u);
});

test("input capturer uses retained directory descriptors, openat no-follow reads, stable generations, and exclusive outputs", () => {
  const syntax = spawnSync(
    "python3",
    [
      "-I",
      "-c",
      'compile(open(__import__("sys").argv[1], "rb").read(), __import__("sys").argv[1], "exec")',
      captureInputsPath,
    ],
    { encoding: "utf8" },
  );
  assert.equal(syntax.status, 0, syntax.stderr);
  assert.match(captureInputs, /os\.open\(path, os\.O_RDONLY \| os\.O_DIRECTORY \| os\.O_NOFOLLOW\)/u);
  assert.match(captureInputs, /os\.open\(name, os\.O_RDONLY \| os\.O_NOFOLLOW, dir_fd=source_root\)/u);
  for (const field of [
    "st_dev",
    "st_ino",
    "st_size",
    "st_uid",
    "st_gid",
    "st_mode",
    "st_nlink",
    "st_mtime_ns",
    "st_ctime_ns",
  ]) {
    assert.ok(captureInputs.includes(field), field);
  }
  assert.match(captureInputs, /os\.O_WRONLY \| os\.O_CREAT \| os\.O_EXCL \| os\.O_NOFOLLOW/u);
  assert.match(captureInputs, /0o600/u);
  assert.match(captureInputs, /os\.fsync\(descriptor\)/u);
  assert.match(captureInputs, /os\.fsync\(output_root\)/u);
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
