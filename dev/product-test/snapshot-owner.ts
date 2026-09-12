import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import type { LaunchConfig } from "../../src/launch/config.ts";
import { buildCogsSkillBundle, type CogsSkillBundleHandle } from "../../src/skills/bundle.ts";
import { createCogsPrivateSkillStore } from "../../src/skills/local-private-store.ts";
import { createCogsSharedSkillOciLayoutResolver } from "../../src/skills/oci-layout.ts";
import { loadCogsRetainedSkillPair } from "../../src/skills/session-preparer.ts";
import { parseCogsSkillSnapshotReceipt } from "../../src/skills/snapshot-session-preparer.ts";

export const hash = (bytes: Uint8Array | string): `sha256:${string}` =>
  `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
export function canonical(value: unknown): string {
  const encode = (v: unknown): string =>
    Array.isArray(v)
      ? `[${v.map(encode).join(",")}]`
      : v !== null && typeof v === "object"
        ? `{${Object.keys(v)
            .sort()
            .map((k) => `${JSON.stringify(k)}:${encode((v as Record<string, unknown>)[k])}`)
            .join(",")}}`
        : JSON.stringify(v);
  return `${encode(value)}\n`;
}
export function check(value: unknown): asserts value {
  if (!value) throw new Error("product-test contract failed");
}
export type Mount = Readonly<{ source: string; target: string; ro: boolean }>;
export type ContainerSpec = Readonly<{
  image: string;
  network: string;
  caps: readonly string[];
  mask: number;
  mounts: readonly Mount[];
  tmpfs: Readonly<Record<string, string>>;
}>;
export type ContainerReceipt = { id: string; pid: number; namespace: string; spec: ContainerSpec };
export type CustodyPort = Readonly<{
  root: string;
  generation: string;
  purpose?: "run" | "capability-probe";
  closed?: Promise<void>;
  request<T = unknown>(op: string, fields?: Record<string, unknown>): Promise<T>;
}>;

/** Independent process owns partial acquisitions even if the TypeScript caller disappears. */
export class HostCustody implements CustodyPort {
  readonly root: string;
  readonly generation: string;
  readonly #child: ChildProcessWithoutNullStreams;
  readonly closed: Promise<void>;
  #tail = Promise.resolve();
  #input = Buffer.alloc(0);
  #pending: { resolve(value: unknown): void; reject(error: Error): void } | undefined;
  #lost = false;
  constructor(
    generation: string,
    seconds: number,
    readonly purpose: "run" | "capability-probe" = "run",
  ) {
    check(/^[a-f0-9]{32}$/.test(generation) && seconds >= 60 && seconds <= 600);
    this.generation = generation;
    this.root = `/var/lib/cogs-product-test/${generation}`;
    this.#child = spawn("/usr/bin/python3", ["-I", fileURLToPath(new URL("host-custody.py", import.meta.url))], {
      env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL: "C", HOME: "/nonexistent" },
      stdio: ["pipe", "pipe", "pipe"],
      detached: true,
    });
    this.closed = new Promise((resolve, reject) => {
      this.#child.once("error", () => {
        this.#lose();
        reject(new Error("custody unavailable"));
      });
      this.#child.once("close", (code) => {
        this.#lose();
        code === 0 ? resolve() : reject(new Error("custody cleanup required"));
      });
    });
    void this.closed.catch(() => undefined);
    this.#child.stderr.resume(); // Never relay subprocess diagnostics or material.
    this.#child.stdout.on("data", (chunk: Buffer) => {
      try {
        check(this.#pending && this.#input.length + chunk.length <= 2 * 1024 * 1024);
        this.#input = Buffer.concat([this.#input, chunk]);
        if (!this.#input.includes(10)) return;
        const result = JSON.parse(this.#input.toString("utf8"));
        check(canonical(result) === this.#input.toString("utf8") && result.generation === this.generation);
        check(Object.keys(result).sort().join() === "generation,result");
        this.#input = Buffer.alloc(0);
        this.#pending.resolve(result.result);
        this.#pending = undefined;
      } catch {
        this.#lose();
      }
    });
    this.#child.stdin.on("error", () => this.#lose());
    this.#child.stdin.write(canonical({ generation, seconds, purpose }));
  }
  request<T = unknown>(op: string, fields: Record<string, unknown> = {}): Promise<T> {
    const result = this.#tail.then(
      () =>
        new Promise<T>((resolve, reject) => {
          check(!this.#lost && !this.#pending && !Object.hasOwn(fields, "op") && !Object.hasOwn(fields, "generation"));
          this.#pending = { resolve: (v) => resolve(v as T), reject };
          this.#child.stdin.write(canonical({ ...fields, op, generation: this.generation }));
        }),
    );
    this.#tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
  #lose(): void {
    this.#lost = true;
    this.#pending?.reject(new Error("custody unavailable; preserve receipts"));
    this.#pending = undefined;
    this.#child.stdin.end(); // EOF asks the independent owner to settle, never grants destroy authority here.
  }
}

export async function put(host: CustodyPort, path: string, bytes: string | Buffer, mode = 0o400, uid = 0) {
  await host.request("file", { path, data: Buffer.from(bytes).toString("base64"), mode, uid });
}
export async function dir(host: CustodyPort, path: string, mode = 0o700, uid = 0) {
  await host.request("mkdir", { path, mode, uid });
}

/** Only closed generated fixtures are admitted, never a checkout, home, or user-selected source. */
export class LocalSkillSnapshotOwner {
  readonly shared: CogsSkillBundleHandle;
  readonly user: CogsSkillBundleHandle;
  readonly sharedRevision: `sha256:${string}`;
  readonly #manifest: Buffer;
  #sources: Record<"shared" | "user", { source_device: string; source_inode: string }> | undefined;
  constructor(
    readonly host: CustodyPort,
    nonempty: boolean,
  ) {
    const bundle = (scope: string) =>
      buildCogsSkillBundle({
        entries: nonempty
          ? [
              {
                path: `${scope}-fixture/SKILL.md`,
                executable: false,
                content: Buffer.from(
                  `---\nname: ${scope}-fixture\ndescription: Synthetic functional test skill.\n---\nOnly use the fixed local fixture.\n`,
                ),
              },
            ]
          : [],
      });
    this.shared = bundle("shared");
    this.user = bundle("user");
    this.#manifest = Buffer.from(
      JSON.stringify({
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        artifactType: this.shared.mediaType,
        config: { mediaType: "application/vnd.oci.empty.v1+json", digest: hash("{}"), size: 2 },
        layers: [{ mediaType: this.shared.mediaType, digest: this.shared.digest, size: this.shared.byteLength }],
      }),
    );
    this.sharedRevision = hash(this.#manifest);
  }
  async publish(launch: LaunchConfig): Promise<void> {
    check(
      !this.#sources &&
        launch.skills.shared_revision === this.sharedRevision &&
        launch.skills.user_revision === this.user.digest,
    );
    await this.host.request("storage", { name: "publication" });
    await dir(this.host, "inputs");
    await dir(this.host, "inputs/shared-oci", 0o555);
    await dir(this.host, "inputs/shared-oci/blobs", 0o555);
    await dir(this.host, "inputs/shared-oci/blobs/sha256", 0o555);
    await dir(this.host, "inputs/private-source", 0o555);
    const userRoot = `inputs/private-source/${hash(launch.user_id).slice(7)}`;
    await dir(this.host, userRoot, 0o555);
    await put(this.host, "inputs/shared-oci/oci-layout", '{"imageLayoutVersion":"1.0.0"}', 0o444);
    await put(
      this.host,
      "inputs/shared-oci/index.json",
      JSON.stringify({
        schemaVersion: 2,
        manifests: [
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: this.sharedRevision,
            size: this.#manifest.length,
            artifactType: this.shared.mediaType,
          },
        ],
      }),
      0o444,
    );
    for (const bytes of [Buffer.from("{}"), this.#manifest, this.shared.copyBytes()])
      await put(this.host, `inputs/shared-oci/blobs/sha256/${hash(bytes).slice(7)}`, bytes, 0o444);
    const made = new Set<string>();
    for (const file of this.user.files) {
      const parts = file.path.split("/");
      for (let n = 1; n < parts.length; n++) {
        const path = `${userRoot}/${parts.slice(0, n).join("/")}`;
        if (!made.has(path)) {
          await dir(this.host, path, 0o555);
          made.add(path);
        }
      }
      await put(this.host, `${userRoot}/${file.path}`, this.user.copyFile(file.path), file.executable ? 0o555 : 0o444);
    }
    const pair = Object.fromEntries(
      (["shared", "user"] as const).map((scope) => {
        const bundle = this[scope];
        const entries = [
          [".cogs-skills-bundle.json", bundle.copyBytes(), 0o444] as const,
          ...bundle.files.map((f) => [f.path, bundle.copyFile(f.path), f.executable ? 0o555 : 0o444] as const),
        ];
        return [
          scope,
          Object.fromEntries(
            entries.map(([p, data, mode]) => [
              `${bundle.digest.slice(7)}/${p}`,
              { data: data.toString("base64"), mode },
            ]),
          ),
        ];
      }),
    );
    const sources = await this.host.request<Record<"shared" | "user", { source_device: string; source_inode: string }>>(
      "pair",
      { pair },
    );
    // Discovery reads the journaled publication: even SIGKILL leaves no external host temp.
    const retained = await loadCogsRetainedSkillPair(
      {
        sharedResolver: await createCogsSharedSkillOciLayoutResolver({
          layoutRoot: `${this.host.root}/inputs/shared-oci`,
        }),
        privateStore: await createCogsPrivateSkillStore({
          sourceRoot: `${this.host.root}/inputs/private-source`,
          storeRoot: `${this.host.root}/state/host-private`,
        }),
      },
      launch,
      AbortSignal.timeout(5000),
      Object.fromEntries(
        (["shared", "user"] as const).map((scope) => [
          scope,
          `${this.host.root}/publication/${this.host.generation}/${scope}/${this[scope].digest.slice(7)}`,
        ]),
      ) as Record<"shared" | "user", string>,
    );
    check(retained.shared.bundle.digest === this.shared.digest && retained.user.bundle.digest === this.user.digest);
    this.#sources = sources;
  }
  mounts(): readonly Mount[] {
    check(this.#sources);
    return (["shared", "user"] as const).map((scope) => ({
      source: `${this.host.root}/publication/${this.host.generation}/${scope}/${this[scope].digest.slice(7)}`,
      target: `/${scope}/skills/${this[scope].digest.slice(7)}`,
      ro: true,
    }));
  }
  async lease(launch: LaunchConfig, worker: ContainerReceipt, sandbox: ContainerReceipt) {
    check(this.#sources);
    const receipt = parseCogsSkillSnapshotReceipt(
      Buffer.from(
        canonical({
          version: "cogs.skill-snapshot-receipt/v1",
          generation: this.host.generation,
          consumer_id: randomBytes(16).toString("hex"),
          session_id: launch.session_id,
          launch_digest: hash(canonical(launch)),
          worker_id: worker.id,
          sandbox_id: sandbox.id,
          sandbox_mount_namespace: sandbox.namespace,
          ...Object.fromEntries(
            (["shared", "user"] as const).map((scope) => [
              scope,
              {
                ...this.#sources?.[scope],
                destination: `/${scope}/skills/${this[scope].digest.slice(7)}`,
                read_only: true,
                bundle_digest: this[scope].digest,
              },
            ]),
          ),
        }),
      ),
    );
    await this.host.request("lease", { receipt });
    return receipt;
  }
}

export const SANDBOX_CAPABILITIES = Object.freeze(
  "CHOWN DAC_OVERRIDE FOWNER SETGID SETUID KILL NET_BIND_SERVICE SYS_CHROOT".split(" "),
);
const CAPABILITY_BITS = [0, 1, 3, 6, 7, 5, 10, 18];
export const SANDBOX_CAPABILITY_MASK = CAPABILITY_BITS.reduce((mask, bit) => mask + 2 ** bit, 0);
export function sandboxCapabilities(removed: string) {
  check(SANDBOX_CAPABILITIES.includes(removed));
  return {
    caps: SANDBOX_CAPABILITIES.filter((c) => c !== removed),
    mask: SANDBOX_CAPABILITY_MASK - 2 ** (CAPABILITY_BITS[SANDBOX_CAPABILITIES.indexOf(removed)] as number),
  };
}
export function containerArguments(host: CustodyPort, spec: ContainerSpec, command: readonly string[], user: string) {
  check(/^sha256:[a-f0-9]{64}$/.test(spec.image));
  check(spec.network === "none" || /^container:[a-f0-9]{64}$/.test(spec.network));
  check(["0:0", "65532:65532"].includes(user));
  const removed = SANDBOX_CAPABILITIES.filter((c) => !spec.caps.includes(c));
  const probe = host.purpose === "capability-probe" && user === "0:0";
  check(!probe || removed.length === 1);
  const expected =
    user === "65532:65532"
      ? { caps: [], mask: 0 }
      : probe
        ? sandboxCapabilities(removed[0] as string)
        : { caps: SANDBOX_CAPABILITIES, mask: SANDBOX_CAPABILITY_MASK };
  check(canonical(spec.caps) === canonical(expected.caps) && spec.mask === expected.mask);
  const targets = new Set<string>();
  for (const m of spec.mounts) {
    check(m.source.startsWith(`${host.root}/`) && !m.source.includes("..") && !/[,:\n]/.test(m.source));
    check(m.target.startsWith("/") && !/[,:\n]/.test(m.target) && !targets.has(m.target));
    targets.add(m.target);
  }
  for (const a of spec.mounts)
    for (const b of spec.mounts)
      if (a !== b) {
        check(a.source !== b.source && !a.source.startsWith(`${b.source}/`) && !b.source.startsWith(`${a.source}/`));
        check(!a.target.startsWith(`${b.target}/`));
      }
  return [
    ..."--pull never --platform linux/amd64 --read-only --log-driver none --memory=4g --memory-swap=4g --memory-swappiness=0 --cpus=2 --pids-limit=128 --shm-size=16m --cap-drop ALL --security-opt no-new-privileges".split(
      " ",
    ),
    "--cgroup-parent",
    `/cogs-product-${host.generation}`,
    ...spec.caps.flatMap((cap) => ["--cap-add", cap]),
    "--network",
    spec.network,
    "--user",
    user,
    "--label",
    `cogs.product.generation=${host.generation}`,
    ...spec.mounts.flatMap((m) => [
      "--mount",
      `type=bind,src=${m.source},dst=${m.target},bind-propagation=rprivate${m.ro ? ",readonly" : ""}`,
    ]),
    ...Object.entries(spec.tmpfs).flatMap(([target, options]) => ["--tmpfs", `${target}:${options}`]),
    ...command,
    spec.image,
  ];
}

export async function pinnedTrust(host: CustodyPort, image: string): Promise<Buffer> {
  const spec: ContainerSpec = { image, network: "none", caps: [], mask: 0, mounts: [], tmpfs: {} };
  const argv = containerArguments(host, spec, ["--entrypoint", "/nodejs/bin/node"], "65532:65532");
  argv.push("-e", "process.stdout.write(require('node:fs').readFileSync('/etc/ssl/certs/ca-certificates.crt'))");
  const result = await host.request<string>("create", { role: "trust", spec, argv });
  const bytes = Buffer.from(result, "base64");
  check(bytes.length >= 1000 && bytes.length <= 1024 * 1024 && !bytes.includes("PRIVATE KEY"));
  return bytes;
}
