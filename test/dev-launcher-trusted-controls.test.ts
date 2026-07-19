import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { LauncherProfile } from "../dev/launcher/contract.ts";
import { createState, resolveLauncherState, writePhase } from "../dev/launcher/state.ts";
import {
  materializeTrustedSshControls,
  preflightTrustedEgressRoot,
  TRUSTED_EGRESS_RUNTIME_ROOT,
  TRUSTED_SSH_RUNTIME_ROOT,
  type TrustedControlSeams,
} from "../dev/launcher/trusted-controls.ts";

const sourceRevision = "a".repeat(40);

function hostBlob(fill = 7): Buffer {
  const blob = Buffer.alloc(51);
  blob.writeUInt32BE(11, 0);
  blob.write("ssh-ed25519", 4, "ascii");
  blob.writeUInt32BE(32, 15);
  blob.fill(fill, 19);
  return blob;
}

function expectedPin(blob: Buffer): string {
  return `SHA256:${createHash("sha256").update(blob).digest("base64").replace(/=+$/u, "")}`;
}

type Setup = Awaited<ReturnType<typeof setup>>;

async function setup(profile: "insecure-container" | "linux-kvm" = "insecure-container") {
  const temp = await realpath(await mkdtemp(join(tmpdir(), "cogs-trusted-controls-")));
  await chmod(temp, 0o700);
  const launcherRoot = join(temp, "launcher");
  await mkdir(launcherRoot, { mode: 0o700 });
  await chmod(launcherRoot, 0o700);
  const state = await resolveLauncherState({ root: launcherRoot, name: "session", sourceRevision });
  const creating = await createState(state, profile);
  await writePhase(state, creating, "sandbox-ready");
  await mkdir(state.driverStateDir, { mode: 0o700 });
  await chmod(state.driverStateDir, 0o700);
  const sentinel = profile === "insecure-container" ? ".cogs-insecure-owner" : ".cogs-linux-kvm-v1";
  const sentinelText =
    profile === "insecure-container"
      ? `${createHash("sha256").update(state.driverStateDir).digest("hex").slice(0, 12)}\n`
      : "";
  await writeFile(join(state.driverStateDir, sentinel), sentinelText, { mode: 0o600 });
  const control = join(state.driverStateDir, "control");
  await mkdir(control, { mode: 0o700 });
  await chmod(control, 0o700);
  const key = Buffer.from(
    "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-private-material\n-----END OPENSSH PRIVATE KEY-----\n",
  );
  await writeFile(join(control, "client_ed25519_key"), key, { mode: 0o600 });
  await writeFile(join(control, "client_ed25519_key.pub"), "public\n", { mode: 0o600 });
  if (profile === "linux-kvm") {
    await writeFile(join(control, "host_ed25519_key"), "host-private\n", { mode: 0o600 });
    await writeFile(join(control, "host_ed25519_key.pub"), "host-public\n", { mode: 0o600 });
  }
  const blob = hostBlob();
  const port = 43210;
  const host = profile === "insecure-container" ? `[127.0.0.1]:${port}` : "192.0.2.2";
  await writeFile(join(state.driverStateDir, "known_hosts"), `${host} ssh-ed25519 ${blob.toString("base64")}\n`, {
    mode: 0o600,
  });
  if (profile === "insecure-container")
    await writeFile(join(state.driverStateDir, "port"), `${port}\n`, { mode: 0o600 });
  const runtimeParent = join(temp, "runtime");
  const sshRoot = join(runtimeParent, "ssh");
  const egressRoot = join(runtimeParent, "egress");
  await mkdir(runtimeParent, { mode: 0o700 });
  await chmod(runtimeParent, 0o700);
  await mkdir(sshRoot, { mode: 0o700 });
  await chmod(sshRoot, 0o700);
  await mkdir(egressRoot, { mode: 0o700 });
  await chmod(egressRoot, 0o700);
  return { temp, state, profile, control, key, blob, port, sshRoot, egressRoot };
}

function seams(
  value: Setup,
  overrides: {
    statfsType?: number;
    after?: (stage: string) => void | Promise<void>;
    directorySyncFailure?: boolean;
    throwingReadName?: string;
  } = {},
): TrustedControlSeams {
  const map = (path: string) => {
    if (path === TRUSTED_SSH_RUNTIME_ROOT) return value.sshRoot;
    if (path.startsWith(`${TRUSTED_SSH_RUNTIME_ROOT}/`))
      return join(value.sshRoot, path.slice(TRUSTED_SSH_RUNTIME_ROOT.length + 1));
    if (path === TRUSTED_EGRESS_RUNTIME_ROOT) return value.egressRoot;
    if (path.startsWith(`${TRUSTED_EGRESS_RUNTIME_ROOT}/`))
      return join(value.egressRoot, path.slice(TRUSTED_EGRESS_RUNTIME_ROOT.length + 1));
    return path;
  };
  const unmap = (path: string) => {
    if (path === value.sshRoot) return TRUSTED_SSH_RUNTIME_ROOT;
    if (path.startsWith(`${value.sshRoot}/`))
      return `${TRUSTED_SSH_RUNTIME_ROOT}/${path.slice(value.sshRoot.length + 1)}`;
    if (path === value.egressRoot) return TRUSTED_EGRESS_RUNTIME_ROOT;
    if (path.startsWith(`${value.egressRoot}/`))
      return `${TRUSTED_EGRESS_RUNTIME_ROOT}/${path.slice(value.egressRoot.length + 1)}`;
    return path;
  };
  const fs = Object.freeze({
    lstat: Object.freeze((path: string) => lstat(map(path))),
    realpath: Object.freeze(async (path: string) => unmap(await realpath(map(path)))),
    readdir: Object.freeze((path: string) => readdir(map(path))),
    statfs: Object.freeze(async (_path: string) => ({ type: overrides.statfsType ?? 0x0102_1994 })),
    open: Object.freeze(async (path: string, flags: number, mode?: number) => {
      const mapped = map(path);
      const handle = await open(mapped, flags, mode);
      const isDirectory = mapped === value.sshRoot || mapped === value.egressRoot;
      return Object.freeze({
        stat: Object.freeze(() => handle.stat()),
        read: Object.freeze(async (buffer: Buffer, offset: number, length: number, position: number) => {
          if (overrides.throwingReadName !== undefined && mapped.endsWith(overrides.throwingReadName)) {
            buffer.fill(0x41, offset, offset + Math.min(length, 8));
            throw new Error("injected read failure");
          }
          return handle.read(buffer, offset, length, position);
        }),
        writeFile: Object.freeze((bytes: Buffer) => handle.writeFile(bytes)),
        sync: Object.freeze(() =>
          overrides.directorySyncFailure && isDirectory
            ? Promise.reject(new Error("injected fsync failure"))
            : handle.sync(),
        ),
        close: Object.freeze(() => handle.close()),
      });
    }),
    unlink: Object.freeze((path: string) => unlink(map(path))),
  });
  return Object.freeze({
    platform: "linux" as const,
    uid: typeof process.geteuid === "function" ? process.geteuid() : 501,
    fs,
    ...(overrides.after === undefined ? {} : { after: Object.freeze(overrides.after) }),
  });
}

async function cleanup(value: Setup): Promise<void> {
  await rm(value.temp, { recursive: true, force: true });
}

function authority(profile: LauncherProfile) {
  return profile === "linux-kvm" ? "authoritative-local" : "functional-only";
}

test("materializes strict insecure controls at the fixed runtime path and cleans exact inode", async () => {
  const value = await setup();
  try {
    const handle = await materializeTrustedSshControls(
      value.state,
      value.profile,
      authority(value.profile),
      undefined,
      seams(value),
    );
    assert.equal(handle.endpoint, `127.0.0.1:${value.port}`);
    assert.equal(handle.username, "root");
    assert.equal(handle.hostKeySha256, expectedPin(value.blob));
    assert.equal(handle.clientKeyPath, `${TRUSTED_SSH_RUNTIME_ROOT}/launcher-${value.state.stateId}`);
    assert.deepEqual(Object.keys(handle).sort(), []);
    const snapshot = JSON.stringify(handle);
    assert.equal(snapshot?.includes(TRUSTED_SSH_RUNTIME_ROOT), false);
    assert.equal(snapshot?.includes(value.state.stateId), false);
    assert.equal(snapshot?.includes(expectedPin(value.blob)), false);
    assert.equal(snapshot?.includes("PRIVATE"), false);
    assert.equal(Object.isFrozen(handle), true);
    assert.deepEqual(await readdir(value.sshRoot), [`launcher-${value.state.stateId}`]);
    assert.deepEqual(
      await open(join(value.sshRoot, `launcher-${value.state.stateId}`), "r").then(async (file) => {
        try {
          return await file.readFile();
        } finally {
          await file.close();
        }
      }),
      value.key,
    );
    const first = handle.close();
    assert.equal(handle.close(), first);
    await first;
    assert.deepEqual(await readdir(value.sshRoot), []);
  } finally {
    await cleanup(value);
  }
});

test("uses exact fixed KVM endpoint and authority without a port fallback", async () => {
  const value = await setup("linux-kvm");
  try {
    const handle = await materializeTrustedSshControls(
      value.state,
      "linux-kvm",
      "authoritative-local",
      undefined,
      seams(value),
    );
    assert.equal(handle.endpoint, "192.0.2.2:22");
    assert.equal(handle.hostKeySha256, expectedPin(value.blob));
    await handle.close();
  } finally {
    await cleanup(value);
  }
});

test("preflights the separate fixed egress tmpfs without creating entries", async () => {
  const value = await setup();
  try {
    await preflightTrustedEgressRoot(undefined, seams(value));
    assert.deepEqual(await readdir(value.egressRoot), []);
    await assert.rejects(
      preflightTrustedEgressRoot(undefined, seams(value, { statfsType: 0x1234 })),
      /trusted controls/,
    );
    await writeFile(join(value.egressRoot, "unknown"), "x", { mode: 0o600 });
    await assert.rejects(preflightTrustedEgressRoot(undefined, seams(value)), /trusted controls/);
  } finally {
    await cleanup(value);
  }
});

test("rejects malformed profile controls with one generic redacted error", async () => {
  const cases: Array<(value: Setup) => Promise<void>> = [
    (value) => writeFile(join(value.state.driverStateDir, "port"), "0\n", { mode: 0o600 }),
    (value) => writeFile(join(value.state.driverStateDir, "port"), "65536\n", { mode: 0o600 }),
    (value) => writeFile(join(value.state.driverStateDir, "port"), "22\nextra\n", { mode: 0o600 }),
    (value) =>
      writeFile(join(value.state.driverStateDir, "known_hosts"), "localhost ssh-ed25519 AAAA\n", { mode: 0o600 }),
    async (value) => {
      const text = await open(join(value.state.driverStateDir, "known_hosts"), "r").then(async (file) => {
        try {
          return await file.readFile("utf8");
        } finally {
          await file.close();
        }
      });
      await writeFile(join(value.state.driverStateDir, "known_hosts"), text.trim(), { mode: 0o600 });
    },
  ];
  for (const mutate of cases) {
    const value = await setup();
    try {
      await mutate(value);
      const error = await materializeTrustedSshControls(
        value.state,
        value.profile,
        authority(value.profile),
        undefined,
        seams(value),
      ).then(
        () => undefined,
        (caught: unknown) => caught,
      );
      assert.equal((error as Error).message, "launcher trusted controls failed");
      assert.equal(JSON.stringify(error).includes("PRIVATE"), false);
      assert.deepEqual(await readdir(value.sshRoot), []);
    } finally {
      await cleanup(value);
    }
  }
});

test("rejects source symlinks, hardlinks, modes, extra controls, and inode replacement", async () => {
  const mutations: Array<(value: Setup) => Promise<TrustedControlSeams>> = [
    async (value) => {
      const key = join(value.control, "client_ed25519_key");
      await unlink(key);
      await symlink("client_ed25519_key.pub", key);
      return seams(value);
    },
    async (value) => {
      await link(join(value.control, "client_ed25519_key"), join(value.control, "extra-hardlink"));
      return seams(value);
    },
    async (value) => {
      await chmod(join(value.control, "client_ed25519_key"), 0o644);
      return seams(value);
    },
    async (value) => {
      await writeFile(join(value.control, "extra"), "x", { mode: 0o600 });
      return seams(value);
    },
    async (value) =>
      seams(value, {
        after: async (stage) => {
          if (stage !== "after-source-read") return;
          const key = join(value.control, "client_ed25519_key");
          const replacement = join(value.control, "replacement");
          await writeFile(replacement, value.key, { mode: 0o600 });
          await rename(replacement, key);
        },
      }),
  ];
  for (const mutate of mutations) {
    const value = await setup();
    try {
      await assert.rejects(
        mutate(value).then((trusted) =>
          materializeTrustedSshControls(value.state, value.profile, authority(value.profile), undefined, trusted),
        ),
        /trusted controls/,
      );
      assert.deepEqual(await readdir(value.sshRoot), []);
    } finally {
      await cleanup(value);
    }
  }
});

test("rejects profile, authority, phase, macOS, abort, tmpfs mode, and fsync failures", async () => {
  const value = await setup();
  try {
    await assert.rejects(
      materializeTrustedSshControls(value.state, "linux-kvm", "authoritative-local", undefined, seams(value)),
      /trusted controls/,
    );
    await assert.rejects(
      materializeTrustedSshControls(value.state, value.profile, "authoritative-local", undefined, seams(value)),
      /trusted controls/,
    );
    await assert.rejects(
      materializeTrustedSshControls(value.state, "macos-vm", "functional-only", undefined, seams(value)),
      /trusted controls/,
    );
    const controller = new AbortController();
    const aborting = seams(value, {
      after: (stage) => {
        if (stage === "after-preflight") controller.abort();
      },
    });
    await assert.rejects(
      materializeTrustedSshControls(value.state, value.profile, authority(value.profile), controller.signal, aborting),
      /trusted controls/,
    );
    await chmod(value.sshRoot, 0o755);
    await assert.rejects(
      materializeTrustedSshControls(value.state, value.profile, authority(value.profile), undefined, seams(value)),
      /trusted controls/,
    );
    await chmod(value.sshRoot, 0o700);
    await assert.rejects(
      materializeTrustedSshControls(
        value.state,
        value.profile,
        authority(value.profile),
        undefined,
        seams(value, { directorySyncFailure: true }),
      ),
      /trusted controls/,
    );
  } finally {
    await cleanup(value);
  }
});

test("rejects missing mutated or replaced driver ownership sentinels", async () => {
  const mutations: Array<(value: Setup) => Promise<void>> = [
    (value) => unlink(join(value.state.driverStateDir, ".cogs-insecure-owner")),
    (value) => writeFile(join(value.state.driverStateDir, ".cogs-insecure-owner"), "wrong\n", { mode: 0o600 }),
    (value) => chmod(join(value.state.driverStateDir, ".cogs-insecure-owner"), 0o644),
    async (value) => {
      const sentinel = join(value.state.driverStateDir, ".cogs-insecure-owner");
      const replacement = join(value.state.driverStateDir, "sentinel-replacement");
      await writeFile(replacement, "wrong\n", { mode: 0o600 });
      await rename(replacement, sentinel);
    },
  ];
  for (const mutate of mutations) {
    const value = await setup();
    try {
      await mutate(value);
      await assert.rejects(
        materializeTrustedSshControls(value.state, value.profile, authority(value.profile), undefined, seams(value)),
        /trusted controls/,
      );
      assert.deepEqual(await readdir(value.sshRoot), []);
    } finally {
      await cleanup(value);
    }
  }

  const kvm = await setup("linux-kvm");
  try {
    await writeFile(join(kvm.state.driverStateDir, ".cogs-linux-kvm-v1"), "not-empty", { mode: 0o600 });
    await assert.rejects(
      materializeTrustedSshControls(kvm.state, "linux-kvm", "authoritative-local", undefined, seams(kvm)),
      /trusted controls/,
    );
  } finally {
    await cleanup(kvm);
  }
});

test("rejects control and runtime path replacement races and redacts failed private reads", async () => {
  for (const target of ["port", "known_hosts"] as const) {
    const value = await setup();
    let reads = 0;
    try {
      await assert.rejects(
        materializeTrustedSshControls(
          value.state,
          value.profile,
          authority(value.profile),
          undefined,
          seams(value, {
            after: async (stage) => {
              if (stage !== "after-control-read") return;
              reads += 1;
              if ((target === "port" && reads === 2) || (target === "known_hosts" && reads === 3)) {
                const path = join(value.state.driverStateDir, target);
                const replacement = join(value.state.driverStateDir, `${target}.replacement`);
                await writeFile(replacement, target === "port" ? `${value.port}\n` : await readText(path), {
                  mode: 0o600,
                });
                await rename(replacement, path);
              }
            },
          }),
        ),
        /trusted controls/,
      );
      assert.deepEqual(await readdir(value.sshRoot), []);
    } finally {
      await cleanup(value);
    }
  }

  const destination = await setup();
  try {
    await assert.rejects(
      materializeTrustedSshControls(
        destination.state,
        destination.profile,
        authority(destination.profile),
        undefined,
        seams(destination, {
          after: async (stage) => {
            if (stage !== "after-materialize") return;
            const runtime = join(destination.sshRoot, `launcher-${destination.state.stateId}`);
            const replacement = join(destination.sshRoot, "replacement");
            await writeFile(replacement, destination.key, { mode: 0o600 });
            await rename(replacement, runtime);
          },
        }),
      ),
      /trusted controls/,
    );
  } finally {
    await cleanup(destination);
  }

  const unknownRuntime = await setup();
  try {
    await assert.rejects(
      materializeTrustedSshControls(
        unknownRuntime.state,
        unknownRuntime.profile,
        authority(unknownRuntime.profile),
        undefined,
        seams(unknownRuntime, {
          after: async (stage) => {
            if (stage !== "after-materialize") return;
            await writeFile(join(unknownRuntime.sshRoot, "unknown"), "x", { mode: 0o600 });
          },
        }),
      ),
      /trusted controls/,
    );
    assert.equal((await readdir(unknownRuntime.sshRoot)).includes("unknown"), true);
  } finally {
    await cleanup(unknownRuntime);
  }

  const failedRead = await setup();
  try {
    const error = await materializeTrustedSshControls(
      failedRead.state,
      failedRead.profile,
      authority(failedRead.profile),
      undefined,
      seams(failedRead, { throwingReadName: "client_ed25519_key" }),
    ).catch((caught: unknown) => caught);
    assert.equal((error as Error).message, "launcher trusted controls failed");
    assert.equal(JSON.stringify(error).includes("PRIVATE"), false);
    assert.deepEqual(await readdir(failedRead.sshRoot), []);
  } finally {
    await cleanup(failedRead);
  }
});

async function readText(path: string): Promise<string> {
  const file = await open(path, "r");
  try {
    return await file.readFile("utf8");
  } finally {
    await file.close();
  }
}

test("cleanup rejects replacement and unknown entries without unlinking them", async () => {
  for (const mutation of ["replacement", "unknown"] as const) {
    const value = await setup();
    try {
      const handle = await materializeTrustedSshControls(
        value.state,
        value.profile,
        authority(value.profile),
        undefined,
        seams(value),
      );
      const runtimeKey = join(value.sshRoot, `launcher-${value.state.stateId}`);
      if (mutation === "replacement") {
        const replacement = join(value.sshRoot, "replacement");
        await writeFile(replacement, "not-the-key", { mode: 0o600 });
        await rename(replacement, runtimeKey);
      } else await writeFile(join(value.sshRoot, "unknown"), "x", { mode: 0o600 });
      await assert.rejects(handle.close(), /trusted controls/);
      assert.equal((await readdir(value.sshRoot)).length > 0, true);
    } finally {
      await cleanup(value);
    }
  }
});
