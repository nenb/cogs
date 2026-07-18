import { createServer, Socket } from "node:net";

export type KvmRelaySnapshot = Readonly<{
  profile: "linux-kvm" | "loopback-functional";
  bindHost: "192.0.2.1" | "127.0.0.1";
  bindPort: number;
  activeTarget: number | null;
  registeredTargets: readonly number[];
  acceptedConnections: number;
  deniedConnections: number;
  switchedTargets: number;
  activeSockets: number;
  maxActiveSockets: number;
  ready: boolean;
  poisoned: boolean;
  closed: boolean;
}>;

export class KvmRelay {
  readonly #profile: "linux-kvm" | "loopback-functional";
  readonly #host: "192.0.2.1" | "127.0.0.1";
  readonly #requestedPort: number;
  readonly #max: number;
  readonly #registered = new Set<number>();
  readonly #sockets = new Set<Socket>();
  readonly #server = createServer((socket) => this.accept(socket));
  #port = 0;
  #target: number | null = null;
  #accepted = 0;
  #denied = 0;
  #switched = 0;
  #started = false;
  #closed = false;
  #poisoned = false;
  #generation = 0;
  #closePromise: Promise<void> | undefined;

  private constructor(
    profile: "linux-kvm" | "loopback-functional",
    host: "192.0.2.1" | "127.0.0.1",
    port: number,
    max = 32,
  ) {
    if (profile === "linux-kvm" && (host !== "192.0.2.1" || port !== 18080)) fail();
    if (profile === "loopback-functional" && host !== "127.0.0.1") fail();
    if (!Number.isInteger(port) || port < 0 || port > 65535 || !Number.isInteger(max) || max < 2 || max > 128) fail();
    this.#profile = profile;
    this.#host = host;
    this.#requestedPort = port;
    this.#max = max;
    this.#server.on("error", () => this.poison());
  }

  static linuxKvm(): KvmRelay {
    return new KvmRelay("linux-kvm", "192.0.2.1", 18080);
  }
  static loopbackFunctional(port = 0, maxActiveSockets = 32): KvmRelay {
    return new KvmRelay("loopback-functional", "127.0.0.1", port, maxActiveSockets);
  }

  async start(): Promise<void> {
    try {
      if (this.#started || this.#closed || this.#poisoned) fail();
      await bound(
        new Promise<void>((resolve, reject) => {
          const onError = () => reject(fail());
          this.#server.once("error", onError);
          this.#server.listen({ host: this.#host, port: this.#requestedPort }, () => {
            this.#server.off("error", onError);
            if (this.#closed || this.#poisoned) {
              this.#server.close(() => undefined);
              reject(fail());
              return;
            }
            const a = this.#server.address();
            const port = typeof a === "object" && a ? a.port : 0;
            if (!Number.isInteger(port) || port < 1 || port > 65535) reject(fail());
            else {
              this.#port = port;
              this.#started = true;
              resolve();
            }
          });
        }),
        2000,
      );
    } catch {
      this.#closed = true;
      this.poison();
      await this.closeServer().catch(() => undefined);
      throw fail();
    }
  }

  registerTarget(port: number): void {
    try {
      this.open();
      const target = validPort(port);
      if (this.#registered.size >= 16 && !this.#registered.has(target)) fail();
      this.#registered.add(target);
    } catch {
      throw fail();
    }
  }

  async switchTo(port: number): Promise<void> {
    try {
      this.open();
      const target = validPort(port);
      if (!this.#registered.has(target)) fail();
      await this.destroyAll();
      if (this.#target !== target && !this.count("switched")) fail();
      this.#target = target;
      if (!this.advanceGeneration()) fail();
    } catch {
      throw fail();
    }
  }

  async clear(): Promise<void> {
    try {
      this.open();
      this.#target = null;
      if (!this.advanceGeneration()) fail();
      await this.destroyAll();
    } catch {
      throw fail();
    }
  }

  snapshot(): KvmRelaySnapshot {
    return Object.freeze({
      profile: this.#profile,
      bindHost: this.#host,
      bindPort: this.#port || this.#requestedPort,
      activeTarget: this.#target,
      registeredTargets: Object.freeze([...this.#registered].sort((a, b) => a - b)),
      acceptedConnections: this.#accepted,
      deniedConnections: this.#denied,
      switchedTargets: this.#switched,
      activeSockets: this.#sockets.size,
      maxActiveSockets: this.#max,
      ready: this.#started && !this.#closed && !this.#poisoned,
      poisoned: this.#poisoned,
      closed: this.#closed,
    });
  }

  close(): Promise<void> {
    if (!this.#closePromise)
      this.#closePromise = this.closeInner().catch(() => {
        throw fail();
      });
    return this.#closePromise;
  }

  private async closeInner(): Promise<void> {
    const started = this.#started,
      port = this.#port;
    this.#closed = true;
    this.#target = null;
    this.#registered.clear();
    this.#generation =
      Number.isSafeInteger(this.#generation) && this.#generation < Number.MAX_SAFE_INTEGER
        ? this.#generation + 1
        : Number.MAX_SAFE_INTEGER;
    await this.destroyAll();
    await this.closeServer();
    if (started) await closedPort(this.#host, port);
    if (this.#sockets.size !== 0 || this.#target !== null || this.#registered.size !== 0) fail();
  }

  private accept(socket: Socket): void {
    const target = this.#target,
      gen = this.#generation;
    if (this.#closed || this.#poisoned || target === null || this.#sockets.size + 2 > this.#max) {
      this.count("denied");
      socket.destroy();
      return;
    }
    if (!this.count("accepted")) {
      socket.destroy();
      return;
    }
    this.track(socket);
    socket.setTimeout(5000, () => this.poison());
    const upstream = new Socket();
    this.track(upstream);
    upstream.setTimeout(5000, () => this.poison());
    const abort = () => this.poison();
    socket.once("error", abort);
    upstream.once("error", abort);
    upstream.connect(target, "127.0.0.1", () => {
      if (this.#closed || this.#poisoned || this.#target !== target || this.#generation !== gen) {
        socket.destroy();
        upstream.destroy();
        return;
      }
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
  }

  private track(socket: Socket): void {
    this.#sockets.add(socket);
    socket.once("close", () => this.#sockets.delete(socket));
  }
  private open(): void {
    if (!this.#started || this.#closed || this.#poisoned) fail();
  }
  private poison(): void {
    this.#poisoned = true;
    this.#target = null;
    this.#generation =
      Number.isSafeInteger(this.#generation) && this.#generation < Number.MAX_SAFE_INTEGER
        ? this.#generation + 1
        : Number.MAX_SAFE_INTEGER;
    for (const s of this.#sockets) s.destroy();
  }
  private count(field: "accepted" | "denied" | "switched"): boolean {
    const current = field === "accepted" ? this.#accepted : field === "denied" ? this.#denied : this.#switched;
    if (!Number.isSafeInteger(current) || current >= Number.MAX_SAFE_INTEGER) {
      if (field === "accepted") this.#accepted = Number.MAX_SAFE_INTEGER;
      else if (field === "denied") this.#denied = Number.MAX_SAFE_INTEGER;
      else this.#switched = Number.MAX_SAFE_INTEGER;
      this.poison();
      return false;
    }
    if (field === "accepted") this.#accepted = current + 1;
    else if (field === "denied") this.#denied = current + 1;
    else this.#switched = current + 1;
    return true;
  }
  private advanceGeneration(): boolean {
    if (!Number.isSafeInteger(this.#generation) || this.#generation >= Number.MAX_SAFE_INTEGER) {
      this.#generation = Number.MAX_SAFE_INTEGER;
      this.poison();
      return false;
    }
    this.#generation++;
    return true;
  }
  private async destroyAll(): Promise<void> {
    for (const s of this.#sockets) s.destroy();
    const end = Date.now() + 500;
    while (this.#sockets.size !== 0 && Date.now() < end) await new Promise((r) => setTimeout(r, 10));
    if (this.#sockets.size !== 0) fail();
  }
  private async closeServer(): Promise<void> {
    await bound(new Promise<void>((resolve) => this.#server.close(() => resolve())), 2000);
  }
}

export function createLinuxKvmRelay(): KvmRelay {
  return KvmRelay.linuxKvm();
}
export function createLoopbackFunctionalRelay(port = 0, maxActiveSockets = 32): KvmRelay {
  return KvmRelay.loopbackFunctional(port, maxActiveSockets);
}

function validPort(port: number): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail();
  return port;
}
async function bound<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([p, new Promise<never>((_, reject) => (t = setTimeout(() => reject(fail()), ms)))]);
  } finally {
    if (t) clearTimeout(t);
  }
}
async function closedPort(host: string, port: number): Promise<void> {
  await bound(
    new Promise<void>((resolve, reject) => {
      const s = new Socket();
      s.once("connect", () => {
        s.destroy();
        reject(fail());
      });
      s.once("error", () => resolve());
      s.connect(port, host);
    }),
    500,
  );
}
function fail(): never {
  throw new Error("launcher relay failed");
}
