import { createServer, Socket } from "node:net";

export type KvmRelayOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;

const abortSignalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get as
  | ((this: AbortSignal) => boolean)
  | undefined;
const eventAdd = EventTarget.prototype.addEventListener;
const eventRemove = EventTarget.prototype.removeEventListener;

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

  async start(options?: KvmRelayOptions): Promise<void> {
    try {
      const cooperative = cooperativeOptions(options);
      checkCooperative(cooperative);
      if (this.#started || this.#closed || this.#poisoned) fail();
      let cancelled = false;
      let settleClosed: (() => void) | undefined;
      const relay = () => {
        cancelled = true;
        this.#closed = true;
        if (this.#server.listening) this.#server.close(() => settleClosed?.());
      };
      const timer = setTimeout(relay, remainingMs(cooperative, 2000));
      if (cooperative.signal) eventAdd.call(cooperative.signal, "abort", relay, { once: true });
      try {
        await new Promise<void>((resolve, reject) => {
          settleClosed = resolve;
          const onError = () => reject(fail());
          this.#server.once("error", onError);
          this.#server.listen({ host: this.#host, port: this.#requestedPort }, () => {
            this.#server.off("error", onError);
            const a = this.#server.address();
            const port = typeof a === "object" && a ? a.port : 0;
            if (!Number.isInteger(port) || port < 1 || port > 65535) reject(fail());
            else if (cancelled || this.#closed) this.#server.close(() => resolve());
            else {
              this.#port = port;
              this.#started = true;
              resolve();
            }
          });
        });
      } finally {
        clearTimeout(timer);
        if (cooperative.signal) eventRemove.call(cooperative.signal, "abort", relay);
      }
      if (cancelled || aborted(cooperative.signal) || this.#closed || this.#poisoned) {
        await this.closeServer();
        throw fail();
      }
    } catch {
      this.#closed = true;
      this.poison();
      await this.closeServer();
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

  async switchTo(port: number, options?: KvmRelayOptions): Promise<void> {
    try {
      const cooperative = cooperativeOptions(options);
      checkCooperative(cooperative);
      this.open();
      const target = validPort(port);
      if (!this.#registered.has(target)) fail();
      await this.destroyAll();
      checkCooperative(cooperative);
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

  close(options?: KvmRelayOptions): Promise<void> {
    cooperativeOptions(options);
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
    if (!this.#server.listening) return;
    await new Promise<void>((resolve) => this.#server.close(() => resolve()));
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
async function closedPort(host: string, port: number): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  const s = new Socket();
  try {
    await new Promise<void>((resolve, reject) => {
      const done = (ok: boolean) => {
        if (timer) clearTimeout(timer);
        s.destroy();
        ok ? resolve() : reject(fail());
      };
      timer = setTimeout(() => done(false), 500);
      s.once("connect", () => done(false));
      s.once("error", () => done(true));
      s.connect(port, host);
    });
  } finally {
    if (timer) clearTimeout(timer);
    s.destroy();
  }
}

function cooperativeOptions(options?: KvmRelayOptions): KvmRelayOptions {
  if (options === undefined) return Object.freeze({});
  if (!options || typeof options !== "object" || Object.getPrototypeOf(options) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(options);
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== "string" || !["deadlineAt", "signal"].includes(key))) fail();
  for (const descriptor of Object.values(descriptors)) {
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail();
  }
  const signal = descriptors.signal?.value;
  const deadlineAt = descriptors.deadlineAt?.value;
  if (signal !== undefined && !(signal instanceof AbortSignal)) fail();
  if (deadlineAt !== undefined && (!Number.isSafeInteger(deadlineAt) || deadlineAt > Date.now() + 60_000)) fail();
  return Object.freeze({
    ...(signal === undefined ? {} : { signal }),
    ...(deadlineAt === undefined ? {} : { deadlineAt }),
  });
}

function checkCooperative(options: KvmRelayOptions): void {
  if (aborted(options.signal) || (options.deadlineAt !== undefined && Date.now() >= options.deadlineAt)) fail();
}
function remainingMs(options: KvmRelayOptions, cap: number): number {
  const remaining = options.deadlineAt === undefined ? cap : Math.min(cap, options.deadlineAt - Date.now());
  if (!Number.isSafeInteger(remaining) || remaining < 1) fail();
  return remaining;
}
function aborted(signal: AbortSignal | undefined): boolean {
  if (!signal) return false;
  try {
    return abortSignalAborted?.call(signal) === true;
  } catch {
    return true;
  }
}
function fail(): never {
  throw new Error("launcher relay failed");
}
