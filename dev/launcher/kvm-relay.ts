import { createServer, Socket } from "node:net";
import type { SecretHolder } from "./openbao.ts";

export type KvmRelayOptions = Readonly<{ signal?: AbortSignal; deadlineAt?: number }>;

const abortSignalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted")?.get as
  | ((this: AbortSignal) => boolean)
  | undefined;
const eventAdd = EventTarget.prototype.addEventListener;
const eventRemove = EventTarget.prototype.removeEventListener;
const proxySentinel = Symbol("cogs.kvm.proxy");

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
  #proxyCapability: SecretHolder | undefined;
  #closePromise: Promise<void> | undefined;

  private constructor(
    profile: "linux-kvm" | "loopback-functional",
    host: "192.0.2.1" | "127.0.0.1",
    port: number,
    max = 32,
  ) {
    if (profile === "linux-kvm" && !((host === "192.0.2.1" && port === 18080) || host === "127.0.0.1")) fail();
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
  static linuxKvmTestLoopback(port = 0): KvmRelay {
    return new KvmRelay("linux-kvm", "127.0.0.1", port);
  }

  configureProxyCapability(holder: SecretHolder): void {
    try {
      if (
        this.#profile !== "linux-kvm" ||
        this.#started ||
        this.#closed ||
        this.#poisoned ||
        this.#proxyCapability !== undefined
      )
        fail();
      requireSecretHolder(holder);
      withSecretOnce(holder, () => undefined);
      this.#proxyCapability = holder;
      if (!this.advanceGeneration()) fail();
    } catch {
      throw fail();
    }
  }

  async start(options?: KvmRelayOptions): Promise<void> {
    try {
      const cooperative = cooperativeOptions(options);
      checkCooperative(cooperative);
      if (this.#started || this.#closed || this.#poisoned || (this.#profile === "linux-kvm" && !this.#proxyCapability))
        fail();
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
    this.#proxyCapability = undefined;
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
      const holder = this.#proxyCapability;
      if (holder === undefined) {
        socket.pipe(upstream);
        upstream.pipe(socket);
        return;
      }
      void this.proxyHandshake(socket, upstream, holder, target, gen).catch(() => this.poison());
    });
  }

  private async proxyHandshake(
    socket: Socket,
    upstream: Socket,
    holder: SecretHolder,
    target: number,
    gen: number,
  ): Promise<void> {
    const header = await readProxyHeader(socket, () => this.poison());
    if (this.#closed || this.#poisoned || this.#target !== target || this.#generation !== gen) fail();
    let injected: Buffer | undefined;
    withSecretOnce(holder, (secret) => {
      injected = injectProxyAuthorization(header, secret);
    });
    if (!injected || this.#closed || this.#poisoned || this.#target !== target || this.#generation !== gen) fail();
    try {
      await writeAll(upstream, injected);
    } finally {
      injected.fill(0);
      injected = undefined;
    }
    if (this.#closed || this.#poisoned || this.#target !== target || this.#generation !== gen) fail();
    socket.pipe(upstream);
    upstream.pipe(socket);
    socket.resume();
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
    this.#proxyCapability = undefined;
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
export function createLinuxKvmRelayForTests(port = 0): KvmRelay {
  return KvmRelay.linuxKvmTestLoopback(port);
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
function readProxyHeader(socket: Socket, onTimeout: () => void): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let buffered = Buffer.alloc(0);
    const timer = setTimeout(() => {
      onTimeout();
      reject(new Error("launcher relay failed"));
    }, 1000);
    let settled = false;
    const done = (ok: boolean, value?: Buffer) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("close", onClose);
      socket.off("error", onClose);
      if (ok) socket.pause();
      else socket.destroy();
      ok ? resolve(value as Buffer) : reject(new Error("launcher relay failed"));
    };
    const onClose = () => done(false);
    const onData = (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk], buffered.length + chunk.length);
      if (buffered.length > 8192) return done(false);
      const end = buffered.indexOf("\r\n\r\n");
      if (end < 0) return;
      const candidate = buffered.subarray(0, end + 4).toString("latin1");
      if (/(^|[^\r])\n/u.test(candidate)) return done(false);
      done(true, buffered);
    };
    socket.on("data", onData);
    socket.once("close", onClose);
    socket.once("error", onClose);
  });
}

function injectProxyAuthorization(raw: Buffer, secret: string): Buffer {
  const end = raw.indexOf("\r\n\r\n");
  if (end < 0 || end > 8192) fail();
  const head = raw.subarray(0, end).toString("latin1");
  if (hasUnsafeHeaderControls(head)) fail();
  const rest = raw.subarray(end + 4);
  const lines = head.split("\r\n");
  if (lines.length < 2 || !/^CONNECT localhost:[1-9][0-9]{0,4} HTTP\/1\.1$/u.test(lines[0] ?? "")) fail();
  const port = Number((lines[0] as string).split(":")[1]?.split(" ")[0]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail();
  let host = 0;
  const seen = new Set<string>();
  for (const line of lines.slice(1)) {
    if (line === "" || /^[ \t]/u.test(line) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+: [\x20-\x7e]*$/u.test(line)) fail();
    const name = line.slice(0, line.indexOf(":")).toLowerCase();
    if (seen.has(name)) fail();
    seen.add(name);
    if (name === "proxy-authorization") fail();
    if (name === "host") host++;
  }
  if (host !== 1 || !lines.some((line) => line.toLowerCase() === `host: localhost:${port}`)) fail();
  return Buffer.concat([
    Buffer.from(`${lines.join("\r\n")}\r\nProxy-Authorization: Bearer ${secret}\r\n\r\n`, "latin1"),
    rest,
  ]);
}

function hasUnsafeHeaderControls(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 10 && (i === 0 || value.charCodeAt(i - 1) !== 13)) return true;
    if (c === 13 && value.charCodeAt(i + 1) !== 10) return true;
    if ((c < 32 && c !== 9 && c !== 10 && c !== 13) || c === 127) return true;
  }
  return false;
}

function requireSecretHolder(holder: unknown): asserts holder is SecretHolder {
  if (!holder || typeof holder !== "object" || !Object.isFrozen(holder)) fail();
  const d = Object.getOwnPropertyDescriptors(holder);
  if (Reflect.ownKeys(d).some((k) => typeof k !== "string" || !["withSecret", "dispose"].includes(k))) fail();
  if (typeof d.withSecret?.value !== "function" || !d.withSecret.enumerable) fail();
  if (typeof d.dispose?.value !== "function" || !d.dispose.enumerable) fail();
}

function validateProxySecret(secret: string): string {
  if (typeof secret !== "string" || !/^[A-Za-z0-9_-]{22,256}$/u.test(secret)) fail();
  return secret;
}

function withSecretOnce(holder: SecretHolder, op: (secret: string) => void): void {
  let calls = 0;
  const result = holder.withSecret((secret) => {
    calls++;
    op(validateProxySecret(secret));
    return proxySentinel;
  });
  if (calls !== 1 || result !== proxySentinel) fail();
}

function writeAll(socket: Socket, buffer: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (error?: Error | null) => {
      if (settled) return;
      settled = true;
      socket.off("error", onError);
      error ? reject(new Error("launcher relay failed")) : resolve();
    };
    const onError = () => done(new Error("launcher relay failed"));
    socket.once("error", onError);
    socket.write(buffer, (error) => done(error));
  });
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
