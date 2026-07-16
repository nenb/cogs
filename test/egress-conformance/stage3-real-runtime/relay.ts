import { createServer, Socket } from "node:net";

export type Stage3RelaySnapshot = Readonly<{
  bindHost: string;
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

export class Stage3RuntimeRelay {
  readonly #bindHost: string;
  readonly #bindPort: number;
  readonly #registered = new Set<number>();
  readonly #sockets = new Set<Socket>();
  readonly #server = createServer((socket) => this.accept(socket));
  readonly #maxActiveSockets: number;
  #activeTarget: number | null = null;
  #acceptedConnections = 0;
  #deniedConnections = 0;
  #switchedTargets = 0;
  #closed = false;
  #started = false;
  #poisoned = false;

  public constructor(bindHost: string, bindPort: number, maxActiveSockets = 32) {
    if (!/^(?:127\.0\.0\.1|192\.0\.2\.1)$/.test(bindHost)) throw new Error("bad relay bind");
    if (!Number.isInteger(bindPort) || bindPort < 1 || bindPort > 65535) throw new Error("bad relay bind");
    if (!Number.isInteger(maxActiveSockets) || maxActiveSockets < 2 || maxActiveSockets > 128)
      throw new Error("bad relay bounds");
    this.#bindHost = bindHost;
    this.#bindPort = bindPort;
    this.#maxActiveSockets = maxActiveSockets;
    this.#server.on("error", () => {
      this.#poisoned = true;
      this.clearAfterPoison();
    });
  }

  public async start(): Promise<void> {
    if (this.#closed || this.#started) throw new Error("bad relay state");
    await new Promise<void>((resolve, reject) => {
      const fail = (error: Error) => reject(error);
      this.#server.once("error", fail);
      this.#server.listen({ host: this.#bindHost, port: this.#bindPort }, () => {
        this.#server.off("error", fail);
        this.#started = true;
        resolve();
      });
    });
  }

  public registerTarget(port: number): void {
    this.assertOpen();
    this.#registered.add(validTarget(port));
  }

  public switchTo(port: number): void {
    this.assertOpen();
    const target = validTarget(port);
    if (!this.#registered.has(target)) throw new Error("unregistered relay target");
    this.destroySockets();
    if (this.#activeTarget !== target) this.#switchedTargets++;
    this.#activeTarget = target;
  }

  public clear(): void {
    this.assertOpen();
    this.destroySockets();
    this.#activeTarget = null;
  }

  public snapshot(): Stage3RelaySnapshot {
    return Object.freeze({
      bindHost: this.#bindHost,
      bindPort: this.#bindPort,
      activeTarget: this.#activeTarget,
      registeredTargets: Object.freeze([...this.#registered].sort((left, right) => left - right)),
      acceptedConnections: this.#acceptedConnections,
      deniedConnections: this.#deniedConnections,
      switchedTargets: this.#switchedTargets,
      activeSockets: this.#sockets.size,
      maxActiveSockets: this.#maxActiveSockets,
      ready: this.#started && !this.#closed && !this.#poisoned,
      poisoned: this.#poisoned,
      closed: this.#closed,
    });
  }

  public async close(): Promise<Stage3RelaySnapshot> {
    if (this.#closed) return this.snapshot();
    const wasStarted = this.#started;
    this.#closed = true;
    this.destroySockets();
    await new Promise<void>((resolve, reject) => {
      this.#server.close((error) => (error === undefined ? resolve() : reject(error)));
    }).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "ERR_SERVER_NOT_RUNNING") throw error;
    });
    if (wasStarted) await assertPortClosed(this.#bindHost, this.#bindPort);
    return this.snapshot();
  }

  private accept(socket: Socket): void {
    socket.setTimeout(15_000, () => socket.destroy());
    this.#sockets.add(socket);
    socket.once("close", () => this.#sockets.delete(socket));
    const target = this.#activeTarget;
    if (this.#closed || this.#poisoned || target === null || this.#sockets.size + 1 > this.#maxActiveSockets) {
      this.#deniedConnections++;
      socket.destroy();
      return;
    }
    this.#acceptedConnections++;
    const upstream = new Socket();
    upstream.setTimeout(15_000, () => upstream.destroy());
    this.#sockets.add(upstream);
    upstream.once("close", () => this.#sockets.delete(upstream));
    upstream.once("error", () => socket.destroy());
    socket.once("error", () => upstream.destroy());
    upstream.connect(target, "127.0.0.1", () => {
      if (this.#closed || this.#activeTarget !== target) {
        socket.destroy();
        upstream.destroy();
        return;
      }
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
  }

  private destroySockets(): void {
    for (const socket of this.#sockets) socket.destroy();
    this.#sockets.clear();
  }

  private assertOpen(): void {
    if (this.#closed || !this.#started || this.#poisoned) throw new Error("bad relay state");
  }

  private clearAfterPoison(): void {
    this.destroySockets();
    this.#activeTarget = null;
  }
}

export function createKvmStage3RuntimeRelay(): Stage3RuntimeRelay {
  return new Stage3RuntimeRelay("192.0.2.1", 18080);
}

function validTarget(port: number): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("bad relay target");
  return port;
}

async function assertPortClosed(host: string, port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const socket = new Socket();
    socket.setTimeout(500, () => {
      socket.destroy();
      reject(new Error("relay close verification timed out"));
    });
    socket.once("connect", () => {
      socket.destroy();
      reject(new Error("relay listener remained after close"));
    });
    socket.once("error", () => resolve());
    socket.connect(port, host);
  });
}
