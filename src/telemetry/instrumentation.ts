import type { CogsWorkerTelemetrySink } from "./worker-telemetry.ts";
import { validateCogsWorkerTelemetrySink } from "./worker-telemetry.ts";

export type CogsTelemetry = CogsWorkerTelemetrySink | undefined;
export type TelemetryClock = Readonly<{ now: () => number }>;

export class TelemetryHealthCursor {
  #snapshot: Readonly<{ queued: number; exported: number; dropped: number; failed: number; lag_ms: number }> =
    Object.freeze({
      queued: 0,
      exported: 0,
      dropped: 0,
      failed: 0,
      lag_ms: 0,
    });
  read(): Readonly<{ queued: number; exported: number; dropped: number; failed: number; lag_ms: number }> {
    return this.#snapshot;
  }
  update(
    snapshot: Readonly<{ queued: number; exported: number; dropped: number; failed: number; lag_ms: number }>,
  ): void {
    this.#snapshot = snapshot;
  }
}

export function captureTelemetry(value: CogsTelemetry): CogsTelemetry {
  validateCogsWorkerTelemetrySink(value);
  return value;
}

export function telemetryStart(clock?: TelemetryClock): number {
  return safeNow(clock);
}

export function telemetryDuration(clock: TelemetryClock | undefined, start: number): number {
  const now = safeNow(clock);
  if (!Number.isSafeInteger(start) || start < 0 || now < start) return 0;
  return Math.min(86_400_000, now - start);
}

export function emitSpan(
  sink: CogsTelemetry,
  name: string,
  attributes: Readonly<Record<string, string | number | boolean>> = Object.freeze({}),
): void {
  try {
    if (sink?.ready === true) sink.span(Object.freeze({ name, attributes: Object.freeze({ ...attributes }) }));
  } catch {}
}

export function emitMetric(
  sink: CogsTelemetry,
  name: string,
  value: number,
  attributes: Readonly<Record<string, string | number | boolean>> = Object.freeze({}),
): void {
  try {
    if (sink?.ready === true && Number.isSafeInteger(value) && value >= 0)
      sink.metric(Object.freeze({ name, attributes: Object.freeze({ ...attributes, value }) }));
  } catch {}
}

export function emitTelemetryHealth(sink: CogsTelemetry, cursor: TelemetryHealthCursor | undefined): void {
  try {
    if (sink?.ready !== true || cursor === undefined) return;
    const snap = safeTelemetrySnapshot(sink.snapshot());
    if (snap === undefined) return;
    const previous = cursor.read();
    emitMetric(sink, "otlp.queue.depth", snap.queued);
    emitMetric(sink, "otlp.export.lag", snap.lag_ms);
    emitMetric(sink, "otlp.dropped", delta(snap.dropped, previous.dropped));
    emitMetric(sink, "otlp.failed", delta(snap.failed, previous.failed));
    cursor.update(Object.freeze(snap));
  } catch {}
}

export function byteBucket(value: unknown): "0" | "1" | "2_4" | "5_16" | "17_64" | "65_256" | "257_1024" | "gt_1024" {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) return "0";
  const n = value as number;
  if (n === 1) return "1";
  if (n <= 4) return "2_4";
  if (n <= 16) return "5_16";
  if (n <= 64) return "17_64";
  if (n <= 256) return "65_256";
  if (n <= 1024) return "257_1024";
  return "gt_1024";
}

function safeTelemetrySnapshot(
  value: unknown,
): Readonly<{ queued: number; exported: number; dropped: number; failed: number; lag_ms: number }> | undefined {
  try {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = ["queued", "exported", "dropped", "failed", "lag_ms"] as const;
    const out: { queued: number; exported: number; dropped: number; failed: number; lag_ms: number } = {
      queued: 0,
      exported: 0,
      dropped: 0,
      failed: 0,
      lag_ms: 0,
    };
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !Number.isSafeInteger(descriptor.value) ||
        descriptor.value < 0
      )
        return undefined;
      out[key] = descriptor.value;
    }
    return Object.freeze(out);
  } catch {
    return undefined;
  }
}

function delta(after: number, before: number): number {
  return after >= before ? after - before : 0;
}

function safeNow(clock: TelemetryClock | undefined): number {
  try {
    const value = clock?.now() ?? Date.now();
    return Number.isSafeInteger(value) && value >= 0 ? value : 0;
  } catch {
    return 0;
  }
}
