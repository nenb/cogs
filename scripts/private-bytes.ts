import { types as utilTypes } from "node:util";

export type PrivateByteCapture = Readonly<{
  bytes: Uint8Array | null;
  bounded: boolean;
}>;

type IntrinsicGetter = (this: unknown) => unknown;

function requiredGetter(prototype: object, key: string): IntrinsicGetter {
  const getter = Object.getOwnPropertyDescriptor(prototype, key)?.get;
  if (getter === undefined) throw new TypeError(`missing intrinsic getter: ${key}`);
  return getter;
}

function optionalGetter(prototype: object, key: string): IntrinsicGetter | undefined {
  return Object.getOwnPropertyDescriptor(prototype, key)?.get;
}

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayByteLength = requiredGetter(typedArrayPrototype, "byteLength");
const typedArrayBuffer = requiredGetter(typedArrayPrototype, "buffer");
const arrayBufferByteLength = requiredGetter(ArrayBuffer.prototype, "byteLength");
const arrayBufferResizable = optionalGetter(ArrayBuffer.prototype, "resizable");
const arrayBufferDetached = optionalGetter(ArrayBuffer.prototype, "detached");
const IntrinsicDataView = DataView;
const sharedArrayBufferByteLength =
  typeof SharedArrayBuffer === "undefined" ? undefined : requiredGetter(SharedArrayBuffer.prototype, "byteLength");
const typedArraySet = Uint8Array.prototype.set;

/**
 * Copies an exact, fixed-length Uint8Array view into private storage without
 * consulting caller-controlled properties. Proxy, subclass/Buffer, impostor,
 * shared, resizable, and detached inputs are rejected before use.
 */
export function capturePrivateBytes(input: unknown, maximum: number, allowEmpty = false): PrivateByteCapture {
  if (!Number.isSafeInteger(maximum) || maximum < 0) throw new TypeError("invalid private byte bound");
  if (
    input === null ||
    typeof input !== "object" ||
    utilTypes.isProxy(input) ||
    Object.getPrototypeOf(input) !== Uint8Array.prototype
  ) {
    return { bytes: null, bounded: false };
  }

  try {
    const length = typedArrayByteLength.call(input);
    const buffer = typedArrayBuffer.call(input);
    if (!Number.isSafeInteger(length) || (length as number) < (allowEmpty ? 0 : 1)) {
      return { bytes: null, bounded: true };
    }
    if ((length as number) > maximum) return { bytes: null, bounded: true };
    if (buffer === null || typeof buffer !== "object") return { bytes: null, bounded: false };

    if (sharedArrayBufferByteLength !== undefined) {
      try {
        sharedArrayBufferByteLength.call(buffer);
        return { bytes: null, bounded: false };
      } catch {
        // A private ArrayBuffer rejects the SharedArrayBuffer intrinsic.
      }
    }

    const backingLength = arrayBufferByteLength.call(buffer);
    if (!Number.isSafeInteger(backingLength) || (backingLength as number) < (length as number)) {
      return { bytes: null, bounded: false };
    }
    if (arrayBufferDetached !== undefined) {
      if (arrayBufferDetached.call(buffer) === true) return { bytes: null, bounded: false };
    } else {
      // A zero-length DataView distinguishes an empty fixed buffer from a detached one.
      new IntrinsicDataView(buffer as ArrayBuffer, 0, 0);
    }
    if (arrayBufferResizable !== undefined && arrayBufferResizable.call(buffer) === true) {
      return { bytes: null, bounded: false };
    }

    const copy = new Uint8Array(length as number);
    typedArraySet.call(copy, input as Uint8Array);
    if (intrinsicByteLength(copy) !== length) return { bytes: null, bounded: false };
    return { bytes: copy, bounded: false };
  } catch {
    return { bytes: null, bounded: false };
  }
}

/** Reads the unshadowable typed-array byte length of trusted private bytes. */
export function intrinsicByteLength(bytes: Uint8Array): number {
  const length = typedArrayByteLength.call(bytes);
  if (!Number.isSafeInteger(length) || (length as number) < 0) throw new TypeError("invalid byte length");
  return length as number;
}
