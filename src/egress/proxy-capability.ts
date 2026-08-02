const basicPrefix = "Basic ";
const capabilityUsername = "cogs";
const decodedPrefix = Buffer.from(`${capabilityUsername}:`, "ascii");
const base64 = /^[A-Za-z0-9+/]+={0,2}$/;
const capability = /^[\x21-\x7e]{16,256}$/;
const maximumDecodedBytes = decodedPrefix.length + 1024;

/**
 * Encode exactly `Basic base64(ASCII("cogs:" + capability))`: one value, one
 * separating space, fixed username `cogs`, and the raw capability as password.
 */
export function encodeProxyAuthorizationBasic(value: string): string {
  if (typeof value !== "string" || !capability.test(value)) throw new Error("invalid proxy capability");
  return `${basicPrefix}${Buffer.from(`${capabilityUsername}:${value}`, "ascii").toString("base64")}`;
}

/**
 * Strictly decode one canonical Basic value. The caller owns and must clear the
 * returned password buffer. Undefined is an authentication failure.
 */
export function decodeProxyAuthorizationBasic(value: string): Buffer | undefined {
  if (typeof value !== "string" || !value.startsWith(basicPrefix)) return undefined;
  const encoded = value.slice(basicPrefix.length);
  if (encoded.length === 0 || encoded.length % 4 !== 0 || !base64.test(encoded)) return undefined;

  let decoded: Buffer | undefined;
  try {
    decoded = Buffer.from(encoded, "base64");
    if (
      decoded.length <= decodedPrefix.length ||
      decoded.length > maximumDecodedBytes ||
      decoded.toString("base64") !== encoded ||
      !decoded.subarray(0, decodedPrefix.length).equals(decodedPrefix)
    ) {
      return undefined;
    }
    return Buffer.from(decoded.subarray(decodedPrefix.length));
  } catch {
    return undefined;
  } finally {
    decoded?.fill(0);
  }
}
