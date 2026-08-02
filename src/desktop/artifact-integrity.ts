import {
  createHash,
  timingSafeEqual,
} from "node:crypto";

const SHA256_HEX = /^[0-9a-f]{64}$/i;

/**
 * Verifies manifest integrity without accepting malformed digests. The
 * comparison is constant-time once both digests have a valid fixed length.
 */
export function verifyArtifactSha256(
  bytes: Uint8Array,
  expectedSha256: string,
): boolean {
  if (!SHA256_HEX.test(expectedSha256)) {
    return false;
  }
  const actual = createHash("sha256").update(bytes).digest();
  const expected = Buffer.from(expectedSha256, "hex");
  return (
    expected.byteLength === actual.byteLength &&
    timingSafeEqual(actual, expected)
  );
}
