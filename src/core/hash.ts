import { createHash } from "node:crypto";

export function sha256Bytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function sha256Text(text: string): string {
  return sha256Bytes(Buffer.from(text, "utf8"));
}

export function utf8ByteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

