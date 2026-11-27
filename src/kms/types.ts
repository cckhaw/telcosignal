import type { KeyObject } from "node:crypto";
export type SigningKeyRef = { kid: string; privateKey: KeyObject };
/** KMS/HSM interface. Local software implementation is a mock; production must use a real KMS/HSM. */
export interface Kms {
  /** Keyed hash (HMAC-SHA256) under a named key; returns raw bytes. Never returns key material. */
  hmac(keyName: string, data: string): Promise<Buffer>;
  /** Envelope encryption (AES-256-GCM) for field-level protection. Output embeds key version. */
  encrypt(keyName: string, plaintext: Buffer, aad: string): Promise<string>;
  decrypt(keyName: string, envelope: string, aad: string): Promise<Buffer>;
  /** Token signing key (current) and public verification keys (current + previous, for rotation). */
  currentSigningKey(): Promise<SigningKeyRef>;
  verificationJwks(): Promise<{ keys: Array<Record<string, unknown>> }>;
  /** Rotation: new key version becomes current; old versions remain decrypt/verify-only. */
  rotate(keyName: string): Promise<number>;
}
