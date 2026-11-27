// LOCAL MOCK KMS. Keys are generated at setup/first use, kept in a 0700 directory (never in repo/images/logs).
// Not a substitute for an HSM: residual risk R-003.
import { createCipheriv, createDecipheriv, createHmac, generateKeyPairSync, randomBytes, createPublicKey, KeyObject } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { exportJWK } from "jose";
import type { Kms, SigningKeyRef } from "./types.js";

export class LocalKms implements Kms {
  constructor(private readonly dir: string) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
  }
  private versions(keyName: string): number[] {
    return readdirSync(this.dir)
      .map((f) => new RegExp(`^${keyName}\\.v(\\d+)\\.key$`).exec(f)?.[1])
      .filter((v): v is string => v !== undefined)
      .map(Number)
      .sort((a, b) => a - b);
  }
  private ensure(keyName: string): number {
    if (!/^[a-z0-9-]{1,40}$/.test(keyName)) throw new Error("bad key name");
    const v = this.versions(keyName);
    if (v.length) return v[v.length - 1] as number;
    return this.newVersion(keyName, 1);
  }
  private newVersion(keyName: string, version: number): number {
    writeFileSync(join(this.dir, `${keyName}.v${version}.key`), randomBytes(32), { mode: 0o600, flag: "wx" });
    return version;
  }
  private key(keyName: string, version: number): Buffer {
    const k = readFileSync(join(this.dir, `${keyName}.v${version}.key`));
    if (k.length !== 32) throw new Error("corrupt key");
    return k;
  }
  async hmac(keyName: string, data: string): Promise<Buffer> {
    // HMAC keys are NOT rotated in place (hash stability); a rotation requires a re-hash migration.
    const v = this.versions(keyName)[0] ?? this.ensure(keyName);
    return createHmac("sha256", this.key(keyName, v)).update(data, "utf8").digest();
  }
  async encrypt(keyName: string, plaintext: Buffer, aad: string): Promise<string> {
    const v = this.ensure(keyName);
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", this.key(keyName, v), iv, { authTagLength: 16 });
    c.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    return `v${v}.${iv.toString("base64url")}.${ct.toString("base64url")}.${c.getAuthTag().toString("base64url")}`;
  }
  async decrypt(keyName: string, envelope: string, aad: string): Promise<Buffer> {
    const [ver, iv, ct, tag] = envelope.split(".");
    if (!ver?.startsWith("v") || !iv || !ct || !tag) throw new Error("bad envelope");
    const d = createDecipheriv("aes-256-gcm", this.key(keyName, Number(ver.slice(1))), Buffer.from(iv, "base64url"), { authTagLength: 16 });
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]);
  }
  private sigVersions(): number[] { return this.versions("token-signing-ec"); }
  private ensureSigning(): number {
    const v = this.sigVersions();
    if (v.length) return v[v.length - 1] as number;
    return this.writeSigning(1);
  }
  private writeSigning(version: number): number {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    writeFileSync(join(this.dir, `token-signing-ec.v${version}.key`), privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600, flag: "wx" });
    return version;
  }
  private signingKeyObject(version: number): KeyObject {
    const pem = readFileSync(join(this.dir, `token-signing-ec.v${version}.key`));
    return createPrivateKeyFromPem(pem);
  }
  async currentSigningKey(): Promise<SigningKeyRef> {
    const v = this.ensureSigning();
    return { kid: `ts-sig-v${v}`, privateKey: this.signingKeyObject(v) };
  }
  async verificationJwks() {
    this.ensureSigning();
    const keys: Array<Record<string, unknown>> = [];
    for (const v of this.sigVersions()) {
      const pub = createPublicKey(this.signingKeyObject(v));
      keys.push({ ...(await exportJWK(pub)), kid: `ts-sig-v${v}`, alg: "ES256", use: "sig" });
    }
    return { keys };
  }
  async rotate(keyName: string): Promise<number> {
    if (keyName === "token-signing-ec") return this.writeSigning((this.sigVersions().pop() ?? 0) + 1);
    return this.newVersion(keyName, (this.versions(keyName).pop() ?? 0) + 1);
  }
}
import { createPrivateKey } from "node:crypto";
function createPrivateKeyFromPem(pem: Buffer): KeyObject { return createPrivateKey(pem); }
export function kmsDirExists(d: string) { return existsSync(d); }
