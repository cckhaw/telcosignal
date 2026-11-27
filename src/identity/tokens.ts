import { SignJWT, jwtVerify, createLocalJWKSet, importJWK, compactVerify, type JWTPayload } from "jose";
import { createHash, randomUUID, timingSafeEqual, X509Certificate } from "node:crypto";
import type { Kms } from "../kms/types.js";
import type { EphemeralStore } from "../common/store.js";
import { ApiError } from "../common/errors.js";
import { clientKeys, type KeyRec } from "./clients.js";
import type { Pool } from "../db/pool.js";

export const ACCESS_TOKEN_TTL_SECONDS = 300;
export const SIGNING_ALGS = ["ES256", "PS256"]; // allowed for participant keys; platform tokens use ES256 only

export function certThumbprint(derOrPem: Buffer): string {
  const der = derOrPem[0] === 0x30 ? derOrPem : new X509Certificate(derOrPem).raw;
  return createHash("sha256").update(der).digest("base64url");
}
function safeEq(a: string, b: string): boolean {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

export async function issueAccessToken(kms: Kms, o: { issuer: string; audience: string }, c: { clientId: string; scope: string[]; thumb: string }) {
  const { kid, privateKey } = await kms.currentSigningKey();
  const token = await new SignJWT({ scope: c.scope.join(" "), client_id: c.clientId, cnf: { "x5t#S256": c.thumb } })
    .setProtectedHeader({ alg: "ES256", kid, typ: "at+jwt" })
    .setIssuer(o.issuer).setAudience(o.audience).setSubject(c.clientId)
    .setIssuedAt().setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`).setJti(randomUUID())
    .sign(privateKey);
  return { token, expiresIn: ACCESS_TOKEN_TTL_SECONDS };
}

export interface AccessClaims { clientId: string; scopes: string[]; jti: string }
/** Strict verification: algorithm pinned, issuer, audience, typ, expiry (≤5 min lifetime), sender-constraint. */
export async function verifyAccessToken(kms: Kms, o: { issuer: string; audience: string }, token: string, presentedThumb: string): Promise<AccessClaims> {
  try {
    const jwks = createLocalJWKSet((await kms.verificationJwks()) as never);
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: o.issuer, audience: o.audience, algorithms: ["ES256"], typ: "at+jwt",
      requiredClaims: ["exp", "iat", "jti", "sub", "scope", "cnf"], clockTolerance: 5,
    });
    if (protectedHeader.typ !== "at+jwt") throw new Error("typ");
    const p = payload as JWTPayload & { scope?: unknown; cnf?: { "x5t#S256"?: unknown }; client_id?: unknown };
    if ((p.exp as number) - (p.iat as number) > ACCESS_TOKEN_TTL_SECONDS) throw new Error("lifetime");
    const bound = p.cnf?.["x5t#S256"];
    if (typeof bound !== "string" || !safeEq(bound, presentedThumb)) throw new Error("cnf");   // sender constraint (mTLS)
    if (typeof p.scope !== "string" || typeof p.sub !== "string" || p.client_id !== p.sub) throw new Error("claims");
    return { clientId: p.sub, scopes: p.scope.split(" ").filter(Boolean), jti: p.jti as string };
  } catch {
    throw new ApiError("AUTHENTICATION_FAILED", "access token invalid");
  }
}

function activeKeyFor(keys: KeyRec[], kid: string | undefined, thumb: string): KeyRec | undefined {
  const now = Date.now();
  return keys.find((k) => k.kid === kid && !k.revokedAt && k.expiresAt.getTime() > now && safeEq(k.certSha256, thumb));
}

/** private_key_jwt client authentication (RFC 7523 / OIDC), bound to the registered client certificate. */
export async function verifyClientAssertion(pool: Pool, store: EphemeralStore, a: { assertion: string; clientId: string; audience: string; thumb: string }): Promise<void> {
  let jti: string;
  try {
    const hdr = JSON.parse(Buffer.from(a.assertion.split(".")[0] ?? "", "base64url").toString("utf8")) as { kid?: string; alg?: string };
    if (!hdr.alg || !SIGNING_ALGS.includes(hdr.alg)) throw new Error("alg");
    const key = activeKeyFor(await clientKeys(pool, a.clientId), hdr.kid, a.thumb);
    if (!key) throw new Error("no active key for this certificate");
    const pub = await importJWK({ ...key.jwk, alg: hdr.alg } as never, hdr.alg);
    const { payload } = await jwtVerify(a.assertion, pub, {
      issuer: a.clientId, subject: a.clientId, audience: a.audience, algorithms: SIGNING_ALGS,
      requiredClaims: ["exp", "iat", "jti"], clockTolerance: 5, maxTokenAge: "60s",
    });
    if ((payload.exp as number) - (payload.iat as number) > 60) throw new Error("assertion lifetime");
    jti = payload.jti as string;
  } catch {
    throw new ApiError("AUTHENTICATION_FAILED", "client assertion invalid");
  }
  // Single-use jti. A store failure fails closed (no token issued) and is reported as unavailable, not as a bad credential.
  let fresh: boolean;
  try { fresh = await store.setNx(`cajti:${a.clientId}:${jti}`, 180); }
  catch { throw new ApiError("SERVICE_UNAVAILABLE", "replay store unavailable (failing closed)"); }
  if (!fresh) throw new ApiError("REPLAY_REJECTED", "client assertion replay");
}

/** Signed-request integrity: compact JWS over {htm, htu, dig, iat, jti}; timestamp window + single-use jti. Fails closed if the store is down. */
export async function verifyRequestSignature(pool: Pool, store: EphemeralStore, a: {
  jws: string | undefined; clientId: string; thumb: string; method: string; path: string; rawBody: Buffer; skewSeconds: number;
}): Promise<void> {
  if (!a.jws) throw new ApiError("AUTHENTICATION_FAILED", "missing request signature");
  let payload: Record<string, unknown>;
  try {
    const hdr = JSON.parse(Buffer.from(a.jws.split(".")[0] ?? "", "base64url").toString("utf8")) as { kid?: string; alg?: string };
    if (!hdr.alg || !SIGNING_ALGS.includes(hdr.alg)) throw new Error("alg");
    const key = activeKeyFor(await clientKeys(pool, a.clientId), hdr.kid, a.thumb);
    if (!key) throw new Error("key");
    const pub = await importJWK({ ...key.jwk, alg: hdr.alg } as never, hdr.alg);
    const v = await compactVerify(a.jws, pub, { algorithms: SIGNING_ALGS });
    payload = JSON.parse(new TextDecoder().decode(v.payload)) as Record<string, unknown>;
  } catch {
    throw new ApiError("AUTHENTICATION_FAILED", "request signature invalid");
  }
  const dig = createHash("sha256").update(a.rawBody).digest("base64url");
  const iat = payload["iat"], jti = payload["jti"];
  if (payload["htm"] !== a.method || payload["htu"] !== a.path || typeof payload["dig"] !== "string" || !safeEq(payload["dig"], dig))
    throw new ApiError("AUTHENTICATION_FAILED", "request signature does not match request");
  if (typeof iat !== "number" || Math.abs(Date.now() / 1000 - iat) > a.skewSeconds) throw new ApiError("REPLAY_REJECTED", "timestamp outside window");
  if (typeof jti !== "string" || !/^[A-Za-z0-9_-]{16,64}$/.test(jti)) throw new ApiError("AUTHENTICATION_FAILED", "bad jti");
  let fresh: boolean;
  try { fresh = await store.setNx(`req:${a.clientId}:${jti}`, a.skewSeconds * 2 + 10); }
  catch { throw new ApiError("SERVICE_UNAVAILABLE", "replay store unavailable (failing closed)"); }
  if (!fresh) throw new ApiError("REPLAY_REJECTED", "nonce reuse");
}
