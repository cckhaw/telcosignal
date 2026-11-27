// MOCK enterprise IdP (SYNTHETIC). Authorization-code + PKCE. Which authentication was "performed" is chosen by mock_* query
// parameters so tests can simulate weak MFA and hostile tokens. Never deployed outside the sandbox.
import https from "node:https";
import { createHash, randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair, type JWK } from "jose";

export const ACR_PHR = "urn:telco-signal:acr:phr";
export interface MockIdp { setRedirect(uri: string): void; origin: string; issuer: string; port: number; clientId: string; clientSecret: string; close(): Promise<void> }
interface Code { sub: string; nonce: string; challenge: string; mfa: string; authAge: number; tamper: string; exp: number; redirect: string }

export async function startMockIdp(tls: { cert: string; key: string }, o: { clientId: string; clientSecret: string; redirectUri: string; port?: number }): Promise<MockIdp> {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const wrong = await generateKeyPair("ES256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "idp-1", alg: "ES256", use: "sig" } as JWK;
  const codes = new Map<string, Code>();
  let origin = "";
  let redirectUri = o.redirectUri;
  const srv = https.createServer({ cert: tls.cert, key: tls.key }, (req, res) => {
    const u = new URL(req.url ?? "/", "https://x");
    const send = (s: number, b: unknown, h: Record<string, string> = {}) => { res.writeHead(s, { "content-type": "application/json", ...h }).end(JSON.stringify(b)); };
    if (u.pathname === "/jwks") return send(200, { keys: [jwk] });
    if (u.pathname === "/authorize" && req.method === "GET") {
      const q = u.searchParams;
      if (q.get("client_id") !== o.clientId || q.get("redirect_uri") !== redirectUri || q.get("response_type") !== "code" || q.get("code_challenge_method") !== "S256") return send(400, { error: "invalid_request" });
      const code = randomBytes(24).toString("base64url");
      codes.set(code, { sub: q.get("login_hint") ?? "", nonce: q.get("nonce") ?? "", challenge: q.get("code_challenge") ?? "", mfa: q.get("mock_mfa") ?? "webauthn", authAge: Number(q.get("mock_auth_age") ?? 0), tamper: q.get("mock_tamper") ?? "", exp: Date.now() + 60_000, redirect: redirectUri });
      return void res.writeHead(302, { location: `${redirectUri}?code=${code}&state=${encodeURIComponent(q.get("state") ?? "")}` }).end();
    }
    if (u.pathname === "/token" && req.method === "POST") {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", async () => {
        const f = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        const c = codes.get(f.get("code") ?? "");
        codes.delete(f.get("code") ?? "");                                           // single use
        if (!c || c.exp < Date.now() || f.get("client_id") !== o.clientId || f.get("client_secret") !== o.clientSecret || f.get("redirect_uri") !== c.redirect) return send(400, { error: "invalid_grant" });
        if (createHash("sha256").update(f.get("code_verifier") ?? "").digest("base64url") !== c.challenge) return send(400, { error: "invalid_grant", detail: "pkce" });
        const now = Math.floor(Date.now() / 1000);
        const strong = c.mfa === "webauthn";
        const claims: Record<string, unknown> = { nonce: c.tamper === "nonce" ? "attacker-nonce" : c.nonce, auth_time: now - c.authAge, acr: strong ? ACR_PHR : c.mfa === "totp" ? "urn:telco-signal:acr:mfa" : "pwd", amr: strong ? ["hwk", "user"] : c.mfa === "totp" ? ["otp", "pwd"] : ["pwd"] };
        let key: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"] | Uint8Array = privateKey;
        let alg = "ES256";
        if (c.tamper === "wrongkey") key = wrong.privateKey;
        if (c.tamper === "hs256") { key = new TextEncoder().encode("0123456789abcdef0123456789abcdef"); alg = "HS256"; }
        const jwt = new SignJWT(claims).setProtectedHeader({ alg, kid: "idp-1" }).setIssuer(c.tamper === "iss" ? "https://evil.example" : origin).setAudience(c.tamper === "aud" ? "another-client" : o.clientId)
          .setSubject(c.sub).setIssuedAt(now).setExpirationTime(c.tamper === "expired" ? now - 3600 : now + 300);
        let idToken = await jwt.sign(key as never);
        if (c.tamper === "unsigned") { const [hd, bd] = idToken.split("."); idToken = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${bd}.`; void hd; }
        send(200, { id_token: idToken, token_type: "Bearer", expires_in: 300 });
      });
      return;
    }
    send(404, { error: "not_found" });
  });
  await new Promise<void>((r) => srv.listen(o.port ?? 0, "127.0.0.1", r));
  const port = (srv.address() as AddressInfo).port;
  origin = `https://localhost:${port}`;
  return { setRedirect: (u: string) => { redirectUri = u; }, origin, issuer: origin, port, clientId: o.clientId, clientSecret: o.clientSecret, close: () => new Promise<void>((r) => { srv.closeAllConnections(); srv.close(() => r()); }) };
}
