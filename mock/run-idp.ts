// Sandbox runner for the MOCK enterprise IdP (SYNTHETIC). Never deployed with real identities.
import { readFileSync } from "node:fs";
import { startMockIdp } from "./idp.js";
const f = (n: string) => readFileSync(process.env[`${n}_FILE`] ?? (() => { throw new Error(`missing ${n}_FILE`); })(), "utf8");
const idp = await startMockIdp({ cert: f("IDP_CERT"), key: f("IDP_KEY") }, { clientId: process.env["TS_OIDC_CLIENT_ID"] ?? "admin-portal", clientSecret: f("TS_OIDC_CLIENT_SECRET").trim(), redirectUri: process.env["ADMIN_REDIRECT_URI"] ?? "", port: Number(process.env["IDP_PORT"] ?? 9444) });
console.log(`mock IdP listening (synthetic) issuer=${idp.issuer}`);
