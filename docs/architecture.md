# Architecture

Sandbox reference implementation. Synthetic data only. Not approved for live data.

## 1. Context and trust boundaries
```
                    TB1                      TB2                         TB3
 Participant (bank) ──mTLS──▶ [WAF/DDoS/API gateway] ──mTLS──▶ Participant API (:8443)
                                                                    │ in-process modules
 Admin user ─SSO+WebAuthn─▶ [admin gateway, VPN/IP allow] ─▶ Admin API+UI (:9443)   (TB4)
                                                                    │
   Router → Adapter A (CAMARA) ──mTLS+allow-list──▶ Telco A mock    (TB5)
          → Adapter B (proprietary) ───────────────▶ Telco B mock
          → Adapter C ───────────────────────────▶ Aggregator mock ▶ Telco C   (TB5)
   Platform ─▶ Postgres (RLS, TB6)   ─▶ Redis (ephemeral, TB7)   ─▶ KMS iface (TB8)
   Platform ─▶ Audit sink outside Postgres (TB9)   ─▶ SIEM/OTel collector (TB10)
```
Boundaries: TB1 internet↔edge; TB2 edge↔platform; TB3 participant plane↔core; TB4 admin plane↔core;
TB5 platform↔telco/aggregator; TB6 app↔database; TB7 app↔Redis; TB8 app↔KMS; TB9 app↔external audit copy; TB10 app↔telemetry; TB11 CI/CD↔runtime; TB12 browser↔admin UI.

## 2. Modular monolith
Modules (no cross-module DB access except through module APIs): `identity` (AS + token verify), `participants`, `consent`, `router`, `registry`, `adapters/*`, `signals`, `ratelimit`, `abuse`, `resilience`, `metering`, `pricing`, `audit`, `kms`, `config` (versioned + approvals), `onboarding`, `credentials`, `observability`, `reporting`, `admin-ui`.
Two Fastify instances built from the same modules but with **disjoint route tables, listeners, TLS contexts, and sessions**; the admin instance binds a separate interface/port and refuses participant tokens (and vice versa).

## 3. Request path (SIM swap example)
1. TLS 1.3 (1.2 min, AEAD suites only), client cert required (`requestCert`, `rejectUnauthorized`).
2. Bearer access token (JWT, `typ=at+jwt`) verified with `jose`: pinned alg (ES256/PS256), `iss`, `aud`, `exp` ≤ 5 min, `jti`, scope, `cnf.x5t#S256` == SHA-256 of the presented client cert → **sender constraint**.
3. Request integrity: `Digest`/content hash + signed headers (RFC 9421-style via vetted lib or JWS detached payload), `X-Timestamp` ±60 s, `X-Nonce`; nonce stored in Redis (`SET NX EX`) → replay rejection. Fail closed if Redis unavailable.
4. Strict JSON-Schema (Ajv, `additionalProperties:false`, size ≤ 4 KB, 2 s overall deadline).
5. AuthZ: participant id derived **only** from the token/cert (never from body); per-signal entitlements; per-function check.
6. Consent/purpose: `purpose_code` + `consent_ref` resolved in DB (RLS scoped); missing/expired/revoked/not permitted for signal → 403 generic code.
7. Rate limit/quota (participant, signal, telco, msisdn-hash) → abuse detector (enumeration heuristics).
8. Router: `HMAC-SHA256(key_id, E.164)` → routing table with porting overlay → telco; kill-switch + circuit-breaker check.
9. Adapter: outbound via allow-listed `undici` Agent (DNS-pinned, no redirects, private-range block, size/time limits, mTLS to telco); response validated against adapter schema as **untrusted**.
10. Normalise to `{status: TRUE|FALSE|UNAVAILABLE|NOT_SUPPORTED}`; any timeout/error/unsupported/invalid/inconsistent → `UNAVAILABLE`/`NOT_SUPPORTED`. Never `FALSE` by default.
11. Metering (append-only; no charge on platform/telco failure), audit (hash-chained), metrics, response with correlation id; errors generic (no existence oracle).

## 4. Data stores
* **Postgres** (system of record): roles `ts_migrator` (owner), `ts_app` (NOBYPASSRLS, no ownership, DML only on allowed tables, no DDL), `ts_reporting` (SELECT on rollup/views). RLS policies keyed on `current_setting('app.org_id')` set with `SET LOCAL` inside a transaction per request (safe with transaction-pooled connections; test proves no leakage after pool reuse). Parameterised queries only. `sslmode=verify-full` outside local dev.
* **Redis**: nonce, rate-limit counters, short breaker state. TTL-bound only; interface `EphemeralStore`.
* **Field-level protection**: envelope encryption (AES-256-GCM via KMS interface `generateDataKey/decrypt`; mock = local software KMS with keys generated at setup, never committed). MSISDN is never stored raw: stored as keyed HMAC (`msisdn_hash`) only; KYC inputs never stored.
* **Audit**: table `audit_log` append-only (revoke UPDATE/DELETE, trigger rejects mutation), `hash = SHA256(prev_hash || canonical(record))`, periodically anchored/shipped to external sink (file-based WORM mock / S3-object-lock in prod). Verification job + test detects tampering.
* **Metering**: `usage_record` append-only; corrections are compensating rows. Rollups (`rollup_minute`, `_hour`, `_day`) built by a worker; dashboards read only rollups, with freshness shown; reconciliation test: rollup totals == sum(usage_record).

## 5. Admin plane
Server-rendered UI (no client secrets), OIDC SSO against an IdP (mock IdP locally) requiring `amr` containing a phishing-resistant method (`hwk`/WebAuthn) — fail closed otherwise. Sessions: `__Host-` cookie, HttpOnly, Secure, SameSite=Strict, idle 15 min / absolute 8 h, rotated on privilege change. CSRF: per-session synchroniser token + Origin check. CSP `default-src 'none'` + nonces, no inline script, Trusted headers. RBAC enforced in API layer (never UI-only). Orgs-scoped roles (telco/bank users) bound via RLS. Every view of sensitive data and every change → audit.
Config changes: `config_change` (draft → pending approval → approved/applied/rolled back); high-risk classes (keys, prices, limits, policy, routing) require approver ≠ requester **and** approver has the role; enforced in DB constraint + service; tested for bypass (self-approve, replay approval, edit-after-approve, role downgrade race).
Onboarding states: draft → testing → pending_approval → active → suspended → retired; transitions in a single guarded function; activation requires passing test evidence rows + second approver.

## 6. Resilience
Per-telco circuit breaker (closed/open/half-open), timeout 2 s default, bulkheads (concurrency cap per telco), kill switches (participant/telco/signal) checked on every request from a versioned, cached config with short TTL and fail-closed default. Fault-injection hooks live only in the mock telcos.

## 7. Observability
OpenTelemetry traces/metrics/logs; attributes allow-list (no MSISDN, no names); `correlation_id` propagated; SIEM-ready JSON events (ECS-like) for authn failures, replay, rate-limit, enumeration, config changes, kill switch. Alert rules in config with ack/escalation.

## 8. Supply chain & runtime
Lockfile + exact pins, `npm ci --ignore-scripts`, SBOM (CycloneDX), build provenance (GitHub artifact attestations / sigstore cosign for images), distroless/non-root image, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, segmented compose networks (`edge`, `core`, `data`, `telco`, `admin`), separate env files per environment.

## 9. Hosting / Vercel assessment (D-003)
| Control | Vercel Functions | Result |
|---|---|---|
| Participant client-cert mTLS terminated at platform | Not supported on Vercel's edge for custom client-cert verification | **Cannot enforce** |
| Admin isolated interface / IP allow-listing | Firewall rules exist; no private isolated listener; IP allow-list only on higher plans | Partial |
| Fixed egress IP / telco mTLS egress | Static IPs add-on only | Partial |
| Region sin1 | Supported (`regions:["sin1"]`) | OK |
Decision: Vercel Production hosts **only the static developer portal/docs** (public, no secrets, no participant data). The participant API and admin plane must run behind a gateway/host that supports client-cert mTLS (e.g. container host in ap-southeast-1 behind an mTLS-capable gateway such as Envoy/NGINX/AWS NLB-TLS passthrough). The control is not dropped. Needs human decision before any live-like hosting.

## 10. Data residency map (initial)
| Data | Location | Note |
|---|---|---|
| App DB (Neon, planned) | AWS Singapore | Outside Malaysia → open cross-border risk R-001, blocks live data |
| Local dev/CI | Ephemeral | Synthetic only |
| Audit external copy | TBD | Must be in approved jurisdiction |
