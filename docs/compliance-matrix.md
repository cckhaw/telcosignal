# Compliance matrix

**No certification or compliance is claimed.** This matrix maps requirements to controls for engineering tracking only.
Status: met / partial / not met / needs human decision. A row is "met" only when its test exists AND was run green (see `docs/reports/`).

## Source text verification
| Standard | Text read in this repo? |
|---|---|
| OWASP ASVS 5.0 (L3) | **Unverified** – not yet fetched; control IDs below are by topic, to be mapped to V-numbers after reading |
| OWASP API Security Top 10 2023 | Known by name (API1–API10:2023); full text **unverified** here |
| OWASP Top 10 | **Unverified** |
| FAPI 2.0 Security Profile | **Unverified** |
| CAMARA security guidance + API specs | **Unverified – must be pinned from camaraproject repos in M1; stop if unavailable** |
| BNM RMiT (Nov 2025) | **Unverified** |
| Malaysia PDPA (2024 amendments) | **Unverified** |
| Cyber Security Act 2024 | **Unverified** (applicability needs legal decision) |

## Matrix
| Req ID | Requirement | Control | Location | Test | Status |
|---|---|---|---|---|---|
| SC-01 | Secret scan blocks merge | gitleaks full history, no allow-list | `.github/workflows/ci.yml`, `.gitleaks.toml` | seeded secret PR (docs/reports/M0.md) | partial (see M0 report) |
| SC-02 | Dependency vuln scan blocks merge | `npm audit` high+, Trivy | ci.yml `dependency-scan` | seeded vulnerable dep PR | partial |
| SC-03 | SAST | Semgrep + CodeQL | ci.yml | CI | partial |
| SC-04 | Container + IaC scan | Trivy image/config | ci.yml | CI | partial |
| SC-05 | Pinned deps + lockfile | exact pins, `check-pins.mjs`, `ignore-scripts` | package.json, scripts | CI | met (locally verified) |
| SC-06 | SBOM | CycloneDX via `npm sbom` | ci.yml `build-test` | CI artifact | partial |
| SC-07 | Signed builds | attestation/cosign | – | – | not met (M1+) |
| SC-08 | Actions pinned by commit SHA (version in comment) | ci.yml, deploy-production.yml | semgrep mutable-tag rule | met (pending CI) |
| SC-09 | Minimal non-root, read-only containers | distroless nonroot Dockerfile; read-only in compose (M1) | docker/Dockerfile | Trivy | partial |
| SC-10 | DAST on running sandbox | ZAP against compose sandbox | ci.yml `dast` | – | not met (sandbox arrives M1) |
| DEP-01 | No preview deployments; prod only | `git.deploymentEnabled=false`; workflow on `main` push only | vercel.json, deploy-production.yml | observed: 1 prod deployment, 0 previews (M0 report) | met |
| DEP-02 | Delete older deployments after latest READY | `scripts/vercel-cleanup.mjs` (fails closed) | scripts | first run OK; delete path unexercised until 2nd merge | partial |
| DEP-03 | Participant mTLS on hosting | Not possible on Vercel | docs/architecture.md §9 | – | needs human decision (D-003) |
| DB-01 | Neon Singapore residency risk recorded | R-001 | threat-model.md | – | needs human decision (D-002) |
| ID-01 | OAuth client credentials, private_key_jwt, no shared secrets | `src/identity/tokens.ts` `verifyClientAssertion` | tests/security/m1-controls "client authentication hygiene" | met (sandbox) |
| ID-02 | Sender-constrained tokens (mTLS), short expiry, strict iss/aud/alg/typ | `issueAccessToken`/`verifyAccessToken` | m1-acceptance "bad token" (forged, alg=none, HS256, aud, iss, exp, lifetime, cnf, typ, stolen token) | met (sandbox) |
| ID-03 | Key rotation and revocation | KMS `rotate`; client/key revocation checked per request | m1-controls "KMS", m1-acceptance revoked client, key expiry | met (sandbox; mock KMS, R-003) |
| ID-04 | AuthZ on every function + object; no cross-participant access | scopes per route; RLS + org from token only | m1-acceptance "wrong scope", "cross-participant"; m1-controls RLS | partial (consents, usage; extends per feature) |
| API-01 | Strict schema, unknown fields rejected, size/time limits | `participant-api/schemas.ts`, bodyLimit 4 KB, timeouts | m1-controls "input validation" | met (sandbox) |
| API-02 | Signed requests, timestamp, nonce, replay rejection | `verifyRequestSignature`, Redis NX | m1-acceptance "replay and request integrity", "fail closed when replay store is down" | met (sandbox) |
| API-03 | Errors reveal no internals / no number existence | `common/errors.ts`; uniform UNAVAILABLE | m1-controls "errors reveal no internals", "signal safety" | met (sandbox) |
| API-04 | Outbound allow-list; telco responses untrusted | `adapters/telcoA.ts` origin allow-list, size cap, strict Ajv, TLS verify | m1-controls signal-safety digits 3-7 | partial (Telco A only; B/C in M2) |
| API-05 | Rate limits, enumeration detection | – | – | not met (M3) |
| DATA-01 | TLS 1.3 preferred / 1.2 min; mTLS | `participant-api/server.ts` | m1-controls "transport" | met (sandbox); edge/gateway not built (R-002/R-005) |
| DATA-02 | Encryption at rest, field-level, KMS iface, rotation | `kms/`, Neon-at-rest (not yet) | m1-controls "KMS" | partial |
| DATA-03 | No raw numbers in logs/audit/usage/DB | keyed HMAC, redaction, audit guard | m1-controls "privacy" | met (sandbox) |
| DB-02 | Separate roles; app not owner; no RLS bypass; pooled-connection isolation | `migrations/001_init.sql`, `db/pool.ts` | m1-controls "database" | met (local PG; not yet on Neon, D-002) |
| DB-03 | Parameterised queries; reviewed, checksummed migrations | all queries parameterised; `db/migrate.ts` | m1-controls migration checksum; Semgrep rule | met |
| PRIV-01 | Purpose + consent ref required; reject missing/expired/revoked/not permitted | `consent/consent.ts` | m1-acceptance "missing / invalid consent" | met (sandbox) |
| AUD-01 | Tamper-evident, append-only audit, copy outside DB | `audit/audit.ts`, `audit_append()` | m1-controls "audit log" (incl. superuser tamper, external copy deletion) | met (sandbox); external sink is a local file mock |
| SAFE-01 | Timeout/error/unsupported never "no swap" | adapters + normaliser | m1-controls "signal safety" | met for SIM swap (other signals M2) |
| RES-01 | Kill switch per participant/telco/signal | `kill_switch` table, checked per request | m1-controls kill switches | partial (admin UI in M4a) |
| METER-01 | No charge on platform/telco failure | DB CHECK + app logic | m1-controls "never billed" | met |
