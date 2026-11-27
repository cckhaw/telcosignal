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
| SC-10 | DAST on running sandbox | Own black-box runner (`tests/dast/run.ts`, 49 checks over real mTLS) against the running sandbox in CI; mutation-checked (disabling rate limiting makes it fail) | ci.yml `dast`, tests/dast | partial: not an off-the-shelf scanner; ZAP/Nuclei with client-certificate support still to add (open item) |
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
| API-04 | Outbound allow-list; telco responses untrusted | `adapters/outbound.ts` (https only, origin allow-list, no redirects, size/time caps, TLS verify + mTLS), per-adapter strict parsers (A: Ajv; B: anchored regex; C: Ajv + request/carrier binding) | m2-signals "malicious or broken telco/aggregator responses", "outbound controls" | met (sandbox mocks); private-IP/DNS pinning for admin-supplied endpoints arrives with M4a |
| API-05 | Rate limits and quotas per participant, signal, telco and phone-number hash; enumeration detection, alert, suspension | `@fastify/rate-limit` (per certificate, token endpoint stricter), `ratelimit/limits.ts` (participant x signal with overrides, per-subject, per-telco), `abuse/enumeration.ts`, `abuse_suspend()` | m1-ratelimit, m3-abuse, DAST (53 checks) | met (sandbox); fixed windows; thresholds are placeholders to tune |
| DATA-01 | TLS 1.3 preferred / 1.2 min; mTLS | `participant-api/server.ts` | m1-controls "transport" | met (sandbox); edge/gateway not built (R-002/R-005) |
| DATA-02 | Encryption at rest, field-level, KMS iface, rotation | `kms/`, Neon-at-rest (not yet) | m1-controls "KMS" | partial |
| DATA-03 | No raw numbers in logs/audit/usage/DB | keyed HMAC, redaction, audit guard | m1-controls "privacy" | met (sandbox) |
| DB-02 | Separate roles; app not owner; no RLS bypass; pooled-connection isolation | `migrations/001_init.sql`, `db/pool.ts` | m1-controls "database" | met (local PG; not yet on Neon, D-002) |
| DB-03 | Parameterised queries; reviewed, checksummed migrations | all queries parameterised; `db/migrate.ts` | m1-controls migration checksum; Semgrep rule | met |
| PRIV-01 | Purpose + consent ref required; reject missing/expired/revoked/not permitted | `consent/consent.ts` | m1-acceptance "missing / invalid consent" | met (sandbox) |
| AUD-01 | Tamper-evident, append-only audit, copy outside DB | `audit/audit.ts`, `audit_append()` | m1-controls "audit log" (incl. superuser tamper, external copy deletion) | met (sandbox); external sink is a local file mock |
| SAFE-01 | Timeout/error/unsupported never "no swap"/"no forwarding"/"match" | adapters + generic signal pipeline | m1-controls "signal safety"; m2-signals (all 4 signals, 3 telcos, ~25 hostile cases) | met (sandbox) |
| RES-01 | Kill switch per participant/telco/signal | `kill_switch` table, checked per request | m1-controls kill switches | partial (admin UI in M4a) |
| METER-01 | No charge on platform/telco failure | DB CHECK + app logic | m1-controls "never billed" | met |
| ROUTE-01 | Phone-number-to-telco routing with number porting | `router/router.ts`, `porting` (keyed hash, effective-dated) | m2-signals "routing, number porting and coverage" | met (sandbox); porting writes need two-person approval (M4a, T-036) |
| REG-01 | Signal registry and per-telco coverage; NOT_SUPPORTED | `signals`, `telco_signal_coverage` | m2-signals | met (sandbox) |
| PRIV-02 | KYC match inputs never stored | in-memory only; redaction; audit/usage carry no attributes | m2-signals "KYC inputs are never stored or logged" | met (sandbox) |
| CAMARA-01 | CAMARA definitions pinned from official repos; adapter paths follow them | `openapi/camara/PINS.md`, `SHA256SUMS` | m2-signals "adapter paths match the vendored, pinned CAMARA definitions" | met for Telco A; the participant API deviates deliberately (architecture §11) |
| RES-02 | Circuit breakers, bulkheads, timeouts; fault injection | `resilience/breaker.ts` (decorator), 2 s adapter timeout | m3-resilience (11 tests incl. DoS-via-unknown-numbers) | met (sandbox); breaker state is per process |
| METER-02 | Append-only metering; configurable platform fee, per-query price, telco cost, tiers (placeholders); no charge on failure | `usage_record` (+triggers, CHECK), `price_plan`, `org_price_plan`, `telco_cost`, `metering/pricing.ts` | m3-metering | met (sandbox); price changes need M4a approval flow |
| METER-03 | Settlement statements reconcile with usage | `metering/statements.ts` (billing role, REPEATABLE READ, digest of usage ids), immutable `statement`, overlap exclusion constraint | m3-metering "statements reconcile with usage records" | met (sandbox) |
| AUTHZ-03 | Least-privilege billing role | `ts_billing`: reads usage/prices, inserts statements only | m3-metering role separation | met (local PG) |
| ADM-01 | Admin SSO with phishing-resistant MFA; no default accounts; fail closed | `admin/server.ts` (OIDC code+PKCE, `acr`/`amr` enforced), `admin_user` (empty at migration) | m4a-auth (MFA, hostile ID tokens, no JIT), DAST admin | met (sandbox, mock IdP) |
| ADM-02 | RBAC, server-side; restricted telco/bank users see only their own organisation | route role matrix + `config_role_policy` + RLS on `ts_admin` | m4a-isolation (8 identities x 8 routes, direct RLS tests) | met (sandbox) |
| ADM-03 | Two-person approval for keys, prices, limits, policy, routing; cannot be bypassed | `cfg_request`/`cfg_decide`/`cfg_apply` SECURITY DEFINER, no write grants for the portal role, CHECK constraint, immutable payload + hash | m4a-approval (19 tests incl. direct-DB attacks) | met (sandbox) |
| ADM-04 | Versioned configuration with diff, rollback (gated) | `config_history` (append-only, before/after/restore), `/history`, change diff view | m4a-approval "versioned configuration" | met (sandbox) |
| ADM-05 | Onboarding states; activation blocked until required tests pass AND second person approves | `cfg_required_tests`, `onb_*`, `ORG_STATE` apply | m4a-onboarding | met (sandbox); telco test results app-asserted (R-010) |
| ADM-06 | CSRF, XSS, session timeout, audit of every view/change | CSRF token+Origin+form-only, auto-escaping, CSP `default-src 'none'`, idle 15 min/absolute 8 h, audit per route | m4a-auth, DAST admin | met (sandbox) |
| ADM-07 | Credentials: public-key registration, show-once secret, rotate, expire alerts, revoke | `/credentials`, `KEY_REGISTER`, `admin_revoke_key` | m4a-onboarding "credentials" | met (sandbox); expiry alerts proper arrive in M4b |
| ADM-08 | Kill switches per participant/telco/signal; lifting is gated | `admin_kill_switch_engage`, `KILL_SWITCH_LIFT` | m4a-approval, DAST | met (sandbox) |
| ADM-09 | Endpoints allow-listed; SSRF-safe telco onboarding | `common/ssrf.ts`, `endpoint_allowlist`, registry re-validation | m4a-onboarding (13 hostile URLs) | partial (R-012 DNS pinning, R-013 cert pinning) |
| ADM-10 | Test console uses synthetic data only; no replay of real requests | `/integration/test` prefix check | m4a-isolation, DAST | met (sandbox) |
| OBS-01 | Logs: search/filter by time, participant, telco, signal, outcome, error code, correlation id; values masked, no unmask; admins cannot edit logs; configurable retention; exports role-restricted and audited | `request_log` (+CHECKs, append-only trigger), `/logs`, `/logs.csv`, `ops/retention.ts` | m4b-logs-trace, m4b-dashboards-alerts (retention) | met (sandbox) |
| OBS-02 | Troubleshooting: trace one request across gateway/router/adapter with timing per step; error catalogue with actions; dependency health; incident notes; no replay | step timings, `/logs/:cid`, `/errors`, `/health`, `incident_note` | m4b-logs-trace (acceptance), m4b-dashboards-alerts (health) | met (sandbox); gateway not instrumented |
| OBS-03 | Alerts: configurable thresholds, acknowledgement, escalation | `alert_rule`, `alert`, `ops/alerts.ts`, `/alerts` | m4b-dashboards-alerts | met (sandbox); no pager delivery (R-018) |
| OBS-04 | Dashboards by period/participant/telco/signal/version; time-bucketed rollups; freshness; org sees only own figures; totals reconcile with usage records | `rollup_*`, `ops/rollups.ts`, `admin/dashboard.ts` | m4b-dashboards-alerts (acceptance), DAST admin | met (sandbox) |
| OBS-05 | CSV export and monthly report | `/dashboard.csv`, `/reports/monthly(.csv)` | m4b-dashboards-alerts | met (sandbox) |
| AUD-02 | Audit trail viewable by auditors; chain verification; not writable from the portal | `audit_search()`, `audit_verify()`, `/audit` | m4b-logs-trace | met (sandbox) |
| PRIV-03 | Retention and deletion jobs; data inventory; residency map; PIA inputs; breach runbook | `ops/retention.ts`, docs/privacy/*, docs/runbooks/breach-notification.md | m4b-dashboards-alerts (retention), docs.test | partial: periods for usage/audit data and DSAR workflow need Legal decisions; legal texts unverified |
| DEV-01 | OpenAPI 3 definition of the participant API | `scripts/gen-openapi.ts` -> `openapi/participant.yaml` (generated; drift fails a test) | m4b-openapi-portal (routes, schemas, live contract) | met (sandbox) |
| DEV-02 | Developer portal (static, public, no secrets) | `scripts/build-portal.ts` -> `portal/` on Vercel | m4b-openapi-portal (reproducible, no script, strict CSP) | met |
| OPS-02 | Backup, restore and a TESTED restore | `ops/backup.ts` | m4b-backup-restore (7 tests) | partial: Neon PITR untested (D-002) |
| OPS-03 | Runbooks (incident, alerts, kill switch, breach, backup/restore, DR, key rotation, retention, onboarding) | docs/runbooks/* | docs.test (tied to alert rules and settings) | partial: never exercised by a human team |
