# Threat Model (STRIDE over trust boundaries + abuse cases)

Scope: platform described in `architecture.md`. Assets: A1 consent/lawful-basis records; A2 MSISDN (as keyed hash only); A3 signal results (sensitive fraud indicators); A4 participant credentials/certs; A5 admin sessions & config; A6 audit log; A7 pricing/metering/settlement; A8 KMS keys; A9 telco connectivity/credentials; A10 availability.
Actors: external attacker, malicious/compromised participant, malicious/compromised telco or aggregator, curious/malicious admin, compromised internal service, supply-chain attacker.
Each threat has an ID, mitigation (control), and the test that proves it. Test IDs map to `tests/…` created in the milestone shown. Status: **Planned** until the test exists and passes (tracked in compliance-matrix).

## 1. Data flow list
F1 participant→gateway→participant API; F2 token issuance (client creds); F3 API→consent store; F4 API→router→adapter→telco; F5 telco→adapter response; F6 API→Postgres; F7 API→Redis; F8 API→KMS; F9 API→audit chain + external sink; F10 admin browser→admin UI/API; F11 admin→IdP (OIDC); F12 admin config→runtime config; F13 reporting/rollup worker; F14 CI/CD→build→deploy; F15 logs/telemetry→SIEM.

## 2. STRIDE by boundary
### TB1/TB2 Participant ↔ edge ↔ platform (F1, F2)
| ID | Cat | Threat | Mitigation | Test (milestone) |
|---|---|---|---|---|
| T-001 | S | Stolen/forged access token used | JWT verify (alg pin, iss, aud, exp≤5m, jti), mTLS-bound `cnf.x5t#S256` | sec/token-forgery, bad-sig, alg=none, wrong-aud, expired (M1) |
| T-002 | S | Token replay from another host | Sender constraint: cert thumbprint must match TLS peer cert | sec/token-wrong-cert (M1) |
| T-003 | S | Client auth with weak/shared secret | Only `private_key_jwt`; `jti` single-use; `aud`=token endpoint; short exp; no `client_secret_*` | sec/client-assertion-* (M1) |
| T-004 | T | Request body tampering in transit/proxy | Signed request + body digest | sec/tamper-body (M1) |
| T-005 | R | Participant denies request | Audit w/ signature digest + correlation id | integ/audit-nonrepudiation (M1) |
| T-006 | I | Error/timing reveals number existence | Uniform error codes/shape; constant-ish path; UNAVAILABLE for all failures | sec/no-existence-oracle (M1,M2) |
| T-007 | D | Flood / slow-loris / large body | Gateway/WAF assumed; server header/body/time limits; per-participant limits | sec/limits, load (M1,M3) |
| T-008 | E | Scope escalation (request signal not entitled) | Scope+entitlement check per function | sec/wrong-scope (M1) |
| T-009 | T | Replay of signed request | Timestamp ±60 s + Redis nonce; fail closed if store down | sec/replay, sec/replay-store-down (M1) |
| T-010 | S/T | TLS downgrade / weak ciphers | TLS ≥1.2, 1.3 preferred, AEAD only; HSTS at edge | sec/tls-config (M1) |
| T-011 | T | Mass assignment / unknown fields | Ajv `additionalProperties:false`, no spread into DB | sec/mass-assign (M1) |
| T-012 | T | Unsafe deserialisation / prototype pollution | JSON-only, `__proto__` rejected, no `eval`/YAML | sec/proto-pollution (M1) |
| T-013 | I | BOLA: participant reads another's data/usage/keys/statements | Org from token only; RLS + per-object checks | sec/bola-* across every endpoint (M1+) |
| T-014 | E | BFLA: participant calls admin function | Separate listener/route table; token audience separation | sec/admin-from-participant (M4a) |

### TB3 Participant plane ↔ core / TB6 DB (F3, F6)
| ID | Cat | Threat | Mitigation | Test |
|---|---|---|---|---|
| T-020 | E | App role bypasses RLS / owns tables | `ts_app` NOBYPASSRLS, not owner, FORCE RLS | integ/rls-role-privs (M1) |
| T-021 | I | Tenant leakage with pooled connections | `SET LOCAL` per txn; reset on release; test reuse | integ/rls-pool-reuse (M1) |
| T-022 | T | SQL injection | Parameterised queries only; lint rule; SAST | sec/sqli-fuzz (M1) |
| T-023 | I | Raw MSISDN stored/logged | HMAC hash only; log redaction; scan of DB/logs in tests | sec/no-raw-msisdn-db-logs (M1) |
| T-024 | R | Consent bypass / stale consent | Fail closed; expiry/revocation checked in same txn as use | sec/consent-* (M1) |
| T-025 | I | KYC match inputs retained | Inputs never persisted; test greps DB | sec/kyc-no-store (M2) |
| T-026 | T | Backup/restore tamper or data loss | PITR/backup + tested restore | ops/restore-test (M3) |

### TB5 Platform ↔ telco/aggregator (F4, F5)
| ID | Cat | Threat | Mitigation | Test |
|---|---|---|---|---|
| T-030 | T | Malicious/oversized/malformed telco response (injection, huge JSON, type confusion) | Treat as untrusted: schema validate, size cap, strict types, ignore unknown | sec/malicious-telco-response (M2) |
| T-031 | T | Telco returns inconsistent data to cause false "no swap" | Any invalid/ambiguous → UNAVAILABLE; never default FALSE | sec/signal-safety (M1,M2) |
| T-032 | S | SSRF via admin-configured endpoint or redirects | Endpoint allow-list, DNS pin, private-IP block, no redirects | sec/ssrf (M2,M4a) |
| T-033 | S | Telco impersonation | mTLS + pinned CA/cert; hostname check | sec/telco-cert-mismatch (M2) |
| T-034 | D | Slow/hung telco exhausts resources | 2 s timeout, bulkhead, circuit breaker | fault/timeout, breaker (M3) |
| T-035 | I | Platform leaks participant identity to telco beyond need | Minimal outbound payload; no participant identifiers | integ/outbound-minimisation (M2) |
| T-036 | T | Porting data poisoning (route to attacker telco) | Porting overlay writes need two-person approval + audit; effective-dated | sec/porting-integrity (M2) |
| T-037 | S | Aggregator trusted blindly | Aggregator treated as untrusted telco; response bound to request id | sec/aggregator-mismatch (M2) |

### TB4/TB12 Admin plane (F10–F12)
| ID | Cat | Threat | Mitigation | Test |
|---|---|---|---|---|
| T-040 | S | Admin account takeover | SSO + phishing-resistant MFA (`amr`), no local accounts, fail closed | sec/admin-no-mfa (M4a) |
| T-041 | E | Single admin changes keys/prices/limits/policy/routing | Two-person approval, approver≠requester, DB-enforced | sec/two-person-bypass-* (M4a) |
| T-042 | T | CSRF on admin | Sync token + Origin + SameSite=Strict | sec/csrf (M4a) |
| T-043 | T | XSS in admin UI (e.g. via logged fields, telco names) | Output encoding, CSP nonce, no inline script, JSON-escape | sec/xss-* (M4a,M4b) |
| T-044 | I | Cross-org view by telco/bank users | RLS + server-side authz | sec/org-isolation (M4a) |
| T-045 | R | Admin edits/deletes logs | Append-only, no edit API, DB trigger; admin can't alter | sec/log-immutability (M4a,M4b) |
| T-046 | I | Secret retrievable after creation | Show-once; only hash/public key stored | sec/secret-show-once (M4a) |
| T-047 | E | Session fixation/long sessions | Rotate on login, idle+absolute timeout | sec/session-* (M4a) |
| T-048 | I | Unmasking of numbers via export/search | No unmask function; export masked; audited | sec/no-raw-msisdn-ui-export (M4b) |
| T-049 | T | Config rollback used to re-introduce weak setting | Rollback is itself a gated change | sec/rollback-gate (M4a) |
| T-050 | E | Insider kill-switch abuse (DoS) | Kill switch audited; alert on use; dual approval to lift for telco-wide | integ/killswitch (M4a) |

### TB7–TB10 Supporting services
| ID | Cat | Threat | Mitigation | Test |
|---|---|---|---|---|
| T-060 | D | Redis down → bypass limits/replay | Fail closed for replay; conservative local fallback limiter | sec/redis-down (M1,M3) |
| T-061 | I | Secrets in logs/images/repo | gitleaks, log redaction, generated local secrets | ci/secret-scan, sec/log-redaction (M0) |
| T-062 | T | KMS key compromise / no rotation | Key versions, rotation procedure tested | integ/key-rotation (M1) |
| T-063 | T | Audit chain tampering | Hash chain + external copy + verifier | sec/audit-tamper (M1) |
| T-064 | I | Telemetry attributes include PII | Attribute allow-list + test | sec/telemetry-pii (M1) |
| T-065 | R | Metering altered to change billing | Append-only usage; compensating rows; reconciliation test | integ/metering-reconcile (M3) |
| T-066 | T | Dashboard disagrees with usage | Rollup reconciliation test | integ/dashboard-reconcile (M4b) |

### TB11 Supply chain (F14)
| ID | Cat | Threat | Mitigation | Test |
|---|---|---|---|---|
| T-070 | T | Vulnerable/malicious dependency | Lockfile, exact pins, `npm audit`/OSV, `--ignore-scripts`, Dependabot | ci/vuln-dep-blocked (M0) |
| T-071 | T | Secret committed | gitleaks + GitHub secret scanning push protection | ci/seeded-secret-blocked (M0) |
| T-072 | T | Compromised CI action | Actions pinned by SHA; least-privilege `permissions:` | ci/workflow-lint (M0) |
| T-073 | T | Image tamper / root container | Non-root, read-only, signed, Trivy | ci/image-scan (M0) |
| T-074 | E | Deploy token misuse (Vercel) | Secrets only in prod job, protected branch/environment, only static portal deployed | review (M0) |
| T-075 | I | Preview deployments expose unreleased content | Previews disabled; production only | ci/deploy-config check (M0) |

## 3. Abuse cases
| ID | Abuse case | Controls | Test |
|---|---|---|---|
| AB-01 | Bank enumerates number ranges to learn who has a SIM swap / who is a subscriber | Per-participant/hash rate limits, sequential-range & high-miss-ratio detection, alert, suspend, uniform responses | sec/enumeration (M3) |
| AB-02 | Bank queries without real customer relationship (purpose abuse) | Purpose code + consent ref mandatory and checked; audit; anomaly alert | sec/consent-* (M1) |
| AB-03 | Collusion: one insider requests and approves price/limit change | Approver≠requester, role-gated, DB-enforced | sec/two-person (M4a) |
| AB-04 | Telco returns "no swap" to hide fraud | Cross-checks, timeouts → UNAVAILABLE; conformance tests; alert on anomalous FALSE ratio | sec/signal-safety, anomaly (M2,M3) |
| AB-05 | Billing fraud: inflate usage / dodge charges via failures | Append-only metering; charge only on success; reconciliation | integ/metering (M3) |
| AB-06 | Participant probes for another participant's usage/keys/statements | BOLA tests on every resource | sec/bola (M1+) |
| AB-07 | Attacker uses stolen cert but no key/token | Needs token bound to same cert + private_key_jwt | sec/stolen-cert (M1) |
| AB-08 | Admin attempts to mass-export logs to infer numbers | Masked-only, export role-restricted + audited + rate-limited | sec/export (M4b) |
| AB-09 | Cache-timing inference of number's telco via latency | Normalised minimum response time floor on error paths | sec/timing (M5) — `m5-adversarial.test.ts` |
| AB-10 | Malicious telco onboarding with endpoint pointing to internal metadata IP | Endpoint allow-list & SSRF guard, approval | sec/ssrf (M4a) |

## 4. Residual risk register (initial; owners proposed)
| ID | Risk | Proposed owner | Status |
|---|---|---|---|
| R-001 | Neon in Singapore: data outside Malaysia (PDPA 2024 cross-border, RMiT outsourcing). Blocks live data. | DPO + Legal | Open |
| R-002 | Vercel cannot enforce participant mTLS; gateway/host not chosen | CTO/Security | Open |
| R-003 | No HSM; KMS is mocked | Security | Open |
| R-004 | Standards texts not all verified | Compliance | Open |
| R-005 | WAF/DDoS assumed, not implemented in repo | Infra | Open |
| R-006 | No independent pen-test/code review yet | CISO | Open |
| R-007 | Runtime image uses Debian slim + `apt-get upgrade` because the distroless base shipped unpatched OpenSSL (Trivy, 2026-11-27); revisit when distroless is patched | Platform | Open |

## Status update after M3 (tests exist and pass in the sandbox)
Implemented with tests: T-007 (limits), T-034 (timeouts, bulkhead, breaker), T-060 (limiter/replay store down fails closed), T-065 (append-only metering, immutable statements, reconciliation), AB-01 (enumeration: detection, uniform answers, alert, suspension), AB-05 (billing integrity: failures never charged; double-billing guard). New residual items: R-008 breaker state per process; R-009 fixed-window rate limits.

## Status update after M4a (tests exist and pass in the sandbox)
T-014, T-032 (admin side), T-036, T-040, T-041, T-042, T-043, T-044, T-045 (admin cannot edit audit/history), T-046 (show-once), T-047, T-049, T-050, AB-03, AB-10 now have passing tests (m4a-auth, m4a-approval, m4a-onboarding, m4a-isolation, DAST admin).
New residual risks: R-010 telco conformance results are asserted by the platform process; R-011 the portal shares the number-hashing key; R-012 DNS answers for telco endpoints are not pinned; R-013 telco certificate pinning per connection not implemented; R-014 single-person safety actions (engage/revoke/suspend) by design.
| R-010 | Telco conformance results are asserted by the portal process, not computed by the database | Platform + Security | Open |
| R-011 | Number-hashing key shared with the admin process (token-signing keys are not) | Security | Open |
| R-012 | No DNS pinning between endpoint validation and connection (rebinding) | Platform | Open |
| R-013 | No per-telco certificate pinning/onboarding workflow | Integration | Open |
| R-014 | Single-person safety actions (engage kill switch, revoke credential, suspend org) | Operations | Accepted by design, alerts in M4b |
| R-015 | Admin rate-limit counters are in-process (not shared across admin instances) | Platform | Open |

## Status update after M4b (tests exist and pass in the sandbox)
T-043 (XSS through log content), T-045 (logs and audit cannot be edited), T-048 (no unmask; no numbers in any screen or export), T-064 (no numbers in logs/telemetry; CHECK constraints), T-066 (dashboards reconcile with usage records), AB-08 (exports role-restricted, audited, masked, formula-safe).
| R-016 | Percentiles are bucket upper bounds; availability is a platform-side approximation | Platform | Accepted, documented |
| R-017 | No shipping of SIEM events to an external SIEM | Security Operations | Open |
| R-018 | No pager/e-mail delivery for alerts | Operations | Open |
| R-019 | Request-log write is best effort (gaps possible if the write fails; the failure is logged) | Platform | Accepted, documented |
| R-020 | No partitioning/archival or capacity testing of request log and rollups | Platform | Open (M5 load test) |

## Status update after M5 (adversarial review of the sandbox; see `docs/reports/M5.md`)
Every T- and AB- entry above is now mapped to the tests or CI controls that prove it in `docs/release/traceability.md` (generated; `tests/unit/traceability.test.ts` fails if an entry has no mapping or a mapped test disappears). The review covered every OWASP API Security Top 10 2023 category (`tests/security/m5-adversarial.test.ts`).
New findings, each fixed with a regression test that was shown to fail without the fix:
* **F-M5-1 (T-007, API4)** audit amplification: every refused request, including rate-limited ones, wrote a serialised hash-chained audit row, so rate limiting did not protect the database. Rate-limited and oversized requests are now counted in the security log and request log only.
* **F-M5-2 (API4/API6)** consent registration was not quota-limited (consent farming, storage exhaustion). Added a per-organisation quota that fails closed when the limiter store is down.
* **F-M5-3 (AB-09, T-006)** refusals and telco-less answers returned measurably faster than normal answers. Added a response-time floor (default 40 ms) for error paths and answers with no telco call; rate-limit shedding is deliberately not delayed.
* **F-M5-4 (T-064)** OpenTelemetry was in the plan and the architecture but not implemented, and T-064 had no test. Implemented tracing with a fail-closed attribute allow-list and a second filter at the exporter; found by my own test that a UUID with eight consecutive digits would have been dropped as "phone-like" (now validated as a UUID).
* **F-M5-5 (T-070)** services were started with `npx tsx` that fetched an unpinned `tsx` at run time; `tsx` is now a pinned dev dependency.
* **F-M5-6 (sandbox)** the participant sandbox did not set `TS_ALLOW_LOOPBACK`, so the registry refused the mock telcos ("no adapter") and the DAST exercised only the UNAVAILABLE path for telco calls; setup now writes it into the participant environment (sandbox only).
* **F-M5-7 (T-070, supply chain)** `npm sbom --omit dev` silently dropped a production dependency (`@opentelemetry/api`, which is also an optional peer of the test runner), so the production-only SBOM was incomplete. The SBOM is now generated with dev dependencies included (a superset) and `tests/unit/release.test.ts` compares it with `package.json`.
New residual items R-021..R-025 are in `docs/release/residual-risks.md`, which is now the consolidated register.
