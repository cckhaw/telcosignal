# PLAN — PayNet Telco Signal API Platform (reference implementation, sandbox only)

> Synthetic data only. No real telco, bank or customer data, credentials or branding.
> NOT approved for live data. No certification or compliance is claimed anywhere in this repo.

## 1. Priority order (conflict rule)
1 Security → 2 Privacy/regulatory → 3 Correctness → 4 Availability/performance → 5 Features/speed.
If a requirement would weaken 1 or 2, work stops on that item and it is logged in
`docs/decisions-needed.md` (the owner reviews at the end; the item is not built in a weakened form).

## 2. How this plan interprets the working agreement
| Instruction | Interpretation |
|---|---|
| "Write plan + threat model, wait for approval before code" **vs** later "review only at the very end; auto-commit and merge" | The later, more specific instruction is taken as the standing approval to proceed through phases. The threat model is still written FIRST and every milestone is traced back to it. Recorded as decision D-001 so it can be reversed. |
| "Ask before creating any cloud resource or incurring cost" | No Neon project, hosted Redis, or other billable resource is created. Vercel/GitHub secrets already provisioned by the owner are used **only** for the Production deploy workflow requested. Neon work is written + tested against local Postgres; Neon provisioning is a blocked item (D-002). |
| "Before any Vercel deployment prove participant mTLS can be enforced; else propose a gateway; do not drop the control" | Vercel Functions cannot terminate participant client-certificate mTLS. Therefore the **participant API and admin plane are NOT deployed to Vercel**. Only the static public developer portal / docs (no participant data, no secrets) is deployed to Vercel Production. Gateway proposal in `docs/architecture.md §9`. Decision D-003. |
| "No Preview deployments; only Production; delete older deployments after latest is live" | `.github/workflows/deploy-production.yml`: triggers on push to `main` only (i.e. on merge); Vercel git-integration previews must be disabled (`vercel.json` `git.deploymentEnabled`); workflow deploys with `--prod`, waits for READY, then deletes all other deployments of the project. |
| "If 5-hour limit is hit, wait and continue" | Work is committed per milestone so it is resumable from git. |

## 3. Stack
TypeScript, Node 22 LTS, Fastify, Postgres (local for dev/test; Neon aws-ap-southeast-1 later, blocked on approval),
Redis (local only; behind `ReplayStore`/`RateLimitStore` interfaces), OpenAPI 3.1, Docker Compose, OpenTelemetry.
Modular monolith, **two separate Fastify listeners** (participant :8443 mTLS, admin :9443 isolated), plus mock telcos A/B/C and mock aggregator as separate processes.

Libraries (proven, no hand-rolled crypto/token handling): `fastify`, `jose` (JWT/JWS/JWK, private_key_jwt, DPoP-free mTLS `cnf.x5t#S256`), `ajv` (strict schema), `pg`, `ioredis`, `pino`, `@opentelemetry/*`, `vitest`, `undici` (outbound with allow-list agent), Node `crypto` (HMAC-SHA256, AES-256-GCM, via a KMS interface — no custom primitives), `@node-rs/argon2` not needed (no passwords: SSO only).

## 4. Repository layout
```
PLAN.md  docs/  src/{platform,participant-api,admin-api,admin-ui,adapters,router,consent,audit,metering,kms,db,common}
mock/{telco-a,telco-b,telco-c,aggregator,idp}  migrations/  openapi/  deploy/  tests/{unit,integration,security,e2e,load}
.github/workflows/  docker/  scripts/
```

## 5. Milestones (security controls + negative tests ship WITH each feature)
| # | Scope | Acceptance (from brief) |
|---|---|---|
| M0 | PLAN, architecture, threat model, compliance matrix, KPI doc, secure CI (gitleaks, Semgrep SAST, npm audit/OSV, Trivy image+IaC, CodeQL, SBOM, DAST stub wired to sandbox), Vercel prod workflow | seeded test secret **and** vulnerable dependency both blocked (proved on throw-away branch/PR, evidence in `docs/reports/`) |
| M1 | DB + RLS + roles, KMS iface, audit hash chain, OAuth AS (client-credentials, private_key_jwt, mTLS-bound tokens), consent, SIM swap via Telco A | bad token, wrong scope, replay, missing consent, cross-participant access all rejected |
| M2 | Telco B (proprietary), C (via aggregator), router + number porting, registry, device swap, call forwarding, KYC match | porting routes correctly; malicious telco response rejected |
| M3 | Rate limits, enumeration detection, circuit breakers, fault injection, append-only metering, pricing, statements | enumeration + fault-injection pass; statements reconcile |
| M4a | Admin portal: SSO+WebAuthn (mock IdP), RBAC, config versioning, two-person approval, onboarding state machines, credentials, kill switches | mock telco + mock bank onboarded end-to-end; 2-person rule unbypassable; kill switches; org isolation |
| M4b | Logs, troubleshooting traces, alerts, dashboards/KPIs/rollups, developer portal, runbooks | seeded failure traced by correlation id; no raw MSISDN in any screen/export; dashboard == usage records |
| M5 | Adversarial review of own sandbox vs every threat-model ID and API Top 10; fixes + regression tests; load test (200 rps, p95 overhead <100 ms) | all findings fixed or risk-registered |

After each milestone: run all tests/scans → record in `docs/reports/Mx.md` (only what was actually run) → commit → PR → CI → merge to `main` → next milestone.

## 6. Standards mapping
Tracked in `docs/compliance-matrix.md`. Source texts that could not be fetched are marked **unverified**. No certification claimed.

## 7. Environments & data
Local (compose) → CI (ephemeral Postgres/Redis) → sandbox. Separate DB roles: `ts_migrator` (owns schema), `ts_app` (no ownership, `NOBYPASSRLS`), `ts_reporting` (read-only, RLS-subject). Synthetic data only; phone numbers from reserved fictitious ranges. Neon (Singapore) residency/cross-border risk is **open and blocks live data** (R-001).

## 8. Out of scope / later
Fraud scores, real telco links, payments. Later: Number Verification, event subscriptions, telco-only signals.

## 9. Release gate
Platform is NOT approved for live data until humans complete: independent pen-test + code review, remediation + retest, PDPA assessment, legal/regulatory review, DR test, named risk-owner sign-off.
