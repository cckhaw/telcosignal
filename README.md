# Telco Signal API Platform — reference implementation (sandbox)

> **SANDBOX ONLY. SYNTHETIC DATA ONLY. NOT APPROVED FOR LIVE DATA.**
> No certification, compliance or regulatory approval is claimed anywhere in this repository. The platform must not process real customer
> data until the human gates in [`docs/release/human-gates.md`](docs/release/human-gates.md) are complete and a named risk owner has signed off.

One API for four telco signals — **SIM swap, device swap, call-forwarding and KYC match** — with participant onboarding and consent, routing
(including number porting) to three mock telcos (A: CAMARA-style, B: proprietary, C: through a mock aggregator), a signal registry, circuit
breakers, append-only metering, pricing and settlement statements, an admin portal, dashboards, a developer portal and runbooks.

Priority order when requirements conflict: **1 security, 2 privacy/regulatory, 3 correctness, 4 availability/performance, 5 features.**

## Status

All milestones M0–M5 are implemented and merged to `main`, followed by a self-conducted security audit and penetration test (M6, [report](docs/security/audit-and-pentest-report.md)); see [`docs/reports/`](docs/reports) for the evidence of each and
[`docs/release/README.md`](docs/release/README.md) for the release-gate package (threat-model traceability, test and scan report, load results,
SBOM, residual-risk register with proposed owners, runbooks).

| Milestone | Scope | Report |
|---|---|---|
| M0 | Threat model, compliance matrix, secure CI, production-only Vercel deploy | [M0](docs/reports/M0.md) |
| M1 | Identity (mTLS, `private_key_jwt`, bound tokens, signed requests), consent, audit chain, KMS, SIM swap | [M1](docs/reports/M1.md) |
| M2 | Telcos B and C, router and porting, registry, device swap, call forwarding, KYC match | [M2](docs/reports/M2.md) |
| M3 | Rate limits, enumeration detection, circuit breakers, metering, pricing, statements | [M3](docs/reports/M3.md) |
| M4a | Admin portal, two-person approval enforced in the database, onboarding | [M4a](docs/reports/M4a.md) |
| M4b | Logs and traces, dashboards, alerts, retention, OpenAPI, developer portal, runbooks, tested restore | [M4b](docs/reports/M4b.md) |
| M5 | Adversarial review (OWASP API Top 10 2023 + every threat-model entry), fixes, OpenTelemetry, 200 rps load test, release package | [M5](docs/reports/M5.md) |
| M6 | Security audit (static, manual, database, CI/CD) and black-box penetration test; 11 defects fixed with regression tests. Self-conducted: not a substitute for an independent test | [report](docs/security/audit-and-pentest-report.md) |

What is **not** done is listed, with proposed owners, in [`docs/release/residual-risks.md`](docs/release/residual-risks.md). The largest items: hosting for the
participant mTLS endpoint (Vercel cannot terminate client certificates), data residency of Neon in Singapore, a real KMS/HSM, WAF/DDoS, an
independent penetration test and code review, and verification of the regulatory texts (all marked *unverified* in the compliance matrix).

## Architecture in one page

Modular monolith (TypeScript, Node 22, Fastify) with **two separate listeners** and no shared routes:

* **Participant plane** (`src/participant-api`, :8443): mutual TLS (TLS 1.3 preferred, 1.2 minimum, AEAD only) → OAuth client credentials with
  `private_key_jwt` → access token bound to the client certificate (`cnf.x5t#S256`, ≤5 min) → signed request (compact JWS over method, path,
  body digest, time, `jti`) with Redis replay protection (fails closed) → scope and entitlement → per-participant, per-signal, per-subject and
  per-telco quotas → consent check → routing → adapter → telco. Every refusal is uniform and reveals nothing about the number.
* **Admin plane** (`src/admin`, :9443): server-rendered, no JavaScript (CSP `default-src 'none'`), OIDC with mandatory phishing-resistant MFA
  (`acr`/`amr` checked, fail closed), no default accounts, seven roles, row-level security for restricted bank/telco users, and a **database-enforced
  two-person rule** for every high-risk change (pricing, limits, entitlements, credentials, routing, porting, kill-switch lifting, policy).
* **Worker** (`src/worker`): rollups, alert evaluation and escalation, retention deletion.
* **Data**: Postgres with roles and forced row-level security, hash-chained append-only audit log with an external copy, keyed HMAC subject hashes
  (numbers are never stored or logged), Redis for replay/limits, mock KMS (`LocalKms`).
* **Signal safety**: the result is `TRUE | FALSE | UNAVAILABLE | NOT_SUPPORTED`. `FALSE` only comes from an explicit, valid negative answer
  from the telco; errors, timeouts, hostile or unsupported answers are never `FALSE`, and failures are never billed.

Details: [`docs/architecture.md`](docs/architecture.md) · [`docs/threat-model.md`](docs/threat-model.md) · [`docs/admin-portal.md`](docs/admin-portal.md) ·
[`docs/compliance-matrix.md`](docs/compliance-matrix.md) · [`docs/kpi-definitions.md`](docs/kpi-definitions.md) · [`PLAN.md`](PLAN.md).

## Quick start (local sandbox)

Prerequisites: Node 22, Postgres 16 (superuser URL for setup), Redis. `docker compose` is provided in `deploy/compose.sandbox.yml` but has never
been executed (unverified).

```bash
npm ci                                              # installs exact, pinned dependencies (lifecycle scripts disabled)
export TS_ADMIN_URL=postgres://postgres:<pw>@127.0.0.1:5432/postgres TS_REDIS_URL=redis://127.0.0.1:6379/0
npm run sandbox:setup                               # roles, database, PKI, KMS dirs, bootstrap admins -> .sandbox/ (gitignored, 0700)
set -a; . .sandbox/env; set +a
npm run sandbox:mocks &                             # mock telcos A, B and aggregator (synthetic)
npm run sandbox:start &                             # participant API on :8443 (mTLS)
set -a; . .sandbox/admin.env; set +a
npm run sandbox:idp & npm run sandbox:admin &       # mock IdP :9444 and admin portal :9443
set -a; . .sandbox/worker.env; set +a; npm run worker &
npm run dast && npm run dast:admin                  # black-box checks against the running sandbox
```

Participant simulator credentials are in `.sandbox/participants.json` (synthetic, never reuse). Full runbook: [`docs/runbooks/sandbox.md`](docs/runbooks/sandbox.md).
Note: Postgres roles are cluster-wide, so running the test suite resets role passwords and breaks an already-running sandbox; re-run `sandbox:setup`.

## Commands

| Command | What it does |
|---|---|
| `npm run typecheck` / `npm run lint` | TypeScript (strict) and ESLint |
| `TS_TEST_ADMIN_URL=postgres://postgres:<pw>@127.0.0.1:5432/postgres npm test` | Full suite: fresh database per test file, real TLS/mTLS, mock telcos and IdP, real PKI |
| `npm run dast`, `npm run dast:admin`, `npm run pentest` | Black-box DAST and penetration test against a running sandbox (own sandbox only): functional abuse checks, TLS downgrade, raw HTTP abuse, slow clients, floods, parser attacks, injection, cross-tenant |
| `npm run load` | Open-loop load test, default 200 rps for 60 s (`tests/load/run.ts`); see [load results](docs/release/load-results.md) |
| `npm run gen:openapi`, `npm run gen:portal` | Regenerate the OpenAPI 3.1 document and the static developer portal (a test fails if they drift) |
| `npm run gen:traceability` | Regenerate [`docs/release/traceability.md`](docs/release/traceability.md) |
| `npm run sbom` | CycloneDX SBOM into `docs/release/` (includes dev dependencies as a superset: `npm sbom --omit dev` dropped a production dependency, finding F-M5-7) |
| `npm run audit:deps` | `npm audit` (high and above) |

## Security and process rules this repository follows

* No secrets in code, images or logs. Secrets are generated at setup into a gitignored directory; gitleaks and GitHub secret scanning run in CI.
* Dependencies are pinned exactly, lifecycle scripts are disabled, new package versions must be ≥7 days old (`.npmrc`), actions are pinned by SHA.
* CI (`.github/workflows/ci.yml`): secret scan, Semgrep SAST, CodeQL, dependency scan, build and test with Postgres and Redis, container and IaC scan
  (Trivy), workflow lint, DAST against the started sandbox, and a `gate` job that requires all of them. No test is skipped or weakened to make a build pass.
* Deployment (`.github/workflows/deploy-production.yml`): **production only, no previews**, triggered by a merge to `main`. Only the static developer portal
  (`portal/`) is deployed to Vercel; the participant and admin planes are **not** (see decision D-003). After the new deployment is READY, older deployments
  are deleted (`scripts/vercel-cleanup.mjs`).
* Branch protection on `main` requiring the `gate` check is an owner action (H-001, see [`docs/decisions-needed.md`](docs/decisions-needed.md)).

## Repository map

```
src/participant-api  src/admin  src/worker  src/identity  src/consent  src/router  src/adapters  src/resilience  src/ratelimit  src/abuse
src/metering  src/audit  src/kms  src/db  src/telemetry  src/ops  src/common      application code
mock/                synthetic telcos A/B, aggregator, IdP
migrations/          001–005 SQL (schema, RLS, roles, audit, registry, limits/billing, admin/approvals, observability)
openapi/             generated participant API (3.1) + vendored, pinned, checksummed CAMARA definitions
portal/              generated static developer portal (the only thing deployed to Vercel)
tests/               security/ unit/ dast/ load/ helpers/
docs/                architecture, threat model, compliance matrix, runbooks, privacy, reports, release package
scripts/ deploy/ docker/ .github/
```

## Where to look first

* Reviewing security: [`docs/security/audit-and-pentest-report.md`](docs/security/audit-and-pentest-report.md) (what was attacked, what was found, what was not tested) → [`docs/threat-model.md`](docs/threat-model.md) → [`docs/release/traceability.md`](docs/release/traceability.md) (each threat → the test that proves it) → [`docs/reports/M5.md`](docs/reports/M5.md).
* Operating it: [`docs/runbooks/README.md`](docs/runbooks/README.md).
* Integrating a bank or telco: the generated developer portal in `portal/` and [`openapi/participant.yaml`](openapi/participant.yaml).
* Deciding what is next: [`docs/decisions-needed.md`](docs/decisions-needed.md) and [`docs/release/human-gates.md`](docs/release/human-gates.md).
