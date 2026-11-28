# M8 security audit (2026-11-28): re-audit after the second-wave signals

> **Self-conducted** by the author of the code, with the same blind spots as any self-review. It is **not** the independent penetration test and code review that gates G1 and G2 require, and nothing here is a certification or a statement of compliance. Sandbox, synthetic data only. NOT approved for live data.

Scope: `main` at `588c979` (M7 merged). Method and results below; the earlier full audit is [`audit-and-pentest-report.md`](audit-and-pentest-report.md) (M6).

## What was run

| Check | Result |
|---|---|
| `npm audit` (production and all dependencies) | 0 vulnerabilities |
| Semgrep (`p/typescript`, `p/nodejs`, `p/owasp-top-ten`, `p/secrets` plus the repository's own rules), 152 rules, 151 files | 0 findings |
| Secret scan of the full git history (connection strings with passwords, private keys, cloud and token prefixes) | Only the documented ephemeral CI database credential and `<pw>` placeholders |
| GitHub Actions: pins by commit SHA, token permissions | Every `uses:` is pinned by SHA; workflow permissions are `contents: read` except the code-scanning job |
| Live DAST against the started sandbox (`npm run dast`), now including the four new routes | 61 of 61 checks passed |
| Live penetration test (`tests/pentest`: TLS downgrade, raw HTTP abuse, slow clients, floods, parser attacks, injection, cross-tenant) | 72 of 72 checks passed (raw results: `pentest-results.json`) |
| Full automated suite | 28 files, 393 tests passed |
| New: seeded fuzzing of the four second-wave endpoints through the full authenticated pipeline | 1 defect found and fixed (F-M8-1) |
| Manual review of the M7 diff (validators, limiter, adapters, mocks, migration, admin console, redaction) | No further defects; 2 observations below |

Dependencies with newer releases exist (`undici` 8.14.0, `@opentelemetry/sdk-trace-base` 2.12.1, `eslint` 10.16.0, `@opentelemetry/api` 1.10.0) but none is flagged by `npm audit`; they follow the normal update path (minimum package age of seven days).

## Finding fixed

| ID | Severity | Finding | Fix and proof |
|---|---|---|---|
| F-M8-1 | Low | A signed POST with **no body** (or no parsed content type) to any authenticated POST route (every signal check and consent registration) answered **500 INTERNAL** instead of 400. The request-signature check received an undefined body. No data was exposed and only an authenticated, signing client could trigger it, but a client-triggerable 500 counts as a server error in the dashboards and alerts, and can feed the circuit and error-rate signals. Predates M7. | `bodyBuf(req)` treats a missing body as an empty buffer so every later step answers 400 `INVALID_REQUEST`. Regression: `tests/security/m8-audit-fuzz.test.ts` ("a signed POST with no body used to be a 500"), proven failing before the fix. |

## Observations (not defects; recorded, not fixed)

* **O-M8-1, billing blocks on a missing price (availability).** If an organisation is entitled to a signal for which its price plan has no price, the statement run reports "no price for <signal>" and generates **no statement for that organisation at all** (it fails closed rather than under-billing). With four new signals this is easy to trigger by granting an entitlement before adding prices. Recommend a check at entitlement or plan-assignment time. Recorded as R-033.
* **O-M8-2, location triangulation remains possible for a patient participant** (already R-029): the cap is per organisation and subject, not across organisations.

## Not tested, and what that means

Independent testing; real telcos; real KMS or HSM; the hosting that will terminate participant mutual TLS; DDoS and WAF; the legal basis for the new signals; the admin plane's identity provider (a mock). Gates G1 to G10 in [`../release/human-gates.md`](../release/human-gates.md) remain open.
