# Test and scan report (M5 release candidate)

> NOT APPROVED FOR LIVE DATA. Only checks that were actually run are listed. "CI" results are for the commit named; a later commit may differ.

## Executed locally (2026-11-27, Node 22.23, Postgres 16, Redis 7; synthetic data)
| Check | Command | Result |
|---|---|---|
| Type check | `npx tsc --noEmit` | clean |
| Lint | `npx eslint .` | clean |
| Test suite | `TS_TEST_ADMIN_URL=… npx vitest run` | 21 files; last complete run 332 passed, 1 failed (a release-package test, fixed by adding the M5 report; the 14 unit tests then passed); full-suite result of the final commit is the CI `build-test` job below |
| Dependency audit | `npm audit` | 0 vulnerabilities |
| Pin check | `node scripts/check-pins.mjs` | all dependency pins exact |
| DAST, participant API | `npx tsx tests/dast/run.ts` against the running sandbox | 53/53 |
| DAST, admin portal | `npx tsx tests/dast/admin.ts` against the running sandbox | 72/72 |
| Load, baseline | `tests/load/run.ts` 200 rps x 60 s | 12 000/12 000 answered, overhead p95 16 ms |
| Load, 5 % faulty telco | same with `LOAD_FAULT_PCT=5` | 12 000/12 000 answered, overhead p95 19 ms, 595 UNAVAILABLE, no fabricated FALSE |
| Regression proof for the M5 fixes | `m5-adversarial.test.ts` with the fixes reverted | 3 tests fail (audit flood, consent quota, timing floor); pass with the fixes |

Not run locally (CI only): gitleaks, Semgrep, CodeQL, Trivy image/IaC scan, actionlint. They are not installed in this environment.

## CI (GitHub Actions `ci.yml`, job `gate` requires all)
Jobs: secret-scan (gitleaks), sast (Semgrep), codeql, dependency-scan, build-test (Postgres + Redis services), container-iac-scan (Trivy), workflow-lint, dast (starts the sandbox and runs both DAST runners), gate. Results for the M5 pull request are recorded in the PR and summarised here when it merges.

## Not done
No independent penetration test, code review, third-party DAST (ZAP/Nuclei with client certificates), SAST rule-set review, or signed build/attestation (SC-07). See `human-gates.md` and `residual-risks.md`.
