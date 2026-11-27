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
| ID-xx … AUD-xx … PRIV-xx … | Remaining requirement rows are added per milestone with the feature | | | | not met (planned M1–M5) |
