# Release-gate package (M5)

> **NOT APPROVED FOR LIVE DATA.** Read [`human-gates.md`](human-gates.md) first. Nothing here is a certification or a statement of compliance.

| Deliverable (from the brief) | Where |
|---|---|
| Threat model | [`../threat-model.md`](../threat-model.md) |
| Threat model → proof (every T-/AB- entry → the test or CI control) | [`traceability.md`](traceability.md) (generated; checked by `tests/unit/traceability.test.ts`) |
| Compliance matrix (standards marked unverified) | [`../compliance-matrix.md`](../compliance-matrix.md) |
| Test and scan reports | [`test-and-scan-report.md`](test-and-scan-report.md), per-milestone reports in [`../reports/`](../reports) |
| SBOM (CycloneDX; includes dev dependencies as a superset, see F-M5-7) | [`sbom.cdx.json`](sbom.cdx.json) (`npm run sbom`) |
| Load test results | [`load-results.md`](load-results.md), raw files in [`load/`](load) |
| Runbooks | [`../runbooks/`](../runbooks) |
| Residual-risk register with proposed owners | [`residual-risks.md`](residual-risks.md) |
| Plain statement that the platform is NOT approved for live data, and the human gates | [`human-gates.md`](human-gates.md) |
| Adversarial review of my own sandbox (OWASP API Top 10 2023 + every threat-model entry) | [`../reports/M5.md`](../reports/M5.md) |
| Open decisions for the owner | [`../decisions-needed.md`](../decisions-needed.md) |

Regenerate: `npm run gen:traceability`, `npm run sbom`, `npm run gen:openapi`, `npm run gen:portal`. The SBOM is regenerated (new serial number and timestamp) each time.
