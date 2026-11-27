# Privacy impact assessment: engineering inputs
This is NOT a completed PIA. It lists facts, risks and mitigations for the assessor. Legal tests under the Malaysian PDPA (as amended 2024) are unverified here.
## Processing description
Participants ask whether a subscriber's SIM or device changed recently, whether call forwarding is active, or whether given identity attributes match, to prevent fraud. The platform routes the request to the serving telco, applies consent and purpose checks and returns a four-state result.
## Necessity and proportionality (engineering view)
Purpose code and consent reference mandatory per request; entitlement per organisation, signal and purpose; minimal outbound data; no caching; no storage of numbers or KYC inputs; per-subject and per-participant rate limits; enumeration detection; kill switches.
## Risks and mitigations
| Risk | Mitigation | Residual |
|---|---|---|
| Bulk lookup or enumeration of numbers | Limits, distinct-subject and range heuristics, uniform answers, alerts, suspension | Thresholds are placeholders; fixed-window limits |
| Disclosing whether a number exists | One answer for unknown, unrouted and failed lookups | Timing side channels not yet measured (M5) |
| Misuse of purpose | Purpose codes, entitlements, audit, anomaly alerts | Relies on participant-supplied consent references |
| Data exposure from logs/backups | No numbers or KYC stored anywhere (constraints + tests); keys stored apart | Key custody is mock |
| Cross-border transfer | Documented (residency map) | **Open, blocks live data (R-001)** |
| Insider access | Role-based, two-person for high-risk changes, audit of every view, no unmask function, restricted tenant views | Single-person safety actions by design (R-014) |
| False reassurance from a signal | Four-state results; FALSE only on an explicit valid negative | Telco data quality is out of scope |
## Open items for the assessor
Lawful basis and consent evidence standards with participants; data-subject rights workflow; retention periods for usage records and the audit log; transfer mechanism; DPO sign-off; regulator engagement.
