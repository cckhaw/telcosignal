# Residual risk register (release gate)

Owners are **proposed**; nobody has accepted them. A risk is only "accepted" when its owner says so in writing (gate G8 in `human-gates.md`).
Severity is my own qualitative judgement for a *live-data* deployment (H high, M medium, L low); none of these block the sandbox.
R-001..R-020 were logged in earlier milestones (`threat-model.md`); R-021..R-025 are new in M5.

| ID | Risk | Sev | Proposed owner | Status / next step |
|---|---|---|---|---|
| R-001 | Neon in Singapore: data outside Malaysia (PDPA 2024 cross-border transfer, RMiT outsourcing/cloud). Only synthetic data is allowed on it. | H | DPO + Legal | Open: legal decision before any live data (G3) |
| R-002 | Vercel cannot terminate participant client certificates; the participant mTLS endpoint has no chosen host/gateway | H | CTO / Security | Open (D-003): choose gateway or host that enforces mTLS; the control is not dropped |
| R-003 | No HSM; KMS is mocked (`LocalKms`, files in a 0700 directory) | H | Security | Open: real KMS/HSM behind the `Kms` interface |
| R-004 | Standards and regulatory texts not verified in this repo | H | Compliance | Open (G7) |
| R-005 | WAF/DDoS protection assumed at the edge, not implemented | H | Infrastructure | Open |
| R-006 | No independent pen test or code review | H | CISO | Open (G1, G2). M5 is a self-review |
| R-007 | Runtime image is Debian slim + `apt-get upgrade` because the distroless base shipped unpatched OpenSSL when scanned | M | Platform | Open: revisit when distroless is patched |
| R-008 | Circuit-breaker state is per process | M | Platform | Open: share state or accept per-instance behaviour |
| R-009 | Rate limits are fixed windows (burst at window edges up to 2x) | L | Platform | Open |
| R-010 | Telco conformance results are asserted by the portal process, not computed by the database | M | Platform + Security | Open |
| R-011 | Number-hashing key shared with the admin process (token-signing keys are not) | M | Security | Open |
| R-012 | No DNS pinning between endpoint validation and connection (rebinding) | M | Platform | Open |
| R-013 | No per-telco certificate pinning/onboarding workflow | M | Integration | Open |
| R-014 | Single-person safety actions (engage kill switch, revoke credential, suspend org) | M | Operations | Accepted by design: alerts exist (M4b); abuse is detectable, not impossible |
| R-015 | Admin rate-limit counters are in-process (not shared across admin instances) | L | Platform | Open |
| R-016 | Percentiles are histogram bucket upper bounds; availability is a platform-side approximation | L | Platform | Accepted, documented |
| R-017 | No shipping of SIEM events to an external SIEM | M | Security Operations | Open |
| R-018 | No pager/e-mail delivery for alerts | M | Operations | Open |
| R-019 | Request-log write is best effort (gaps possible; the failure is logged) | L | Platform | Accepted, documented |
| R-020 | No partitioning/archival of the request log and rollups | M | Platform | Open: M5 measured growth (see load results), not capacity |
| R-021 | OpenTelemetry spans are emitted through an allow-list but no OTLP exporter is bundled; the only exporter is `console` (sandbox) | M | Platform + Security Operations | Open: choose collector, add exporter (a dependency and network-egress decision) and re-run `m5-telemetry.test.ts` |
| R-022 | AB-09 timing floor is a fixed minimum (default 40 ms), not constant-time: a consented caller can still observe the telco path time; other callers cannot reach it | L | Security | Accepted by design: the floor equalises refusals and telco-less answers; tune per observed telco latency |
| R-023 | Load test ran on one shared VM with mock telcos over loopback; no soak, no multi-instance, no WAN, no gateway, no Neon | M | Platform + Operations | Open: repeat on target infrastructure (G5) |
| R-024 | `tsx` (TypeScript on the fly) is how the sandbox and CI start services; the container image runs compiled JavaScript | L | Platform | Open: keep sandbox-only; `tsx` is now a pinned dev dependency |
| R-025 | Consent-registration quota default (120/min/organisation), subject limit (20/hour), abuse thresholds and the response floor are placeholders chosen without production traffic data | M | Product + Security | Open: tune with real volumes before go-live |

Branch protection (H-001) is an owner action tracked in `decisions-needed.md` and `human-gates.md` (G9), not a platform risk.
