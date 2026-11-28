# NOT APPROVED FOR LIVE DATA

**This platform is a sandbox reference implementation. It uses synthetic data only. It is NOT approved to process live telco, bank or customer
data, and nothing in this repository is a certification, an attestation or a statement of compliance with any law, regulation or standard.**

Automated tests, scans and my own adversarial review reduce risk; they do not replace the human steps below. Live data must not be processed
until **every** gate is complete, evidenced and signed off by a named risk owner.

| # | Gate | Why a human is required | Status | Proposed owner |
|---|---|---|---|---|
| G1 | Independent penetration test of the participant plane, admin plane, CI/CD and hosting, then remediation and a retest | The tests here are written by the same party that wrote the code (the M5 review and the M6 audit and penetration test are self-reviews; they found and fixed 11 defects, which shows self-review is useful and also that it is not enough) | Not started | CISO |
| G2 | Independent security code review (including the crypto, token, RLS and two-person-rule code) | Same reason | Not started | CISO |
| G3 | PDPA assessment: lawful basis, consent model, cross-border transfer (Neon in Singapore), retention periods, breach duty, PIA completed from `docs/privacy/pia-inputs.md` | Legal/regulatory judgement; the regulatory texts are unverified here | Not started | DPO + Legal |
| G4 | Legal and regulatory review (BNM RMiT outsourcing/cloud, CSA 2024 applicability, contractual terms with banks and telcos, CAMARA licensing) | Legal judgement | Not started | Legal + Compliance |
| G5 | Disaster-recovery test on the real target platform (Neon PITR or equivalent, RTO/RPO agreed) | The restore test here covers a local Postgres only | Not started | Platform + Operations |
| G6 | Decision and build of the participant mTLS hosting/gateway (Vercel cannot terminate client certificates), WAF/DDoS, real KMS/HSM, SIEM shipping, alert delivery | Infrastructure and cost decisions | Open (D-003, R-002, R-003, R-005, R-017, R-018) | CTO / Security |
| G7 | Verification of every standard against its published text (ASVS 5.0, OWASP API Top 10 2023, FAPI 2.0, CAMARA, BNM RMiT Nov-2025, PDPA 2024, CSA 2024) and mapping of the compliance matrix | Texts are marked unverified in `docs/compliance-matrix.md` | Not started | Compliance |
| G8 | Residual-risk acceptance: each open item in `residual-risks.md` accepted, mitigated or rejected by its owner | Only a person can accept risk | Not started | Named risk owner |
| G9 | Branch protection requiring the `gate` check, required reviews for changes to security-relevant paths (H-001) | Repository owner action (also H-002 secrets in environments restricted to `main`, and H-003 rotate the exposed Neon password) | Owner reports it is enabled; see M5 report for what I could observe | Repository owner |
| G3a | Legal and privacy opinion specifically on device location, roaming, tenure and number recycling (lawful basis, consent wording, permitted purposes, cross-border) before any is switched on for real data (R-032, D-009) | Accountability | Not started | Legal counsel + privacy owner |
| G10 | Written sign-off by a named risk owner that the above are complete | Accountability | Not started | Named risk owner |

Until G1–G10 are complete the sandbox banner (`SANDBOX: synthetic data only. NOT APPROVED for live data`) remains in every service start-up log
and the developer portal, and `tests/unit/banner.test.ts` fails if it is removed.
