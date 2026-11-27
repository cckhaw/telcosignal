# Decisions needed / assumptions (owner reviews at the end)

| ID | Item | Status | Default taken |
|---|---|---|---|
| D-001 | Brief says "wait for approval after docs" but also "review only at the end, auto-merge". | Assumed: proceed | Proceed through milestones; reversible by stopping at any merged milestone. |
| D-002 | Neon project (aws-ap-southeast-1) via Vercel Marketplace — cloud resource / cost. Region is immutable. | **Needs human approval** | Not created. Local Postgres only; Neon-specific tests parked. |
| D-003 | Vercel cannot enforce participant mTLS / admin isolation. | **Needs human decision** | Vercel hosts only the static developer portal. Participant + admin planes need a gateway/host (see architecture §9). |
| D-004 | Hosted Redis | Needs approval | Local only. |
| D-005 | Targets (p95<100 ms overhead, 2 s timeout, 200 rps) | Assumption | Used as configurable defaults. |
| D-006 | Standards texts (ASVS 5.0, FAPI 2.0, CAMARA, BNM RMiT Nov-2025, PDPA 2024, CSA 2024) | Verify | Marked **unverified** until fetched and read. |
| D-007 | CAMARA specs must be pinned from camaraproject repos; if unreachable, stop. | Pending M1 | See compliance matrix / M1 gate. |
