# Decisions needed / assumptions (owner reviews at the end)

| ID | Item | Status | Default taken |
|---|---|---|---|
| D-001 | Brief says "wait for approval after docs" but also "review only at the end, auto-merge". | Assumed: proceed | Proceed through milestones; reversible by stopping at any merged milestone. |
| D-002 | Neon project (aws-ap-southeast-1) via Vercel Marketplace — cloud resource / cost. Region is immutable. | **Owner has provisioned it and connected it to the Vercel project** (observed: Neon-integration variable NAMES on the project; values are sensitive and not readable by me) | Not created by me. M5 adds `neon-verify` (manual workflow, synthetic data only) to run the suite against it; results are in `docs/reports/M5.md`. Live data stays blocked on R-001 (cross-border) and G3. |
| D-003 | Vercel cannot enforce participant mTLS / admin isolation. | **Needs human decision** | Vercel hosts only the static developer portal. Participant + admin planes need a gateway/host (see architecture §9). |
| D-004 | Hosted Redis | Needs approval | Local only. |
| D-005 | Targets (p95<100 ms overhead, 2 s timeout, 200 rps) | Assumption | Used as configurable defaults. |
| D-006 | Standards texts (ASVS 5.0, FAPI 2.0, CAMARA, BNM RMiT Nov-2025, PDPA 2024, CSA 2024) | Verify | Marked **unverified** until fetched and read. |
| D-007 | CAMARA specs must be pinned from camaraproject repos; if unreachable, stop. | Pending M1 | See compliance matrix / M1 gate. |
| H-001 | Enable branch protection on main requiring the `gate` check (cannot be set from the session) | Owner says it is enabled | At my last check (M5) the API showed no classic protection on `main` and one ruleset, `Standard`, with enforcement `disabled`, no target branches and no required-status-check or pull-request rule. See `docs/reports/M5.md` for what to change. |
| H-002 | GitHub environments for secrets: a collaborator with write access can read repository-level secrets by editing a workflow on a branch. Move `VERCEL_*` and the Neon `DATABASE_URL` into environments restricted to `main` with required reviewers (cannot be set from the session). | Needs repo owner | Open |
| H-003 | Rotate the Neon database password (it was exposed once, see R-028) and update the `DATABASE_URL` GitHub secret and the Vercel/Neon integration. | Needs repo owner | Open |
