# Runbook: local sandbox (synthetic data only)
**Owner (proposed)** Platform Engineering.
1. Postgres 16 superuser URL and Redis available locally (or `docker compose -f deploy/compose.sandbox.yml up -d postgres redis`; the compose file is unverified, see its header).
2. `TS_ADMIN_URL=postgres://... TS_REDIS_URL=redis://... npm run sandbox:setup` generates DB roles and passwords, PKI, key directories (participant and admin plane separately), the mock-IdP client secret and bootstrap administrators (`TS_BOOTSTRAP_ADMINS`, default two sandbox subjects; there are no default accounts). Output: `.sandbox/` (0700/0600, gitignored). Re-running **recreates** the database.
3. Start (each in its own terminal, or background): `set -a; . .sandbox/env; set +a; npm run sandbox:mocks; npm run sandbox:start` (participant plane :8443 + three mock telcos), then `set -a; . .sandbox/admin.env; set +a; npm run sandbox:idp; npm run sandbox:admin` (admin plane :9443 + mock IdP :9444), and `set -a; . .sandbox/worker.env; set +a; npm run worker` (rollups, alerts, retention).
4. `npm run dast` and `npm run dast:admin` run the black-box checks against the live sandbox.
Note: Postgres roles are cluster-wide. Running the test suite on the same cluster resets role passwords, which breaks an already-running sandbox: re-run step 2.
Participant simulator credentials are in `.sandbox/participants.json` (synthetic; never reuse anywhere).
