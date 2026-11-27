# Runbook: local sandbox (synthetic data only)
1. Postgres 16 superuser URL and Redis available locally (or `docker compose -f deploy/compose.sandbox.yml up -d postgres redis`; compose file is unverified, see its header).
2. `TS_ADMIN_URL=postgres://… TS_REDIS_URL=redis://… npm run sandbox:setup` — generates DB roles/passwords, PKI, KMS dir and `.sandbox/env` (0700/0600, gitignored). Re-running **recreates** the database.
3. `set -a; . .sandbox/env; set +a; npm run sandbox:mocks &  npm run sandbox:start &`
4. `npm run dast` runs the black-box checks against https://localhost:8443.
Note: Postgres roles are cluster-wide. Running the test suite on the same cluster resets the role passwords, which breaks an already-running sandbox: re-run step 2.
Participant simulator credentials are in `.sandbox/participants.json` (synthetic; never reuse anywhere).
