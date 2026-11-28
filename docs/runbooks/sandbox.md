# Runbook: local sandbox (synthetic data only)
**Owner (proposed)** Platform Engineering.
1. Postgres 16 superuser URL and Redis available locally (or `docker compose -f deploy/compose.sandbox.yml up -d postgres redis`; the compose file is unverified, see its header).
2. `TS_ADMIN_URL=postgres://... TS_REDIS_URL=redis://... npm run sandbox:setup` generates DB roles and passwords, PKI, key directories (participant and admin plane separately), the mock-IdP client secret and bootstrap administrators (`TS_BOOTSTRAP_ADMINS`, default two sandbox subjects; there are no default accounts). Output: `.sandbox/` (0700/0600, gitignored). Re-running **recreates** the database.
3. Start (each in its own terminal, or background): `set -a; . .sandbox/env; set +a; npm run sandbox:mocks; npm run sandbox:start` (participant plane :8443 + three mock telcos), then `set -a; . .sandbox/admin.env; set +a; npm run sandbox:idp; npm run sandbox:admin` (admin plane :9443 + mock IdP :9444), and `set -a; . .sandbox/worker.env; set +a; npm run worker` (rollups, alerts, retention).
4. `npm run dast`, `npm run dast:admin` and `npm run pentest` run the black-box checks and the penetration test against the live sandbox (own sandbox only; `pentest` opens hundreds of connections and a 4 000-request burst, so run it on the same machine, not across a network you do not own).
Note: Postgres roles are cluster-wide. Running the test suite on the same cluster resets role passwords, which breaks an already-running sandbox: re-run step 2.
Participant simulator credentials are in `.sandbox/participants.json` (synthetic; never reuse anywhere).

Load test (own sandbox only): start the sandbox, raise the quotas for the run (defaults are meant to shed 200 rps from two participants), and run `npm run load`:
`TS_RATE_LIMIT_RPS=250 npm run sandbox:setup`, then append `TS_LIMIT_PARTICIPANT_SIGNAL_PER_MIN=20000`, `TS_LIMIT_CONSENT_PER_MIN=5000`, `TS_LIMIT_TELCO_PER_SEC=400`, `MOCK_LATENCY_MS=60` to `.sandbox/env`, start the services, then
`DB_URL=<TS_MIGRATOR_URL from .sandbox/db.env> LOAD_SUBJECTS=6000 [LOAD_FAULT_PCT=5] npm run load`. Results: `docs/release/load-results.md`.
Telemetry: `TS_OTEL_EXPORTER=console` prints allow-listed spans as JSON to stdout (off by default). `TS_MIN_RESPONSE_MS` (default 40) sets the AB-09 response-time floor; `0` disables it.
