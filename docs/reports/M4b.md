# M4b report (2026-11-27)
Delivered: request log + request tracing, log search and masked views, audit-trail viewer, dashboards (traffic, response time with platform overhead separated from telco time, reliability, security, business) built on time-bucketed rollups with stated freshness, CSV export and monthly report, alerting (configurable rules, acknowledgement, escalation, auto-resolve, SIEM-ready events), incident notes, dependency health, error catalogue, retention and deletion jobs, background worker on a least-privilege role, OpenAPI definition generated from the code, static developer portal, tested backup/restore, runbooks and privacy documents. See `docs/kpi-definitions.md`.

## Executed locally (Node 22, Postgres 16, Redis 7)
`tsc --noEmit` clean, `eslint .` clean, `vitest run`: **298 tests pass** (17 files). New in M4b: logs/trace 20, dashboards/alerts/retention 23, OpenAPI/portal 11, backup/restore 7, docs 5.
Live-sandbox DAST: participant **53/53**, admin portal **72/72** (now including dashboards, logs, exports, audit viewer and filter fuzzing; the worker runs alongside).

## Acceptance
* **A seeded failure is traced by correlation id.** A telco HTTP 500 is found by correlation id in the log search; the trace shows every step (auth, signature, validate, policy, limits, consent, route, adapter, finalise) with timing, the router decision (telco-a), platform overhead vs telco time, the reason class and the operator action; the gateway row states that it is not instrumented here. Timeouts, unsupported signals, consent rejections and authentication failures are each traceable and classified; the failing step is where the step list stops. Real requests cannot be replayed.
* **No raw phone number appears in any screen or export.** For 7 identities x 18 pages x 3 traces and all CSV exports, none of the numbers used (and no full-length number) appears; there is no unmask or lookup-by-number function; the database refuses any E.164 string in the request log (route, reason, steps, subject reference) and in incident notes (CHECK constraints); a full-table scan of the request log and usage records finds none; CSV cells are protected against formula injection.
* **Dashboard totals match usage records.** Totals, billable volume, every outcome and every error type, by telco, signal, version and participant (including the filter combinations), screen and CSV; rebuilds are idempotent; late data is picked up; freshness and staleness are displayed; each organisation sees only its own figures.
Also: alerts open with a SIEM-ready event, are not duplicated, acknowledgement stops escalation, unacknowledged alerts escalate, alerts resolve when the condition clears, thresholds are configurable by operations/admins only and every change is versioned and audited, low volume does not alert; retention deletes only expired rows and only through the worker role, with a 7-day floor even if a setting is corrupted; the restored database is faithful (data, structure, grants, forced RLS, audit chain, statement digests) and refuses to restore over an existing database.

## Defects found by my own tests and fixed
- A trend query used `hour` as a bare alias (SQL syntax error, HTTP 500 on every dashboard).
- Test-data and expectation errors that the stricter assertions exposed (no product defect): documented in the commit history.
- A rare intermittent alert miss, traced to a precision mismatch: the abuse-flag metric used `ts <= now`, JavaScript clocks have millisecond precision and Postgres timestamps microseconds, so a flag written in the same millisecond was skipped. Proven by a regression test that fails with the old bound and passes with the fix; the needless upper bound was removed.
- The documentation test caught a runbook with no named owner.
- DAST runner: a leak regex matched the HTML `<select>` element; fuzz volume exceeded the portal's own per-session rate limit (the limiter working).

## Observed values (sandbox only)
Backup 97 ms and restore 418 ms for a 212 KB database. These say nothing about production volumes.

## Honest limits (new residual risks R-016..R-020)
- R-016 Percentiles are histogram bucket upper bounds, and "availability" is a platform-side approximation.
- R-017 Events are SIEM-ready JSON on the process log; there is no shipping to an external SIEM.
- R-018 Alerts escalate in the system and emit events; no pager or e-mail delivery exists.
- R-019 The request log is written after the response, best effort: if the write fails the request is still served and the failure is logged, so the log can have gaps.
- R-020 No partitioning or archival of the request log and rollups; no capacity testing (M5).
- Neon point-in-time restore is untested (D-002). Runbooks were never exercised by a human team. The compose file remains unexecuted. The gateway/WAF is assumed, not built.
