# Load test results (sandbox, synthetic data)

Target (brief): about **200 requests/second**, **p95 platform overhead < 100 ms** (platform time excluding the telco call), telco timeout 2 s,
**all security controls on**.

## How it was run
`tests/load/run.ts` (`npm run load`): an **open-loop** generator. Requests are issued on a fixed schedule whatever the earlier ones are doing and
latency is measured from the *scheduled* send time, so queueing cannot hide (no coordinated omission). Every request is a real mTLS request with a
bearer token bound to the client certificate and an ES256-signed request; subjects are random synthetic numbers (not a sequential scan), each with
its own registered consent; the original four signals (the second-wave signals were not load-tested) are spread over the telcos that cover them. Server-side figures come from the platform's own request
log (`total_ms − telco_ms`), written after the response.

Controls on during the run: mutual TLS, token verification, request signature and Redis replay check, scope and entitlement, per-participant /
per-signal / per-subject / per-telco quotas, consent check, enumeration detection (it raised flags, as designed), circuit breakers and bulkheads,
usage metering, hash-chained audit, request log, response-time floor. **Settings raised for the run only**: `TS_RATE_LIMIT_RPS=250` per certificate
(default 100), `TS_LIMIT_PARTICIPANT_SIGNAL_PER_MIN=20000` (default 600), `TS_LIMIT_CONSENT_PER_MIN=5000` (default 120), `TS_LIMIT_TELCO_PER_SEC=400`
(default 200): at 200 rps from two participants the defaults would (correctly) shed traffic. Mock telcos answer after a fixed 60 ms (`MOCK_LATENCY_MS`).

Environment: one 4-core, 16 GB Linux VM running **everything** (load generator, platform, three mock telcos, Postgres 16, Redis, Node 22) over
loopback. This is deliberately pessimistic for CPU contention and optimistic for network latency.

## Results (raw files in `docs/release/load/`)
| Scenario | Offered / achieved rps | Completed | HTTP 200 | Client p50 / p95 / p99 (ms) | **Platform overhead p50 / p95 / p99 (ms)** | Telco p95 (ms) |
|---|---|---|---|---|---|---|
| Baseline, 60 s | 200 / 199.8 | 12 000 / 12 000 | 100 % (TRUE 6 108, FALSE 5 892) | 66.6 / 78.2 / 118.1 | **6 / 16 / 52** | 62 |
| 5 % faulty telco (hang, HTTP 500, garbage), 60 s | 200 / 193.5 | 12 000 / 12 000 | 100 % (UNAVAILABLE 595 ≈ 5 %, **no fabricated FALSE**) | 67.2 / 89.1 / 2 006.9 | **6 / 19 / 64** | 63 |

* Target met in these runs: **p95 platform overhead 16 ms and 19 ms (< 100 ms)** at the offered 200 rps with all controls on.
* Hung telco calls end at the 2 s bound (client p99 ≈ 2 007 ms is exactly those requests: the telco time, not platform overhead); they are answered `UNAVAILABLE` and not billed.
* Platform p95 step times (ms): adapter 62.6 (telco wait), finalise 4.1, consent 3.1, auth 2.4, limits 1.8, route 1.6, signature 1.6, policy 1.0.
* Platform CPU was about 50 % of one core at 200 rps.

## What this does NOT show (read before quoting these numbers)
* One shared VM with loopback networking, mock telcos, no WAN latency, no gateway/WAF/TLS terminator in front, a local (not Neon) database: **not capacity-planning evidence.**
* 60-second runs: no soak, no memory-growth or connection-leak observation, no failure-over of Postgres/Redis, a single platform instance.
* `request_log` grows by one row per request and the audit log by one row per signal request plus one per consent or token issue (38 816 audit rows at the end of both runs, including the consent registrations and a smoke run): partitioning/archival is **not** implemented (R-020).
* Error-path latency includes the deliberate 40 ms response-time floor (AB-09); the overhead figures above are for answered signal requests.
* With the dynamic registry the adapter and circuit-breaker state is per process (R-008); a multi-instance run was not done.
