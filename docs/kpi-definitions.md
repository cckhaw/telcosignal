# KPI definitions (as implemented in M4b)
Source of truth for every count: the append-only `usage_record` table (metered requests) and `request_log` (all requests, including rejections before metering). Dashboards read ONLY the time-bucketed rollups `rollup_minute` (from usage records) and `rollup_security_minute` (from the request log), rebuilt by the worker role, so they never touch the request path. Every figure is filterable by period, participant, telco, signal and API version (participant/org filters are forced to the caller's own organisation for restricted users). The screen states the **data-as-of watermark** and flags rollups older than 3 minutes as **stale**. Targets are configurable placeholders (`kpi_target`).
Latency percentiles come from fixed histogram buckets (upper bounds 5, 10, 25, 50, 100, 250, 500, 1000, 2000 ms and an open last bucket) and are reported as the **upper bound of the bucket containing the percentile** (conservative; "n/a" without data; ">=2000 ms" beyond the last bound). **Platform overhead = total time minus telco time**, shown separately from telco time.
Reconciliation (proved by tests in `m4b-dashboards-alerts`): dashboard totals, billable volume, outcome counts and error-type counts equal the usage records exactly, overall and per telco, signal, API version and participant; per-participant totals add up to the overall total; rebuilding rollups is idempotent; the CSV export and the monthly report show the same numbers.

| KPI | Formula as implemented | Source | Refresh | Placeholder target |
|---|---|---|---|---|
| Requests (metered) | sum(requests) | rollup_minute | worker, 30 s | - |
| Billable volume | sum(billable) = TRUE/FALSE outcomes only | rollup_minute | 30 s | - |
| Requests/sec | avg = requests / seconds in window (to now); peak = max per-minute total / 60 | rollup_minute | 30 s | peak <= 200 rps (local) |
| Trend | requests per hour | rollup_minute | 30 s | - |
| Share by participant / telco | requests_x / requests_total (participant shares: staff only) | rollup_minute | 30 s | - |
| Response time p50/p95/p99 | percentile of merged `h_total` | rollup_minute | 30 s | - |
| Platform overhead p50/p95/p99 | percentile of merged `h_over` (total - telco) | rollup_minute | 30 s | p95 < 100 ms |
| Telco time p50/p95/p99 | percentile of merged `h_telco` | rollup_minute | 30 s | p95 < 2000 ms |
| Success rate | (TRUE + FALSE) / (TRUE + FALSE + UNAVAILABLE) | rollup_minute | 30 s | >= 99.5 % |
| UNAVAILABLE rate | UNAVAILABLE / eligible | rollup_minute | 30 s | <= 1 % |
| NOT_SUPPORTED rate | NOT_SUPPORTED / all metered | rollup_minute | 30 s | n.a. |
| Timeout rate | reason_class=timeout / eligible | rollup_minute | 30 s | <= 0.5 % |
| Errors by type | requests by `reason_class` (timeout, telco_fault, client_data, circuit_open, bulkhead, limit, kill_switch, no_route, unsupported, disabled, rejected) | rollup_minute | 30 s | - |
| Availability (platform-side, approximate) | 1 - (no_route + circuit_open) / eligible; telco faults are reported separately as telco-side | rollup_minute | 30 s | >= 99.9 % |
| Circuit breaker state | live per-telco state of this instance (Health, Integration); `circuit_open` count over time | in-process + rollup | live / 30 s | closed |
| SLA attainment / breaches | share of minutes (with >= 5 eligible requests) whose success rate meets the target; breaches = minutes below | rollup_minute + kpi_target | 30 s | per plan |
| Authentication failures, rate-limit hits, replay rejections, consent denials | sum of events by error code | rollup_security_minute | 30 s | alert thresholds |
| Suspected enumeration | count of abuse flags in the window (staff) | abuse_flag | live | 0 |
| Credentials near expiry | active keys expiring within 30 days (scoped by RLS) | client_keys | live | 0 |
| Active participants | distinct organisations with requests in the window | rollup_minute | 30 s | - |
| Onboarding progress / signal coverage | organisations by state; covered (telco, signal) pairs on active telcos / possible (staff) | organisations, telco_signal_coverage | live | - |
| Charges / telco cost | sum of statement totals within the window (only where statements have been generated); otherwise stated as unavailable | statement | on generation | placeholder prices |
Limitations: availability is an approximation (the platform has no external prober); breaker state is per process; fixed-window limits and bucket-bound percentiles are coarse by design.
