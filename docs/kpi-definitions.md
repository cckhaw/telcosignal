# KPI definitions

Targets are configurable placeholders (platform config `kpi_targets`). All dashboards read **time-bucketed rollups**
(`rollup_minute/hour/day`) and display "data as of <rollup watermark>". Figures are scoped per organisation by RLS.
Source of truth for every count: append-only `usage_record`. Reconciliation test: sum(rollups) == count(usage_record) per filter.

| KPI | Formula | Source | Refresh | Placeholder target |
|---|---|---|---|---|
| Requests | count(usage_record) | usage_record | 1 min | – |
| Requests/sec (avg, peak) | requests / bucket seconds; max over 1-min buckets/60 | rollup_minute | 1 min | peak ≤ 200 rps (local) |
| Share by participant/telco | requests_x / requests_total | rollup | 1 min | – |
| p50/p95/p99 total latency | quantile over latency histogram | rollup (histogram buckets) | 1 min | – |
| Platform overhead p95 | p95(total_ms − telco_ms) | rollup | 1 min | < 100 ms |
| Telco time p95 | p95(telco_ms) | rollup | 1 min | < 2000 ms |
| Success rate | outcome TRUE/FALSE / (all excl. client 4xx) | rollup | 1 min | ≥ 99.5 % |
| Availability | 1 − (platform_fail / eligible requests) | rollup | 1 min | ≥ 99.9 % |
| UNAVAILABLE rate / NOT_SUPPORTED rate | count(outcome) / eligible | rollup | 1 min | ≤ 1 % / n.a. |
| Timeout rate | count(timeout) / eligible | rollup | 1 min | ≤ 0.5 % |
| Circuit breaker state | latest state per telco | resilience state | 10 s | closed |
| SLA attainment / breaches | window success & latency vs SLA config | rollup + config | 5 min | per plan |
| Auth failures / rate-limit hits / replay rejections | count of security_event by type | security_event rollup | 1 min | alert thresholds |
| Suspected enumeration | count(abuse_flag) | abuse_flag | 1 min | 0 |
| Credentials near expiry | count(cred where expires < now + N d) | credentials | 1 h | 0 within 30 d |
| Active participants | distinct org with ≥1 request in window | rollup | 1 h | – |
| Onboarding progress | orgs by state | onboarding | 5 min | – |
| Signal coverage | (telco,signal) pairs active / defined | registry | 5 min | – |
| Billable volume / charges / telco cost | sum(billable), sum(price), sum(telco_cost) | usage_record | 1 h | n.a. (placeholder prices) |
