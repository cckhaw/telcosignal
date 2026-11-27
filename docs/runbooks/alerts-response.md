# Alert response (one section per alert rule)
**Owner (proposed)** Head of Security Operations. **Roles** acknowledge: operations, platform_admin, security_auditor; configure rules: operations, platform_admin.

Thresholds and windows are configurable (Alerts page; every change versioned and audited). Defaults below. Rate-based rules are not evaluated below 5 eligible requests in the window. An alert is acknowledged by operations, a platform admin or the security auditor; an unacknowledged alert escalates after its configured time; alerts resolve themselves when the condition clears.

## auth-failures-high (warning, >20 in 10 min; escalate 30 min)
Possible credential stuffing, stolen token reuse, clock skew or a broken participant release. Look at Logs filtered by error code AUTHENTICATION_FAILED and participant. One client: contact the participant; many clients from one source: consider the WAF; consider revoking and re-issuing credentials.
## replay-rejections (critical, >5 in 10 min; escalate 15 min)
Replayed signed requests (attack) or a participant retry bug (reusing request ids). Check the participant; if unexplained treat as an attack: engage the participant kill switch, preserve logs, follow incident-response.md.
## enumeration-suspected (critical, any flag in 60 min; escalate 15 min)
The abuse detector flagged sequential-range scanning, many distinct subjects, or consent probing. Review the flag (counts only; no numbers are stored), the participant's recent logs and consents. Suspend the participant (kill switch) pending review; auto-suspension is available by configuration. Responses were uniform, so nothing was revealed to the participant, but treat as a possible misuse of purpose.
## success-rate-low (critical, <95% in 15 min)
Telco or platform degradation. Dashboard -> reliability and errors by type: timeouts or telco faults point at a telco (check the circuit breaker, Health page, telco contact); rejected points at consent/entitlement changes. **Signal safety holds throughout: failures are UNAVAILABLE, never FALSE.**
## timeouts-high (warning, >5% in 15 min)
Telco latency. Check Health (breaker states), contact the telco, consider the telco kill switch if it is harming others (bulkheads and breakers already limit the blast radius).
## circuit-breaker-open (critical, any in 10 min)
A telco connection tripped its breaker. Traffic to that telco answers UNAVAILABLE without calling it; the breaker retries automatically. Find the cause with the trace and telco contact.
## credentials-expiring (warning, any key expiring within 30 days)
Credentials page lists them. Ask the participant to register a new public key (two-person approval), overlap, then retire the old key.
## rate-limit-hits (warning, >200 in 10 min)
A participant is hitting limits: legitimate growth (raise their limit through the two-person process) or abuse (see enumeration-suspected).
