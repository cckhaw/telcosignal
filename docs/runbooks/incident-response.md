# Incident response
**Purpose** Contain, investigate, recover and learn from a security or availability incident without destroying evidence. **Owner (proposed)** Head of Security Operations. **Roles** platform_admin, operations (contain), security_auditor (investigate, read-only), integration_engineer (telco liaison).

## Trigger
An alert (see alerts-response.md), a participant or telco report, a SIEM correlation, or a monitoring anomaly. Severity: **critical** = confirmed or likely compromise, data exposure, or loss of signal safety; **warning** = degraded or suspicious; **info** = noteworthy.

## Steps
1. **Open an incident note** in the portal (Alerts, or on the request trace) with the correlation ids. Notes cannot contain phone numbers and cannot be edited or deleted.
2. **Contain first, with the smallest effective switch** (kill-switch.md): participant switch for a suspect participant; telco switch for a faulty or hostile telco; signal switch for a flawed signal. Engaging is immediate and single-person by design; **lifting needs a second person**.
3. **Preserve evidence.** Do not edit anything: the audit log is append-only and hash-chained (Audit trail page shows chain status); logs are append-only until retention. Export what you need (exports are role-restricted and audited). Nothing may be replayed against telcos: use the test console with synthetic numbers only.
4. **Trace.** Search Logs by correlation id, participant, telco, signal, outcome or error code. The trace shows each step with timing, the router decision, platform overhead vs telco time, the reason class and what to do. Use the Audit trail for who changed what.
5. **Credentials.** If a participant credential may be compromised: revoke the key now (immediate, single-person), suspend the organisation if needed, then register a new public key through the two-person process.
6. **Assess personal-data impact.** The platform stores no raw numbers and no KYC inputs; hashes are keyed. Still follow breach-notification.md to decide, with the DPO, whether anything is notifiable.
7. **Recover.** Fix the cause (configuration change by two people, key rotation, telco repair), lift switches with a second person, confirm dashboards and alerts return to normal.
8. **Review.** Within 5 working days: timeline, root cause, what detection worked, what did not, actions with owners. Update the threat model and these runbooks.

## Verification
Alerts resolved (they self-resolve when the condition clears); audit chain intact; success rate and overhead back within targets; participants informed; actions recorded.

## Not yet possible (see residual risks)
Automatic paging/escalation to people (alerts escalate in the system and emit SIEM events; a real pager integration is not built). Cross-instance circuit-breaker state is per process. WAF/DDoS controls are assumed in front and are not part of this repository.
