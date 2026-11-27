# Disaster recovery and failover
**Owner (proposed)** CTO / Head of Platform Engineering. **Status** Not exercised. A disaster-recovery test is one of the human gates before live data (release gate).
## Scenarios and what exists today
| Scenario | Today | Gap |
|---|---|---|
| Database lost or corrupted | Restore into a new database from backup (tested) | Neon point-in-time restore untested (D-002); no standby |
| Redis lost | Replay and rate limiting **fail closed** (requests refused with 503) until it is back; nothing is lost (ephemeral only) | A hosted/HA Redis needs approval (D-004) |
| Platform host/container lost | Stateless processes; restart from images and config | No orchestration or multi-region in this repository |
| Telco outage | Circuit breakers, bulkheads, UNAVAILABLE results, kill switch | No automatic failover between telcos (each number routes to one telco) |
| KMS keys lost | Existing hashes cannot be recomputed and tokens cannot be verified | Mock KMS only (R-003): a real HSM/KMS with backup is required |
| Admin IdP outage | No admin sign-in (fail closed); participant traffic unaffected | Break-glass procedure to be defined by the owner |
## Steps (database loss)
1. Declare the incident (incident-response.md). 2. Engage kill switches if data integrity is in doubt. 3. Restore (backup-restore.md) into a new database. 4. Verify. 5. Switch connection strings; rotate credentials. 6. Reconcile usage and statements for the gap period (statements are immutable; corrections are new rows). 7. Review.
