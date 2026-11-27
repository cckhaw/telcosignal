# Retention and deletion
**Owner (proposed)** Data Protection Officer. **Implemented and tested** (`src/ops/retention.ts`, run by the worker role).
| Data | Retention | Mechanism |
|---|---|---|
| Request log (search, traces) | `logs.retention_days` (default 90, floor 7) | Rows can only be deleted by the worker role and only after the period (trigger); change via two-person SETTING |
| Consents | deleted `consent.retention_days` (default 180, floor 30) after expiry or revocation | Worker job; removes the subject link |
| Admin sessions | 30 days after ending | Worker job |
| Abuse flags | 365 days | Worker job |
| Usage records | **not deleted** (billing evidence; append-only) | Retention period to be set by Finance/Legal |
| Statements | **not deleted** (immutable) | As above |
| Audit log | **never deleted** here (append-only, hash-chained) | Retention and archival to be set by Legal |
| Backups | Encrypted, expire per the backup policy | Operations |
## Legal hold
Not implemented. To hold data, stop the worker or raise the retention settings via the two-person process before the period elapses.
## Data subject requests
The platform holds no raw identity data. A subject can be located only by a keyed hash computed from the number by an authorised operator with KMS access; deletion of consent rows for a subject is possible via the schema owner. A formal DSAR/erasure workflow needs Legal input and is not built.
