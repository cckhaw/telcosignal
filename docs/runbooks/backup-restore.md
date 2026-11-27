# Backup and restore
**Purpose** Recover the system of record. **Owner (proposed)** Head of Platform Engineering. **Status** The portable logical backup/restore below is implemented and **tested** (`tests/security/m4b-backup-restore.test.ts`). Point-in-time restore on Neon is the intended primary mechanism and is **blocked on D-002** (no Neon resource has been created); it has not been tested.

## What a backup contains
Schema, data, ownership, grants, row-level-security policies, triggers and functions (pg_dump custom format). It does NOT contain KMS keys, TLS keys, participant private keys (the platform never has them) or the external audit copy. Back those up separately and keep them apart from the data backup, otherwise a stolen backup plus keys exposes more than either alone.
## Take a backup
`backupDatabase(superuserUrl, dbName, file)` (src/ops/backup.ts). Encrypt the file at rest and store it in an approved jurisdiction (residency map).
## Restore
`restoreDatabase(superuserUrl, newDbName, file)` restores into a **new** database and refuses to restore over an existing one. Then:
1. Point a staging instance at the restored database and run the verification below. 2. Only then switch the application (new connection strings; rotate the database passwords). 3. Keep the old database until the verification and a business sign-off are complete.
## Verification (all automated in the test)
Row counts of every table equal; schema migrations and checksums equal; ownership, grants, policies, triggers and functions equal; row-level security still enabled **and forced**; the application role still sees nothing without a tenant context and cannot reach another tenant; the audit chain verifies (recomputation and external copy); statements still tie to usage records by digest; rollups equal usage; the backup contains no key material and no phone numbers.
## Observed timings (sandbox only)
212 KB database (30 usage records): backup 97 ms, restore 418 ms. These say nothing about production volumes; measure on a representative dataset before quoting an RPO/RTO.
## Neon (blocked)
When approved: enable point-in-time restore and branch protection, restore to a new branch, run the same verification, and record RPO/RTO. Preview branches must never copy production-like data.
