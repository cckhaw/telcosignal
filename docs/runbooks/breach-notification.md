# Personal-data breach notification (inputs and procedure)
**Purpose** Decide quickly and consistently whether a suspected breach is notifiable and gather what regulators and affected parties need. **Owner (proposed)** Data Protection Officer with Legal. **Status** These are engineering INPUTS. Notification duties, deadlines and thresholds under the Malaysian PDPA (as amended 2024), Bank Negara Malaysia RMiT (November 2025) and the Cyber Security Act 2024 have **not been verified against the official texts** (compliance matrix: unverified) and must be confirmed by Legal.

## Facts the platform can supply (by design)
- **No raw phone numbers** are stored in the database, logs, traces, metrics, usage records, audit records or backups (CHECK constraints and tests). Subjects exist only as keyed hashes; the key is held in the KMS, not in the database.
- **KYC attributes are never stored or logged** (processed in memory only).
- Consent records hold keyed subject hashes, purpose, signals and dates; request logs hold an 8-hex prefix of a keyed hash.
- The audit log is tamper-evident (hash chain, external copy); use it to establish who accessed what and when.
## Steps
1. Contain (incident-response.md). 2. Establish scope from the audit trail and logs: which participants, which signals, which time window, which data classes (consent subject hashes; request metadata). 3. Determine whether hashes could be reversed: only with the keyed-hash key; establish whether the KMS or key directory was exposed. 4. Record the timeline. 5. DPO + Legal decide on notification of the regulator and affected parties and on notifying participants and telcos under their contracts. 6. Notify within the legally required time (to be confirmed). 7. Remediate and record lessons.
## Contact placeholders
Regulator contacts, participant security contacts and telco NOC contacts are not stored here; they belong in the organisation's incident system.
## Residency
Data in the planned Neon region is outside Malaysia (open risk R-001). A breach involving that database may have cross-border implications.
