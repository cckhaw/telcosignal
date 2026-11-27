# Data-residency map
| Data / component | Location in the sandbox | Planned live location | Status |
|---|---|---|---|
| System-of-record database | Local Postgres (ephemeral) | Neon, AWS Singapore (aws-ap-southeast-1), created via the Vercel Marketplace | **Not created (D-002).** Outside Malaysia: **open residency and cross-border transfer risk R-001; blocks live data until approved**. Region is immutable after creation |
| Redis (replay, limits, abuse counters) | Local | Local/approved region; hosted Redis needs approval (D-004) | Ephemeral data only; keyed hashes, no numbers |
| KMS / HSM | Local mock | Approved KMS/HSM in an approved jurisdiction | Mock only (R-003) |
| Audit external copy | Local file | WORM storage in an approved jurisdiction | Not built |
| Backups | Local files | Encrypted, approved jurisdiction | Policy to be set |
| Static developer portal | Vercel production (public documentation, no personal data) | Same | Deployed; contains no data |
| Participant API and admin plane | Local | A host with mTLS-capable gateway in an approved region | Not on Vercel (D-003) |
| Telco/aggregator traffic | Mock telcos | Real telco connections (out of scope here) | Numbers leave the platform only to the serving telco |
Cross-border transfer analysis, contracts and any regulatory approvals are **human decisions** (see the release gate).
