# Data inventory (inputs for a privacy impact assessment)
Synthetic data only in this repository. This inventory states what the platform WOULD hold with live data. Classification: P = personal data (or derived from it), O = operational, C = credential.
| Data | Where | Class | Contains | Minimisation / protection |
|---|---|---|---|---|
| Subscriber number (MSISDN) | Request in transit and in memory only; sent to the serving telco | P | The number | Never stored, logged, traced, metered, audited or backed up (CHECK constraints, tests). Outbound minimisation: telco receives only number + window (A/B/C) |
| Subject hash | consents, porting, Redis keys (abuse, limits) | P (pseudonym) | HMAC-SHA256(number) under a KMS key; request log keeps an 8-hex prefix | Keyed: not reversible without the key; key outside the database |
| KYC attributes | In memory in transit only | P | Name, address, document, birthdate, email... | Never stored or logged; verified by test across all tables, logs and the audit copy |
| Consent / lawful basis | consents | P | consent_ref, purpose, signals, dates, subject hash | Required on every request; RLS per organisation; deleted after retention |
| Signal result | Response only; usage record keeps the outcome class | P | TRUE/FALSE/UNAVAILABLE/NOT_SUPPORTED | No result caching; usage record has no subject |
| Usage records, statements | usage_record, statement | O | Org, signal, telco, outcome, timings, correlation id | Append-only; no subject; billing evidence |
| Request log | request_log | O | Route, status, outcome, timings, masked subject prefix | CHECK constraints reject any number; retention-bound |
| Audit log | audit_log (+ external copy) | O | Who did what; no numbers | Append-only, hash-chained |
| Admin identities | admin_user, admin_session | P (staff) | IdP subject, display name, role | No passwords stored; session ids stored only as hashes |
| Participant public keys, cert thumbprints | client_keys | C (public) | Public JWK, thumbprint | Private keys never held |
| Platform keys | KMS (mock locally) | C | Signing/encryption/hash keys | Separate store; admin plane has its own signing key directory |
## Data subjects and purposes
Subscribers of participating telcos, checked by banks for fraud prevention (purpose codes FRAUD_PREVENTION, ACCOUNT_TAKEOVER_CHECK, TRANSACTION_RISK). Lawful basis and consent references are supplied by the participant and recorded; the platform does not itself collect consent from subscribers.
