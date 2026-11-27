# Onboarding operations (telco and bank)
**Owner (proposed)** Head of Partner Integration. All steps are performed in the admin portal and are tested end to end (m4a-onboarding).
## Telco
1. Create the organisation (draft). 2. Request allow-listing of the telco's endpoint origin (second person approves). The portal refuses private, loopback, link-local, metadata and encoded addresses and non-https URLs. 3. Register the connection (adapter type, endpoint) and signal coverage (second person). 4. Move to testing. 5. Run health check and conformance tests (platform-run, against the telco's test numbers). 6. Submit for approval (blocked until every required test passed). 7. A **second person** activates it (fresh sign-in). 8. Route number prefixes to it (second person). Suspension is immediate; porting changes are two-person.
## Bank
1. Create the organisation. 2. Entitle signals and purposes (second person). 3. Register a public key + certificate thumbprint for a new client (second person; scopes beyond the entitlement are refused). 4. Move to testing; the bank performs sandbox calls (including one without consent). 5. "Evaluate certification": computed by the database from real sandbox evidence, never asserted by a person. 6. Submit; a second person activates. 7. Assign a price plan and limits (two-person).
## Offboarding
Suspend (immediate), revoke credentials (immediate), request retirement (second person), remove routing and entitlements.
