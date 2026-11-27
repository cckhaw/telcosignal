# M4a report (2026-11-27)
Delivered: isolated admin interface (server-rendered, no client script), OIDC SSO with mandatory phishing-resistant MFA, server-side sessions, RBAC with seven roles, organisation isolation (RLS on a dedicated DB role), versioned configuration with diff and gated rollback, **database-enforced two-person approval**, telco and bank onboarding state machines, DB-driven adapter registry (changes go live without a restart), credentials (public-key registration, show-once generated keys, rotation, revocation, expiry flags), kill switches, test console (synthetic numbers only), API version management. See `docs/admin-portal.md`.

## Executed locally (Node 22, Postgres 16, Redis 7)
`tsc --noEmit` clean, `eslint .` clean, `vitest run`: **231 tests passed** (12 files; 78 new in M4a).
DAST on a freshly generated live sandbox: participant API **53/53**, admin portal **53/53**. Mutation check: removing the portal's Origin check makes the admin DAST report 51/53.

## Acceptance
* **Mock telco and mock bank onboarded end to end through the portal** (m4a-onboarding, 14 tests). Telco: SSRF-prone endpoints refused (metadata, private ranges, encoded hosts such as 2130706433/0x7f000001/127.1, credentials in URLs, non-https); origin allow-listed by two people; connection and coverage registered by two people; traffic does NOT reach a telco that is not active; platform-run conformance tests pass; submission blocked until they do; activation needs a second person; the bank's traffic then reaches the new telco; a telco whose conformance fails can never be activated; suspension is immediate. Bank: entitlement (second person), public key + certificate for a new client (second person; scopes beyond the entitlement refused at approval), certification computed from real sandbox evidence (cannot be asserted by hand), activation by a second person, suspension cuts it off at once, retirement needs a second person.
* **Two-person approval cannot be bypassed** (m4a-approval, 19 tests): requester can never decide their own change, through the UI or by calling the database function directly; the portal's DB role has no write grant on 18 high-risk statements tried; role policy per kind; replay/double application, stale requests, 24 h expiry, payload tamper (integrity hash), disabled/demoted approver, step-up re-authentication (UI and DB) all refused; the schema also forbids requester == decider and freezes decided requests; at least two active platform administrators always remain.
* **Kill switches work**: engaged immediately by operations/platform admin only (finance/auditor refused), traffic cut at once, lifting needs a second person.
* **One organisation cannot see another** (m4a-isolation, 18 tests): per-route role matrix over 8 identities x 8 routes; a bank user sees only its own organisation, clients, keys and requests (foreign ids indistinguishable from nonexistent); cannot request or revoke for another organisation; row-level security proven directly on the portal's DB role (no scope = no rows; restricted scope cannot be widened).
* **Web application security** (m4a-auth, 27 tests): no default accounts; weak MFA, password-only, stale authentication, unprovisioned or disabled identities refused; seven hostile ID-token modes refused (aud, iss, nonce, expired, unsigned, HS256, wrong key); state/PKCE/code replay; `__Host-` HttpOnly Secure SameSite=Strict cookies with only a hash stored; rotation at login; idle (15 min) and absolute (8 h) timeouts; CSRF (token + Origin + form encoding); XSS (auto-escaping, CSP with no script at all); source-address allow-list; participant and admin planes share no routes or credentials; every view, change and denial audited.

## Defects found by my own tests and fixed
- SSRF validator trusted a normalised hostname: `https://2130706433` became `127.0.0.1`. It now refuses any host whose written form differs from the parsed one.
- Invalid tier definitions returned HTTP 500 instead of 400.
- The participant role lacked `SELECT` on entitlements/allow-list (caught by the full suite).
- A routing *prefix* in an audit record tripped the audit privacy guard (E.164 pattern) and failed the request closed; audit entries for prefix/porting targets now carry only the target type.

## CI finding on PR #11 and its fix
CodeQL (high): the admin routes had no rate limiting. Added `@fastify/rate-limit` to the admin interface: per session (per source address before sign-in), 600/min by default, 60/min on the sign-in endpoints; test proves per-session isolation and sign-in throttling. Counters are in-process (R-015: not shared across several admin instances).

## Honest limits (new residual risks R-010..R-014, see threat model)
- R-010 Telco conformance results are asserted by the platform process (the database cannot call a telco); a compromised portal could record one. Activation still needs a second person who sees the results.
- R-011 The portal shares the number-hashing key with the participant plane (needed to hash numbers for porting). Token-signing keys are NOT shared (separate key directory).
- R-012 Endpoint validation is by name and allow-list; DNS answers are not pinned (DNS-rebinding between validation and connection is not prevented).
- R-013 Telco certificate onboarding (pinning a telco's own CA/cert per connection) is not implemented; outbound mTLS trusts the deployment's CA bundle.
- R-014 Single-person actions are deliberate (engage kill switch, revoke credential, suspend organisation, advance to testing); they are role-gated, audited and alerted but not two-person.
- The mock IdP stands in for a real enterprise IdP; WebAuthn itself is performed by the IdP, not tested here.
- Dashboards, logs, alert configuration and the developer portal are M4b. The audit log search/export UI is not built yet (audit rows are written for every view and change).
- Compose file still unexecuted (no Docker daemon). Not on Neon (D-002).
