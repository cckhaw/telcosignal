# Admin portal design (M4a)

Isolated admin interface: separate listener/port/TLS context and (in compose) separate network; no participant routes exist on it, and participant tokens are not accepted. Optional source-address allow-list (`TS_ADMIN_ALLOWED_CIDRS`, default loopback). Server-rendered HTML only (no client-side script): CSP `script-src 'none'`.

## Authentication
OIDC authorization-code + PKCE (S256) against an enterprise IdP (mock IdP in the sandbox). ID token verified with `jose` (issuer, audience, nonce, expiry, ES256 only, JWKS from the pinned IdP). **Fail closed unless** `acr` is the phishing-resistant level and `amr` contains `hwk`. No local passwords. The subject must already exist and be active in `admin_user` (no just-in-time provisioning, no default accounts; first platform admins are created at setup with subjects the operator supplies). Sessions: random 256-bit id, only its SHA-256 stored; `__Host-` cookie, HttpOnly, Secure, SameSite=Strict; idle 15 min, absolute 8 h; rotated at login; server-side revocation on logout.

## Authorisation and isolation
Role matrix enforced server-side per route AND in the database (`config_role_policy`). Roles: platform_admin, operations, integration_engineer, security_auditor (read-only), finance, telco_user, bank_user (restricted to one organisation). Row-level security on the admin database role (`ts_admin`): staff scope sees all, restricted users only their organisation's rows.

## Two-person rule (database-enforced)
`ts_admin` has **no write grant** on any high-risk table. Mutations happen only inside `SECURITY DEFINER` functions owned by `ts_config`. A change is requested (`cfg_request`), then decided by a different person (`cfg_decide`), which in one transaction verifies: role may approve this kind; approver != requester (also a CHECK constraint); payload hash unchanged (payload is immutable); base version not stale; request not expired (24 h); approver re-authenticated within 5 minutes (step-up); then applies the mutation and appends a history row (before/after). Rollback is itself a gated change. Immediate single-person actions (deliberately): engage a kill switch, revoke a credential, suspend an organisation. Lifting a kill switch, issuing/rotating keys, prices, limits, policy, routing/porting, entitlements, activation/retirement and admin users need approval.

## Onboarding
States draft -> testing -> pending_approval -> active -> suspended -> retired. Activation requires every required test to have passed (computed by the database for bank certification from real usage/audit evidence; recorded by the platform for telco conformance runs) AND a second person's approval.

## Credentials
Public-key registration (platform never holds participant private keys). Optional sandbox convenience: the platform generates a keypair, shows the private key ONCE in the response and never stores it. Rotation overlaps old/new keys; revocation is immediate.
