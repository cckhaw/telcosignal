# Kill switches
**Purpose** Stop traffic quickly for one participant, one telco or one signal. **Owner (proposed)** Head of Operations. **Roles** engage: platform_admin, operations. Lift: requested by operations/platform_admin, **approved by a different person** (platform_admin or operations) with a fresh sign-in.

## Scopes and effect (tested)
- **participant** (client id): every request from that client is refused with 403 at once (not billed).
- **telco** (telco id): requests that would route to it answer UNAVAILABLE without calling the telco (not billed); other telcos unaffected.
- **signal** (SIM_SWAP, DEVICE_SWAP, CALL_FORWARDING, KYC_MATCH, NUMBER_RECYCLING, KYC_TENURE, DEVICE_LOCATION, DEVICE_ROAMING): requests answer UNAVAILABLE for that signal.
Switches are read from the database on every request and fail closed if the state cannot be read.

## Engage
Portal -> Kill switches -> Engage (scope, key). Immediate, audited, emits a SIEM-ready event. Finance, integration engineers and auditors cannot engage.
## Lift
Kill switches -> "Request lift". A second authorised person reviews the request (diff view) and approves after re-authenticating. The requester cannot approve; the schema forbids it.
## Related immediate actions (also single-person by design)
Suspend an organisation (cuts its tokens at once); revoke a credential (effective at once).
## Verification
Dashboard and Logs show the reason class `kill_switch`; no telco calls are made; the audit trail records engage and lift with both identities.
