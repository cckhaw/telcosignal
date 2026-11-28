# Design note: Number Verification (not built in this release)

> Sandbox reference only. This is a design and a decision record, not an implementation. Status: **proposed, not approved**.

## What it is

CAMARA Number Verification lets a service confirm that the phone number a user claims is the SIM currently attached to **the data connection the user is using right now**,
with no SMS code. The operator's network authenticates the device (header enrichment or an operator redirect), then the service asks the operator "is this the number?"

## Why it is not a signal like the others

The other eight signals are **server-to-server** questions about a number the participant already holds: the participant calls the platform, the platform calls the telco.
Number Verification is **device-to-operator**: the answer only exists if the end user's own request travels over the operator's mobile network, so there is an
authorisation-code redirect through the operator and a browser or app on the subscriber's device. Putting it behind the participant plane as a "check" call would either
(a) not work (no device session) or (b) silently weaken it (a server-side call can only be answered by a lookup, which is what SIM-swap and tenure already are).

| Property | Server-to-server signals (built) | Number Verification |
|---|---|---|
| Caller on the wire | Participant server (mTLS, signed request) | The subscriber's device, over the operator network |
| Consent | Consent reference registered by the participant | The act of the user following the redirect (the operator holds it) |
| Result | TRUE / FALSE / UNAVAILABLE / NOT_SUPPORTED | verified true / false, bound to that session |
| Replay model | `jti` + signed request | Single-use authorisation code, state, PKCE |
| Hosting | mTLS endpoint (not Vercel) | A public redirect URI the operator can reach, plus an operator-side flow |

## Proposed integration (when a telco and a participant commit to it)

1. **A separate plane**, not a route on the participant API: a small "verification broker" with its own origin, so the participant mTLS plane keeps its minimal surface.
2. Participant requests a verification session (mTLS, signed, scope `number-verification:start`) with `purposeCode` and a consent reference. The broker returns a one-time
   authorisation URL on the operator's domain with `state`, a nonce and PKCE.
3. The user's device opens the URL **over mobile data**; the operator authenticates the SIM and redirects to the broker's callback with a code.
4. The broker exchanges the code with the operator (mTLS, `private_key_jwt`), calls the operator's verify endpoint with the claimed number (supplied by the participant at step 2, **held only as a keyed hash plus an encrypted blob for the session lifetime**) and records a four-state result.
5. The participant polls or is called back **with a signed, single-use result bound to the session id**. Wi-Fi, a mismatched number, a replayed code or an expired session are never FALSE: they are UNAVAILABLE ("could not verify"), because "the user was on Wi-Fi" is not evidence of fraud.

## Controls the build would need (not yet designed in detail)

* Redirect URI allow-list per participant; exact-match only; no open redirect; `state` bound to the session; PKCE; short code lifetime (<= 60 s); single use.
* The result must say "verified on this session" only; it must never be reusable as a standing assertion about the number.
* The broker must be rate-limited per participant **and** per number (an attacker triggering verification prompts is a harassment and enumeration vector).
* Operator-specific behaviour (header enrichment vs redirect) differs; each telco needs its own conformance tests.
* Fallback behaviour is a **product** decision: "could not verify" must route to a stronger factor, never to approval.

## Decision requested

Do not build until at least one Malaysian operator confirms it exposes Number Verification and a participant commits to an app or browser flow that can run over mobile data.
Until then the platform's answer to "does this person hold this SIM right now?" is: combine SIM swap, device swap and call forwarding (all built).
Recorded as decision D-008 in `docs/decisions-needed.md` and risk R-030.
