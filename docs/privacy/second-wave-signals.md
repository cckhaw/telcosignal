# Privacy inputs: second-wave signals (M7)

> Sandbox only, synthetic data only. This is an **input** to a privacy impact assessment, not an assessment, and it is not legal advice. No claim of compliance with any
> law is made. Whether any signal below may be used for a given purpose, on a given lawful basis, in a given country is a question for qualified counsel (human gate G3).

| Signal | What the participant learns | Personal data involved | Sensitivity | Extra controls in this build |
|---|---|---|---|---|
| `NUMBER_RECYCLING` | One boolean: the number was reassigned to a different subscriber since a date | The number (never stored; keyed hash only), a date | Medium: reveals that a number changed hands, not to whom | Look-back capped at 5 years; date never stored or logged |
| `KYC_TENURE` | One boolean: the line has been active for at least N days | The number, N | Medium: reveals relationship length with the operator | N capped at 3650; never stored or logged |
| `DEVICE_LOCATION` | One boolean: the device is inside a circle the participant chose | The number, a latitude, a longitude, a radius | **High**: location of a person | Explicit per-subject consent that lists this signal; radius floor 2,000 m; separate per-subject cap (default 4 per hour); coordinates and radius never stored, logged, audited or metered; PARTIAL is UNAVAILABLE; one boolean only |
| `DEVICE_ROAMING` | One boolean: the device is roaming abroad now | The number | Medium-high: reveals travel | Country code and name are discarded at the adapter and are not in the API; one boolean only |

## What is and is not stored

Stored per call (as for every signal): organisation, signal, telco, outcome, billable flag, timings, correlation id, keyed subject hash prefix in the request log. **Not stored anywhere:**
the number, coordinates, radius, specified date, tenure days, the telco's country, any timestamp the telco returns. Tests assert this
(`tests/security/m7-second-wave.test.ts`: "coordinates, radius and dates are never in logs, the audit chain, usage records or traces").
Redaction paths cover `latitude`, `longitude`, `radiusMeters`, `specifiedDate`, `minTenureDays`, `area` and `params` in logs.

## Why location needs more than the others

* Repeated yes/no questions about a moving circle can **triangulate** a person (AB-11). The radius floor and the low per-subject cap make this slow and visible;
  they do **not** make it impossible for a patient, consented, malicious participant. The residual risk is recorded as R-029.
* The participant chooses the area, so a legitimate use ("is the device in the country the customer says they are in?") needs a country-sized circle (up to 200 km radius); a bank that needs more should ask a different question.
* A consent for SIM swap does not cover location: the consent record names each signal and the check is per signal (tested).

## Open questions for counsel and the privacy owner (not answered here)

1. Is location verification for fraud prevention permitted without a fresh, specific consent at the moment of the transaction, in each market served? The build requires a consent reference per subject and signal and an expiry; it cannot judge whether that consent is valid in law.
2. Are tenure and recycling "personal data" in the relevant jurisdiction when they describe a subscription rather than a person? The build treats them as personal.
3. Retention of the telco-side logs of these calls is the telco's obligation; it is not controlled here.
4. Cross-border: a roaming or location answer about a person abroad may engage another country's rules.

## Not built, on purpose

* **KYC Fill-in** (the operator returns the registered identity): returns personal data rather than a signal; no lawful-basis story has been agreed.
* **Device connectivity status** (reachable / not reachable): weak fraud value, and it reveals when a person's phone is off. Roaming status was built instead.
* **Location retrieval and geofencing subscriptions**: they return or stream where a person is. Out of scope.
