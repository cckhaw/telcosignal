# Pinned CAMARA API definitions (official camaraproject repositories)
Copied verbatim; never edited. Verify with `sha256sum -c SHA256SUMS`.

| File | Repository | Release tag | Commit |
|---|---|---|---|
| sim-swap.yaml | camaraproject/SimSwap | r4.3 | b8bc48129250d9b425148a8be56f9d31506fb30f |
| device-swap.yaml | camaraproject/DeviceSwap | r4.3 | 5194cabf747a42f354ca42fe89b20cc7163377de |
| call-forwarding-signal.yaml | camaraproject/CallForwardingSignal | r4.3 | 123830f45de8528e065b2cd05d93b86f22d196bc |
| kyc-match.yaml | camaraproject/KnowYourCustomer | r2.2 | 604427aaea70c58efd5f325b451863953c352d6c |
| number-recycling.yaml | camaraproject/NumberRecycling | r3.3 | ce69c2f674c5aa2db2f7b6990d12d15f3cc70ddb |
| kyc-tenure.yaml | camaraproject/Tenure | r3.4 | e00e6995acc59cb4d199ce1c8b490222f3031af5 |
| location-verification.yaml | camaraproject/DeviceLocation | r4.3 | c8cb61f065767bdd6b23dbe383bd51ba35529744 |
| device-roaming-status.yaml | camaraproject/DeviceStatus | r2.2 | 555e31fa6de8fb1d5ad4ba8706c6f18f42bd0f20 |

Telco A (mock) implements these definitions as published. The **participant-facing** platform API
deliberately deviates (documented in docs/architecture.md section 11): four-state result instead of boolean,
no 404 for unknown numbers (existence oracle), mandatory purpose + consent reference.

The last four files are the second-wave signals (number recycling, KYC tenure, device location verification, device roaming status).
Their API versions are pre-1.0 or newer than the first four (see each file's `info.version`); the adapter path test fails if a pinned file and the adapter disagree.
Only the circle area type and the `phoneNumber` device identifier of location verification are used; for roaming status only the boolean `roaming` is read (country code and name are deliberately discarded).
