# Pinned CAMARA API definitions (official camaraproject repositories)
Copied verbatim; never edited. Verify with `sha256sum -c SHA256SUMS`.

| File | Repository | Release tag | Commit |
|---|---|---|---|
| sim-swap.yaml | camaraproject/SimSwap | r4.3 | b8bc48129250d9b425148a8be56f9d31506fb30f |
| device-swap.yaml | camaraproject/DeviceSwap | r4.3 | 5194cabf747a42f354ca42fe89b20cc7163377de |
| call-forwarding-signal.yaml | camaraproject/CallForwardingSignal | r4.3 | 123830f45de8528e065b2cd05d93b86f22d196bc |
| kyc-match.yaml | camaraproject/KnowYourCustomer | r2.2 | 604427aaea70c58efd5f325b451863953c352d6c |

Telco A (mock) implements these definitions as published. The **participant-facing** platform API
deliberately deviates (documented in docs/architecture.md section 11): four-state result instead of boolean,
no 404 for unknown numbers (existence oracle), mandatory purpose + consent reference.
