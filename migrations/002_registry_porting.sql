-- 002: signal registry, per-telco coverage, number-porting overlay (keyed hash only; never raw numbers).
CREATE TABLE signals (
  id          text PRIMARY KEY CHECK (id IN ('SIM_SWAP','DEVICE_SWAP','CALL_FORWARDING','KYC_MATCH')),
  scope       text NOT NULL UNIQUE,
  api_version text NOT NULL,
  enabled     boolean NOT NULL DEFAULT true,
  camara_ref  text NOT NULL
);
INSERT INTO signals(id, scope, api_version, camara_ref) VALUES
  ('SIM_SWAP','sim-swap:check','v1','SimSwap r4.3 (b8bc481)'),
  ('DEVICE_SWAP','device-swap:check','v1','DeviceSwap r4.3 (5194cab)'),
  ('CALL_FORWARDING','call-forwarding:check','v1','CallForwardingSignal r4.3 (123830f)'),
  ('KYC_MATCH','kyc-match:check','v1','KnowYourCustomer r2.2 (604427a)');

CREATE TABLE telco_signal_coverage (
  telco_id text NOT NULL REFERENCES telcos(id),
  signal   text NOT NULL REFERENCES signals(id),
  PRIMARY KEY (telco_id, signal)
);

CREATE TABLE porting (
  subject_hash   bytea NOT NULL CHECK (length(subject_hash) = 32),
  telco_id       text NOT NULL REFERENCES telcos(id),
  effective_from timestamptz NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (subject_hash, effective_from)
);
CREATE INDEX porting_lookup ON porting(subject_hash, effective_from DESC);

GRANT SELECT ON signals, telco_signal_coverage, porting TO ts_app, ts_reporting;
