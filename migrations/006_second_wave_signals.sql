-- 006: second-wave signals (number recycling, KYC tenure, device location verification, device roaming).
-- Registry rows are inserted ENABLED but no telco has coverage until it is added through the two-person coverage change,
-- so nothing is routed anywhere until a human approves it. Location is a sensitive signal: see docs/privacy/second-wave-signals.md.
ALTER TABLE signals DROP CONSTRAINT signals_id_check;
ALTER TABLE signals ADD CONSTRAINT signals_id_check CHECK (id IN ('SIM_SWAP','DEVICE_SWAP','CALL_FORWARDING','KYC_MATCH','NUMBER_RECYCLING','KYC_TENURE','DEVICE_LOCATION','DEVICE_ROAMING'));
INSERT INTO signals(id, scope, api_version, camara_ref) VALUES
  ('NUMBER_RECYCLING','number-recycling:check','v1','NumberRecycling r3.3 (ce69c2f)'),
  ('KYC_TENURE','kyc-tenure:check','v1','Tenure r3.4 (e00e699)'),
  ('DEVICE_LOCATION','device-location:check','v1','DeviceLocation r4.3 location-verification (c8cb61f)'),
  ('DEVICE_ROAMING','device-roaming:check','v1','DeviceStatus r2.2 device-roaming-status (555e31f)');
