-- 003 (M3): per-participant limit overrides, abuse flags, pricing (placeholders), telco cost, immutable statements.
-- Prices are PLACEHOLDERS in integer minor units (no floating point money).

CREATE TABLE rate_limit_override (
  org_id               uuid NOT NULL REFERENCES organisations(id),
  signal               text NOT NULL REFERENCES signals(id),
  max_per_minute       integer NOT NULL CHECK (max_per_minute BETWEEN 1 AND 100000),
  PRIMARY KEY (org_id, signal)
);

-- Abuse flags hold counts only: never numbers or hashes of numbers.
CREATE TABLE abuse_flag (
  id          bigserial PRIMARY KEY,
  ts          timestamptz NOT NULL DEFAULT now(),
  org_id      uuid NOT NULL REFERENCES organisations(id),
  client_id   text NOT NULL,
  kind        text NOT NULL CHECK (kind IN ('HIGH_DISTINCT_SUBJECTS','SEQUENTIAL_RANGE','CONSENT_PROBING','NUMBER_REPEAT')),
  observed    integer NOT NULL CHECK (observed >= 0),
  threshold   integer NOT NULL CHECK (threshold >= 0),
  window_s    integer NOT NULL,
  status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','suspended','dismissed')),
  correlation_id text NOT NULL
);

CREATE TABLE price_plan (
  id                 text PRIMARY KEY CHECK (id ~ '^[a-z0-9-]{3,40}$'),
  currency           text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  platform_fee_minor integer NOT NULL CHECK (platform_fee_minor >= 0),          -- per billable query
  signal_price_minor jsonb NOT NULL,                                            -- {"SIM_SWAP": 50, ...} per billable query
  tiers              jsonb NOT NULL                                             -- [{"upTo": 1000, "pct": 100}, {"upTo": null, "pct": 80}] marginal, monthly volume per signal
);
CREATE TABLE org_price_plan (
  org_id         uuid NOT NULL REFERENCES organisations(id),
  plan_id        text NOT NULL REFERENCES price_plan(id),
  effective_from timestamptz NOT NULL,
  PRIMARY KEY (org_id, effective_from)
);
CREATE TABLE telco_cost (
  telco_id       text NOT NULL REFERENCES telcos(id),
  signal         text NOT NULL REFERENCES signals(id),
  cost_minor     integer NOT NULL CHECK (cost_minor >= 0),
  effective_from timestamptz NOT NULL,
  PRIMARY KEY (telco_id, signal, effective_from)
);

CREATE TABLE statement (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind          text NOT NULL CHECK (kind IN ('participant','telco')),
  org_id        uuid REFERENCES organisations(id),
  telco_id      text REFERENCES telcos(id),
  period_start  timestamptz NOT NULL,
  period_end    timestamptz NOT NULL CHECK (period_end > period_start),
  currency      text NOT NULL,
  lines         jsonb NOT NULL,
  usage_count   integer NOT NULL CHECK (usage_count >= 0),
  total_minor   bigint NOT NULL CHECK (total_minor >= 0),
  usage_digest  bytea NOT NULL CHECK (length(usage_digest) = 32),   -- sha256 over the ordered ids of the usage rows included
  generated_at  timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'participant' AND org_id IS NOT NULL AND telco_id IS NULL) OR (kind = 'telco' AND telco_id IS NOT NULL AND org_id IS NULL))
);
CREATE EXTENSION IF NOT EXISTS btree_gist;     -- trusted extension: the database owner may create it
CREATE UNIQUE INDEX statement_unique ON statement(kind, COALESCE(org_id::text, telco_id), period_start, period_end);
-- Double-billing guard: two statements for the same subject may never cover overlapping periods (the same usage would be charged twice).
ALTER TABLE statement ADD CONSTRAINT statement_no_overlap
  EXCLUDE USING gist (kind WITH =, (COALESCE(org_id::text, telco_id)) WITH =, tstzrange(period_start, period_end) WITH &&);
CREATE TRIGGER statement_no_update BEFORE UPDATE OR DELETE ON statement FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER statement_no_truncate BEFORE TRUNCATE ON statement FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

ALTER TABLE statement ENABLE ROW LEVEL SECURITY; ALTER TABLE statement FORCE ROW LEVEL SECURITY;
CREATE POLICY statement_tenant  ON statement FOR SELECT TO ts_app USING (kind = 'participant' AND org_id = current_org());
CREATE POLICY statement_billing ON statement FOR ALL    TO ts_billing USING (true) WITH CHECK (true);
CREATE POLICY statement_rep     ON statement FOR SELECT TO ts_reporting USING (true);
CREATE POLICY statement_owner   ON statement FOR ALL    TO ts_migrator USING (true) WITH CHECK (true);
CREATE POLICY usage_billing     ON usage_record FOR SELECT TO ts_billing USING (true);

GRANT SELECT ON rate_limit_override, price_plan, org_price_plan, telco_cost, telcos TO ts_app;
GRANT INSERT ON abuse_flag TO ts_app;
GRANT USAGE ON SEQUENCE abuse_flag_id_seq TO ts_app;
GRANT SELECT ON statement TO ts_app, ts_reporting;
GRANT SELECT ON abuse_flag, rate_limit_override, price_plan, org_price_plan, telco_cost TO ts_reporting;
-- Billing role: the only non-owner able to read usage across organisations and write statements. No other tables.
GRANT USAGE ON SCHEMA public TO ts_billing;
GRANT SELECT ON usage_record, price_plan, org_price_plan, telco_cost, telcos, organisations TO ts_billing;
GRANT SELECT, INSERT ON statement TO ts_billing;

-- Auto-suspension path for abuse detection: the application role cannot write kill_switch directly; it may only
-- call this narrow function (participant scope only, known clients only), owned by a role that can do nothing else.
CREATE FUNCTION abuse_suspend(p_client_id text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM clients WHERE client_id = p_client_id) THEN RETURN false; END IF;
  INSERT INTO kill_switch(scope, key, enabled) VALUES ('participant', p_client_id, true)
    ON CONFLICT (scope, key) DO UPDATE SET enabled = true;
  RETURN true;
END $$;
GRANT CREATE ON SCHEMA public TO ts_switch;
ALTER FUNCTION abuse_suspend(text) OWNER TO ts_switch;
REVOKE CREATE ON SCHEMA public FROM ts_switch;
GRANT SELECT ON clients TO ts_switch;
GRANT SELECT, INSERT, UPDATE ON kill_switch TO ts_switch;
REVOKE ALL ON FUNCTION abuse_suspend(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION abuse_suspend(text) TO ts_app;
CREATE POLICY clients_switch ON clients FOR SELECT TO ts_switch USING (true);
