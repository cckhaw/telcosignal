-- 001_init: core schema, roles/grants, RLS, append-only audit. Synthetic data only.
-- Run as ts_migrator (schema owner). Roles are created by scripts/db-setup (superuser, passwords generated).

CREATE TABLE organisations (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  kind        text NOT NULL CHECK (kind IN ('bank','telco','platform')),
  state       text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft','testing','pending_approval','active','suspended','retired')),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE clients (
  client_id   text PRIMARY KEY CHECK (client_id ~ '^[a-z0-9][a-z0-9_-]{2,62}$'),
  org_id      uuid NOT NULL REFERENCES organisations(id),
  state       text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended','revoked')),
  scopes      text[] NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Public keys only: the platform never holds a participant private key.
CREATE TABLE client_keys (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id   text NOT NULL REFERENCES clients(client_id),
  kid         text NOT NULL,
  jwk         jsonb NOT NULL CHECK (NOT (jwk ? 'd') AND NOT (jwk ? 'p') AND NOT (jwk ? 'q') AND NOT (jwk ? 'k')),
  cert_sha256 text NOT NULL CHECK (cert_sha256 ~ '^[A-Za-z0-9_-]{43}$'),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz,
  UNIQUE (client_id, kid)
);

CREATE TABLE consents (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid NOT NULL REFERENCES organisations(id),
  consent_ref  text NOT NULL CHECK (consent_ref ~ '^[A-Za-z0-9._:-]{4,128}$'),
  subject_hash bytea NOT NULL CHECK (length(subject_hash) = 32),   -- HMAC-SHA256(msisdn); never the number
  purpose_code text NOT NULL CHECK (purpose_code IN ('FRAUD_PREVENTION','ACCOUNT_TAKEOVER_CHECK','TRANSACTION_RISK')),
  signals      text[] NOT NULL CHECK (cardinality(signals) > 0),
  granted_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  UNIQUE (org_id, consent_ref)
);

CREATE TABLE telcos (
  id        text PRIMARY KEY CHECK (id ~ '^[a-z0-9-]{1,30}$'),
  adapter   text NOT NULL CHECK (adapter IN ('camara','proprietary','aggregator')),
  base_url  text NOT NULL,
  state     text NOT NULL DEFAULT 'active' CHECK (state IN ('active','suspended','retired'))
);

CREATE TABLE route_prefix (
  prefix  text PRIMARY KEY CHECK (prefix ~ '^\+[1-9][0-9]{1,14}$'),
  telco_id text NOT NULL REFERENCES telcos(id)
);

CREATE TABLE kill_switch (
  scope    text NOT NULL CHECK (scope IN ('participant','telco','signal')),
  key      text NOT NULL,
  enabled  boolean NOT NULL DEFAULT false,
  PRIMARY KEY (scope, key)
);

CREATE TABLE usage_record (
  id            bigserial PRIMARY KEY,
  ts            timestamptz NOT NULL DEFAULT now(),
  org_id        uuid NOT NULL REFERENCES organisations(id),
  signal        text NOT NULL,
  telco_id      text,
  outcome       text NOT NULL CHECK (outcome IN ('TRUE','FALSE','UNAVAILABLE','NOT_SUPPORTED','REJECTED')),
  billable      boolean NOT NULL DEFAULT false,    -- never true on platform/telco failure
  total_ms      integer NOT NULL CHECK (total_ms >= 0),
  telco_ms      integer NOT NULL DEFAULT 0 CHECK (telco_ms >= 0),
  correlation_id text NOT NULL,
  CHECK (NOT billable OR outcome IN ('TRUE','FALSE'))
);

-- Audit log: append-only and hash-chained. Canonical text is plain fields so any verifier can recompute.
CREATE TABLE audit_log (
  seq            bigint PRIMARY KEY,
  ts_us          bigint NOT NULL,
  correlation_id text NOT NULL,
  actor          text NOT NULL,
  action         text NOT NULL,
  org_id         text NOT NULL DEFAULT '',
  outcome        text NOT NULL,
  detail_text    text NOT NULL,
  prev_hash      bytea NOT NULL,
  hash           bytea NOT NULL
);

CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'append-only table: % not permitted', TG_OP USING ERRCODE = '42501'; END $$;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER usage_no_update BEFORE UPDATE OR DELETE ON usage_record FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER usage_no_truncate BEFORE TRUNCATE ON usage_record FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- Row-level security (forced, so even the owner is subject to it).
ALTER TABLE consents     ENABLE ROW LEVEL SECURITY; ALTER TABLE consents     FORCE ROW LEVEL SECURITY;
ALTER TABLE usage_record ENABLE ROW LEVEL SECURITY; ALTER TABLE usage_record FORCE ROW LEVEL SECURITY;
ALTER TABLE clients      ENABLE ROW LEVEL SECURITY; ALTER TABLE clients      FORCE ROW LEVEL SECURITY;
ALTER TABLE client_keys  ENABLE ROW LEVEL SECURITY; ALTER TABLE client_keys  FORCE ROW LEVEL SECURITY;

CREATE FUNCTION current_org() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.org_id', true), '')::uuid $$;

CREATE POLICY consents_tenant ON consents FOR ALL TO ts_app USING (org_id = current_org()) WITH CHECK (org_id = current_org());
CREATE POLICY usage_tenant_sel ON usage_record FOR SELECT TO ts_app USING (org_id = current_org());
CREATE POLICY usage_tenant_ins ON usage_record FOR INSERT TO ts_app WITH CHECK (org_id = current_org());
CREATE POLICY clients_tenant ON clients FOR SELECT TO ts_app USING (org_id = current_org());
CREATE POLICY client_keys_tenant ON client_keys FOR SELECT TO ts_app
  USING (client_id IN (SELECT client_id FROM clients WHERE org_id = current_org()));
-- Read-only reporting role: explicit policies (not BYPASSRLS).
CREATE POLICY consents_rep ON consents FOR SELECT TO ts_reporting USING (true);
CREATE POLICY usage_rep ON usage_record FOR SELECT TO ts_reporting USING (true);
CREATE POLICY clients_rep ON clients FOR SELECT TO ts_reporting USING (true);
CREATE POLICY client_keys_rep ON client_keys FOR SELECT TO ts_reporting USING (true);
-- Owner policies so migrations/seeding by ts_migrator work while FORCE RLS stays on.
CREATE POLICY consents_owner ON consents FOR ALL TO ts_migrator USING (true) WITH CHECK (true);
CREATE POLICY usage_owner ON usage_record FOR ALL TO ts_migrator USING (true) WITH CHECK (true);
CREATE POLICY clients_owner ON clients FOR ALL TO ts_migrator USING (true) WITH CHECK (true);
CREATE POLICY client_keys_owner ON client_keys FOR ALL TO ts_migrator USING (true) WITH CHECK (true);

-- Authentication lookups happen before the organisation is known: narrow SECURITY DEFINER functions
-- owned by a dedicated role that may read only these two tables. ts_app gets EXECUTE, not table access to other tenants.
CREATE FUNCTION authn_lookup_client(p_client_id text)
RETURNS TABLE(client_id text, org_id uuid, state text, scopes text[], org_state text, org_kind text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT c.client_id, c.org_id, c.state, c.scopes, o.state, o.kind
  FROM clients c JOIN organisations o ON o.id = c.org_id WHERE c.client_id = p_client_id $$;
CREATE FUNCTION authn_client_keys(p_client_id text)
RETURNS TABLE(kid text, jwk jsonb, cert_sha256 text, expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT k.kid, k.jwk, k.cert_sha256, k.expires_at, k.revoked_at FROM client_keys k WHERE k.client_id = p_client_id $$;

CREATE FUNCTION audit_append(p_correlation text, p_actor text, p_action text, p_org text, p_outcome text, p_detail text)
RETURNS TABLE(seq bigint, ts_us bigint, prev_hash bytea, hash bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE last_seq bigint; last_hash bytea; new_seq bigint; now_us bigint; canon text; h bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(7283001);
  SELECT a.seq, a.hash INTO last_seq, last_hash FROM audit_log a ORDER BY a.seq DESC LIMIT 1;
  IF last_seq IS NULL THEN last_seq := 0; last_hash := decode(repeat('00', 32), 'hex'); END IF;
  new_seq := last_seq + 1;
  now_us := (extract(epoch FROM clock_timestamp()) * 1000000)::bigint;
  canon := new_seq || '|' || now_us || '|' || p_correlation || '|' || p_actor || '|' || p_action || '|' || p_org || '|' || p_outcome || '|' || p_detail;
  h := sha256(last_hash || convert_to(canon, 'UTF8'));
  INSERT INTO audit_log(seq, ts_us, correlation_id, actor, action, org_id, outcome, detail_text, prev_hash, hash)
    VALUES (new_seq, now_us, p_correlation, p_actor, p_action, p_org, p_outcome, p_detail, last_hash, h);
  RETURN QUERY SELECT new_seq, now_us, last_hash, h;
END $$;

-- Ownership of definer functions moves to restricted roles (they have BYPASSRLS / audit write only).
GRANT CREATE ON SCHEMA public TO ts_lookup, ts_audit;
ALTER FUNCTION authn_lookup_client(text)  OWNER TO ts_lookup;
ALTER FUNCTION authn_client_keys(text)    OWNER TO ts_lookup;
ALTER FUNCTION audit_append(text,text,text,text,text,text) OWNER TO ts_audit;
REVOKE CREATE ON SCHEMA public FROM ts_lookup, ts_audit;
GRANT SELECT ON clients, client_keys, organisations TO ts_lookup;
GRANT SELECT, INSERT ON audit_log TO ts_audit;

-- Least-privilege grants. ts_app: no ownership, no DDL, no audit table access.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ts_app, ts_reporting, ts_lookup, ts_audit;
GRANT SELECT ON clients, client_keys TO ts_app;
GRANT SELECT, INSERT, UPDATE ON consents TO ts_app;            -- UPDATE: revocation only (column-limited below)
REVOKE UPDATE ON consents FROM ts_app;
GRANT UPDATE (revoked_at) ON consents TO ts_app;
GRANT SELECT, INSERT ON usage_record TO ts_app;
GRANT USAGE ON SEQUENCE usage_record_id_seq TO ts_app;
GRANT SELECT ON telcos, route_prefix, kill_switch TO ts_app;
GRANT EXECUTE ON FUNCTION authn_lookup_client(text), authn_client_keys(text), audit_append(text,text,text,text,text,text) TO ts_app;
GRANT EXECUTE ON FUNCTION current_org() TO ts_app, ts_reporting;
GRANT SELECT ON consents, usage_record, clients, client_keys, organisations, telcos, route_prefix, audit_log TO ts_reporting;
