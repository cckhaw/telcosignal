-- 004 (M4a): admin identity, sessions, versioned config with DATABASE-ENFORCED two-person approval, onboarding, credentials.
-- ts_admin (the portal's DB role) has NO write grant on any high-risk table; mutations happen only inside SECURITY DEFINER
-- functions owned by ts_config, which verify role, approver != requester, payload integrity, staleness, expiry and re-authentication.

-- ---------- schema changes to existing tables ----------
ALTER TABLE telcos DROP CONSTRAINT telcos_state_check;
ALTER TABLE telcos ADD CONSTRAINT telcos_state_check CHECK (state IN ('draft','testing','active','suspended','retired'));
ALTER TABLE telcos ADD COLUMN org_id uuid REFERENCES organisations(id);

CREATE TABLE endpoint_allowlist (origin text PRIMARY KEY CHECK (origin ~ '^https://[a-z0-9.-]+(:[0-9]{1,5})?$'));
CREATE TABLE platform_setting (
  key   text PRIMARY KEY CHECK (key IN ('consent.max_days','sandbox.allow_loopback')),
  value jsonb NOT NULL
);
INSERT INTO platform_setting VALUES ('consent.max_days','400'), ('sandbox.allow_loopback','true');
CREATE TABLE org_entitlement (
  org_id   uuid NOT NULL REFERENCES organisations(id),
  signal   text NOT NULL REFERENCES signals(id),
  purposes text[] NOT NULL CHECK (cardinality(purposes) > 0),
  PRIMARY KEY (org_id, signal)
);
CREATE TABLE api_version (
  version text PRIMARY KEY CHECK (version ~ '^v[0-9]{1,3}$'),
  status  text NOT NULL CHECK (status IN ('current','deprecated','sunset')),
  sunset_date date,
  note    text NOT NULL DEFAULT ''
);
INSERT INTO api_version(version, status) VALUES ('v1','current');
CREATE TABLE onboarding_test (
  id       bigserial PRIMARY KEY,
  org_id   uuid NOT NULL REFERENCES organisations(id),
  test_key text NOT NULL CHECK (test_key ~ '^[a-z_]+(:[A-Z_]+)?$'),
  status   text NOT NULL CHECK (status IN ('pass','fail')),
  evidence jsonb NOT NULL CHECK (pg_column_size(evidence) < 4096),
  run_by   text NOT NULL,
  run_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------- admin identity ----------
CREATE TABLE admin_user (
  sub          text PRIMARY KEY CHECK (sub ~ '^[A-Za-z0-9._:@-]{3,128}$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 100),
  role         text NOT NULL CHECK (role IN ('platform_admin','operations','integration_engineer','security_auditor','finance','telco_user','bank_user')),
  org_id       uuid REFERENCES organisations(id),
  state        text NOT NULL DEFAULT 'active' CHECK (state IN ('active','disabled')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK ((role IN ('telco_user','bank_user')) = (org_id IS NOT NULL))
);
CREATE TABLE admin_session (
  id_hash      bytea PRIMARY KEY CHECK (length(id_hash) = 32),     -- SHA-256 of the cookie value; the id itself is never stored
  sub          text NOT NULL REFERENCES admin_user(sub),
  csrf         text NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  auth_time    timestamptz NOT NULL,
  ended_at     timestamptz
);

-- ---------- versioned configuration with approval ----------
CREATE TABLE config_role_policy (
  kind        text PRIMARY KEY,
  can_request text[] NOT NULL,
  can_approve text[] NOT NULL
);
INSERT INTO config_role_policy(kind, can_request, can_approve) VALUES
  ('PRICE_PLAN',       '{finance,platform_admin}',                                   '{platform_admin,finance}'),
  ('RATE_LIMIT',       '{operations,platform_admin}',                                '{platform_admin,operations}'),
  ('ROUTING',          '{integration_engineer,operations,platform_admin}',           '{platform_admin,operations}'),
  ('PORTING',          '{operations,integration_engineer,platform_admin}',           '{platform_admin,operations}'),
  ('SETTING',          '{platform_admin,operations}',                                '{platform_admin}'),
  ('KEY_REGISTER',     '{integration_engineer,platform_admin,bank_user,telco_user}', '{platform_admin,operations,integration_engineer}'),
  ('KILL_SWITCH_LIFT', '{operations,platform_admin}',                                '{platform_admin,operations}'),
  ('ORG_STATE',        '{integration_engineer,operations,platform_admin}',           '{platform_admin}'),
  ('ENTITLEMENT',      '{integration_engineer,platform_admin}',                      '{platform_admin,operations}'),
  ('ADMIN_USER',       '{platform_admin}',                                           '{platform_admin}');

CREATE TABLE config_change (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind           text NOT NULL REFERENCES config_role_policy(kind),
  target         text NOT NULL CHECK (length(target) BETWEEN 1 AND 200),
  payload        jsonb NOT NULL CHECK (pg_column_size(payload) < 16384),
  payload_hash   bytea NOT NULL,
  base_version   bigint,
  org_id         uuid REFERENCES organisations(id),
  rollback_of    bigint,
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','applied','rejected','withdrawn','expired')),
  requested_by   text NOT NULL REFERENCES admin_user(sub),
  requested_role text NOT NULL,
  requested_at   timestamptz NOT NULL DEFAULT now(),
  decided_by     text REFERENCES admin_user(sub),
  decided_at     timestamptz,
  decision_note  text CHECK (length(decision_note) <= 500),
  -- Two-person rule at the constraint level: whoever applies or rejects can never be the requester.
  CHECK (decided_by IS NULL OR decided_by <> requested_by),
  CHECK ((status IN ('applied','rejected')) = (decided_by IS NOT NULL))
);
CREATE TABLE config_history (
  version      bigserial PRIMARY KEY,
  change_id    uuid NOT NULL REFERENCES config_change(id),
  kind         text NOT NULL,
  target       text NOT NULL,
  before_state jsonb,
  after_state  jsonb,
  restore      jsonb,               -- payload that would restore the previous state (rollback is itself a gated change)
  requested_by text NOT NULL,
  applied_by   text NOT NULL,
  applied_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX config_history_target ON config_history(kind, target, version DESC);
CREATE TRIGGER history_no_update BEFORE UPDATE OR DELETE ON config_history FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER history_no_truncate BEFORE TRUNCATE ON config_history FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- A request is immutable; only its status may move, and only out of 'pending'.
CREATE FUNCTION config_change_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'config changes cannot be deleted' USING ERRCODE='42501'; END IF;
  IF OLD.status <> 'pending' THEN RAISE EXCEPTION 'a decided change is immutable' USING ERRCODE='42501'; END IF;
  IF NEW.kind <> OLD.kind OR NEW.target <> OLD.target OR NEW.payload <> OLD.payload OR NEW.payload_hash <> OLD.payload_hash
     OR NEW.requested_by <> OLD.requested_by OR NEW.requested_at <> OLD.requested_at OR NEW.base_version IS DISTINCT FROM OLD.base_version
     OR NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.rollback_of IS DISTINCT FROM OLD.rollback_of THEN
    RAISE EXCEPTION 'a pending change may not be edited (payload, requester, target are immutable)' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER config_change_guard BEFORE UPDATE OR DELETE ON config_change FOR EACH ROW EXECUTE FUNCTION config_change_guard();
CREATE TRIGGER config_change_no_truncate BEFORE TRUNCATE ON config_change FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ---------- helper predicates for RLS ----------
CREATE FUNCTION admin_staff() RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT coalesce(current_setting('app.admin_scope', true), '') = 'all' $$;
CREATE FUNCTION admin_visible(o uuid) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT admin_staff() OR (o IS NOT NULL AND o = current_org()) $$;

-- ---------- application of approved changes ----------
CREATE FUNCTION cfg_required_tests(p_org uuid) RETURNS text[] LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE k text; r text[] := '{}';
BEGIN
  SELECT kind INTO k FROM organisations WHERE id = p_org;
  IF k = 'telco' THEN
    r := ARRAY['health_check'] || coalesce((SELECT array_agg('conformance:' || c.signal ORDER BY c.signal) FROM telco_signal_coverage c JOIN telcos t ON t.id = c.telco_id WHERE t.org_id = p_org), '{}');
  ELSIF k = 'bank' THEN
    r := ARRAY['cert_unconsented_rejected'] || coalesce((SELECT array_agg('cert:' || e.signal ORDER BY e.signal) FROM org_entitlement e WHERE e.org_id = p_org), '{}');
  END IF;
  RETURN r;
END $$;
CREATE FUNCTION onb_missing_tests(p_org uuid) RETURNS text[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT coalesce(array_agg(t ORDER BY t), '{}') FROM unnest(cfg_required_tests(p_org)) t
  WHERE NOT EXISTS (SELECT 1 FROM (SELECT DISTINCT ON (test_key) test_key, status FROM onboarding_test WHERE org_id = p_org ORDER BY test_key, id DESC) l WHERE l.test_key = t AND l.status = 'pass')
$$;

CREATE FUNCTION cfg_apply(c config_change) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE p jsonb := c.payload; act text := p->>'action'; b jsonb; a jsonb; rs jsonb; n int; oid uuid; k text; arr text[];
BEGIN
  IF c.kind = 'PRICE_PLAN' THEN
    IF act = 'create_plan' THEN
      INSERT INTO price_plan(id, currency, platform_fee_minor, signal_price_minor, tiers)
        VALUES (p#>>'{plan,id}', p#>>'{plan,currency}', (p#>>'{plan,platformFeeMinor}')::int, p#>'{plan,signalPriceMinor}', p#>'{plan,tiers}');
      RETURN jsonb_build_object('before', null, 'after', p->'plan', 'restore', null);
    ELSIF act = 'assign' THEN
      SELECT jsonb_build_object('planId', plan_id) INTO b FROM org_price_plan WHERE org_id = (p->>'orgId')::uuid ORDER BY effective_from DESC LIMIT 1;
      INSERT INTO org_price_plan(org_id, plan_id, effective_from) VALUES ((p->>'orgId')::uuid, p->>'planId', coalesce((p->>'effectiveFrom')::timestamptz, now()));
      RETURN jsonb_build_object('before', b, 'after', jsonb_build_object('planId', p->>'planId'),
        'restore', CASE WHEN b IS NULL THEN null ELSE jsonb_build_object('action','assign','orgId',p->>'orgId','planId',b->>'planId') END);
    END IF;
  ELSIF c.kind = 'RATE_LIMIT' THEN
    SELECT to_jsonb(max_per_minute) INTO b FROM rate_limit_override WHERE org_id = (p->>'orgId')::uuid AND signal = p->>'signal';
    IF p->'maxPerMinute' = 'null'::jsonb THEN DELETE FROM rate_limit_override WHERE org_id = (p->>'orgId')::uuid AND signal = p->>'signal';
    ELSE INSERT INTO rate_limit_override(org_id, signal, max_per_minute) VALUES ((p->>'orgId')::uuid, p->>'signal', (p->>'maxPerMinute')::int)
         ON CONFLICT (org_id, signal) DO UPDATE SET max_per_minute = EXCLUDED.max_per_minute; END IF;
    RETURN jsonb_build_object('before', b, 'after', p->'maxPerMinute', 'restore', jsonb_build_object('orgId', p->>'orgId', 'signal', p->>'signal', 'maxPerMinute', coalesce(b, 'null'::jsonb)));
  ELSIF c.kind = 'SETTING' THEN
    SELECT value INTO b FROM platform_setting WHERE key = p->>'key';
    INSERT INTO platform_setting(key, value) VALUES (p->>'key', p->'value') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
    RETURN jsonb_build_object('before', b, 'after', p->'value', 'restore', CASE WHEN b IS NULL THEN null ELSE jsonb_build_object('key', p->>'key', 'value', b) END);
  ELSIF c.kind = 'ROUTING' THEN
    IF act = 'set_prefix' THEN
      SELECT to_jsonb(telco_id) INTO b FROM route_prefix WHERE prefix = p->>'prefix';
      INSERT INTO route_prefix(prefix, telco_id) VALUES (p->>'prefix', p->>'telcoId') ON CONFLICT (prefix) DO UPDATE SET telco_id = EXCLUDED.telco_id;
      RETURN jsonb_build_object('before', b, 'after', to_jsonb(p->>'telcoId'), 'restore', CASE WHEN b IS NULL THEN jsonb_build_object('action','remove_prefix','prefix',p->>'prefix') ELSE jsonb_build_object('action','set_prefix','prefix',p->>'prefix','telcoId',b#>>'{}') END);
    ELSIF act = 'remove_prefix' THEN
      SELECT to_jsonb(telco_id) INTO b FROM route_prefix WHERE prefix = p->>'prefix';
      DELETE FROM route_prefix WHERE prefix = p->>'prefix';
      RETURN jsonb_build_object('before', b, 'after', null, 'restore', CASE WHEN b IS NULL THEN null ELSE jsonb_build_object('action','set_prefix','prefix',p->>'prefix','telcoId',b#>>'{}') END);
    ELSIF act = 'allow_origin' THEN
      INSERT INTO endpoint_allowlist(origin) VALUES (p->>'origin'); RETURN jsonb_build_object('before', null, 'after', to_jsonb(p->>'origin'), 'restore', jsonb_build_object('action','remove_origin','origin',p->>'origin'));
    ELSIF act = 'remove_origin' THEN
      DELETE FROM endpoint_allowlist WHERE origin = p->>'origin'; RETURN jsonb_build_object('before', to_jsonb(p->>'origin'), 'after', null, 'restore', jsonb_build_object('action','allow_origin','origin',p->>'origin'));
    ELSIF act = 'create_telco' THEN
      IF NOT EXISTS (SELECT 1 FROM endpoint_allowlist WHERE origin = substring(p->>'baseUrl' from '^(https://[a-z0-9.-]+(:[0-9]{1,5})?)(/|$)')) THEN RAISE EXCEPTION 'endpoint origin is not on the allow-list'; END IF;
      INSERT INTO telcos(id, adapter, base_url, state, org_id) VALUES (p->>'telcoId', p->>'adapter', p->>'baseUrl', 'draft', (p->>'orgId')::uuid);
      RETURN jsonb_build_object('before', null, 'after', p, 'restore', null);
    ELSIF act = 'telco_endpoint' THEN
      IF NOT EXISTS (SELECT 1 FROM endpoint_allowlist WHERE origin = substring(p->>'baseUrl' from '^(https://[a-z0-9.-]+(:[0-9]{1,5})?)(/|$)')) THEN RAISE EXCEPTION 'endpoint origin is not on the allow-list'; END IF;
      SELECT to_jsonb(base_url) INTO b FROM telcos WHERE id = p->>'telcoId';
      UPDATE telcos SET base_url = p->>'baseUrl' WHERE id = p->>'telcoId';
      RETURN jsonb_build_object('before', b, 'after', to_jsonb(p->>'baseUrl'), 'restore', jsonb_build_object('action','telco_endpoint','telcoId',p->>'telcoId','baseUrl',b#>>'{}'));
    ELSIF act = 'telco_state' THEN
      SELECT to_jsonb(state) INTO b FROM telcos WHERE id = p->>'telcoId';
      UPDATE telcos SET state = p->>'state' WHERE id = p->>'telcoId';
      RETURN jsonb_build_object('before', b, 'after', to_jsonb(p->>'state'), 'restore', jsonb_build_object('action','telco_state','telcoId',p->>'telcoId','state',b#>>'{}'));
    ELSIF act = 'coverage_set' THEN
      SELECT to_jsonb(array_agg(signal ORDER BY signal)) INTO b FROM telco_signal_coverage WHERE telco_id = p->>'telcoId';
      DELETE FROM telco_signal_coverage WHERE telco_id = p->>'telcoId';
      INSERT INTO telco_signal_coverage(telco_id, signal) SELECT p->>'telcoId', s FROM jsonb_array_elements_text(p->'signals') s;
      RETURN jsonb_build_object('before', b, 'after', p->'signals', 'restore', jsonb_build_object('action','coverage_set','telcoId',p->>'telcoId','signals',coalesce(b,'[]'::jsonb)));
    END IF;
  ELSIF c.kind = 'PORTING' THEN
    INSERT INTO porting(subject_hash, telco_id, effective_from) VALUES (decode(p->>'subjectHash','hex'), p->>'telcoId', coalesce((p->>'effectiveFrom')::timestamptz, now()));
    RETURN jsonb_build_object('before', null, 'after', jsonb_build_object('telcoId', p->>'telcoId'), 'restore', null);   -- the number is never recorded, only its keyed hash
  ELSIF c.kind = 'KEY_REGISTER' THEN
    IF NOT EXISTS (SELECT 1 FROM clients WHERE client_id = p->>'clientId') THEN
      IF p->'createClient' IS NULL THEN RAISE EXCEPTION 'unknown client'; END IF;
      oid := (p#>>'{createClient,orgId}')::uuid;
      IF oid IS DISTINCT FROM c.org_id THEN RAISE EXCEPTION 'client organisation does not match the request'; END IF;
      SELECT array_agg(s) INTO arr FROM jsonb_array_elements_text(p#>'{createClient,scopes}') s;
      IF EXISTS (SELECT 1 FROM unnest(arr) s WHERE s NOT IN ('consent:write','consent:read','statements:read')
                   AND s NOT IN (SELECT sg.scope FROM signals sg JOIN org_entitlement e ON e.signal = sg.id AND e.org_id = oid)) THEN
        RAISE EXCEPTION 'requested scopes exceed the organisation''s entitlements'; END IF;
      INSERT INTO clients(client_id, org_id, scopes) VALUES (p->>'clientId', oid, arr);
    ELSIF (SELECT org_id FROM clients WHERE client_id = p->>'clientId') IS DISTINCT FROM c.org_id THEN RAISE EXCEPTION 'client belongs to another organisation'; END IF;
    IF p->'jwk' ? 'd' OR p->'jwk' ? 'p' OR p->'jwk' ? 'q' OR p->'jwk' ? 'k' THEN RAISE EXCEPTION 'private key material is not accepted'; END IF;
    INSERT INTO client_keys(client_id, kid, jwk, cert_sha256, expires_at) VALUES (p->>'clientId', p->>'kid', p->'jwk', p->>'certSha256', (p->>'expiresAt')::timestamptz);
    IF p->>'rotateOutKid' IS NOT NULL THEN
      UPDATE client_keys SET expires_at = least(expires_at, now() + make_interval(mins => coalesce((p->>'overlapMinutes')::int, 60))) WHERE client_id = p->>'clientId' AND kid = p->>'rotateOutKid';
    END IF;
    RETURN jsonb_build_object('before', null, 'after', jsonb_build_object('clientId', p->>'clientId', 'kid', p->>'kid', 'expiresAt', p->>'expiresAt'), 'restore', null);
  ELSIF c.kind = 'KILL_SWITCH_LIFT' THEN
    UPDATE kill_switch SET enabled = false WHERE scope = p->>'scope' AND key = p->>'key' AND enabled;
    GET DIAGNOSTICS n = ROW_COUNT; IF n = 0 THEN RAISE EXCEPTION 'that kill switch is not engaged'; END IF;
    RETURN jsonb_build_object('before', jsonb_build_object('enabled', true), 'after', jsonb_build_object('enabled', false), 'restore', null);
  ELSIF c.kind = 'ORG_STATE' THEN
    oid := (p->>'orgId')::uuid; SELECT state INTO k FROM organisations WHERE id = oid;
    IF NOT ((k = 'pending_approval' AND p->>'toState' = 'active') OR (k = 'suspended' AND p->>'toState' = 'active') OR (k IN ('active','suspended') AND p->>'toState' = 'retired')) THEN
      RAISE EXCEPTION 'transition % -> % is not allowed', k, p->>'toState'; END IF;
    IF p->>'toState' = 'active' AND cardinality(onb_missing_tests(oid)) > 0 THEN RAISE EXCEPTION 'activation blocked: required tests have not passed (%)', array_to_string(onb_missing_tests(oid), ', '); END IF;
    UPDATE organisations SET state = p->>'toState' WHERE id = oid;
    UPDATE telcos SET state = CASE WHEN p->>'toState' = 'active' THEN 'active' ELSE 'retired' END WHERE org_id = oid;
    RETURN jsonb_build_object('before', to_jsonb(k), 'after', to_jsonb(p->>'toState'), 'restore', null);
  ELSIF c.kind = 'ENTITLEMENT' THEN
    oid := (p->>'orgId')::uuid;
    SELECT to_jsonb(purposes) INTO b FROM org_entitlement WHERE org_id = oid AND signal = p->>'signal';
    IF p->'purposes' = 'null'::jsonb THEN DELETE FROM org_entitlement WHERE org_id = oid AND signal = p->>'signal';
    ELSE SELECT array_agg(s) INTO arr FROM jsonb_array_elements_text(p->'purposes') s;
         INSERT INTO org_entitlement(org_id, signal, purposes) VALUES (oid, p->>'signal', arr) ON CONFLICT (org_id, signal) DO UPDATE SET purposes = EXCLUDED.purposes; END IF;
    RETURN jsonb_build_object('before', b, 'after', p->'purposes', 'restore', jsonb_build_object('orgId', p->>'orgId', 'signal', p->>'signal', 'purposes', coalesce(b, 'null'::jsonb)));
  ELSIF c.kind = 'ADMIN_USER' THEN
    SELECT to_jsonb(u) - 'created_at' INTO b FROM admin_user u WHERE sub = p->>'sub';
    INSERT INTO admin_user(sub, display_name, role, org_id, state) VALUES (p->>'sub', p->>'displayName', p->>'role', (p->>'orgId')::uuid, coalesce(p->>'state','active'))
      ON CONFLICT (sub) DO UPDATE SET display_name = EXCLUDED.display_name, role = EXCLUDED.role, org_id = EXCLUDED.org_id, state = EXCLUDED.state;
    -- Two-person approval must remain possible: never leave fewer than two active platform administrators.
    IF (SELECT count(*) FROM admin_user WHERE role = 'platform_admin' AND state = 'active') < 2 THEN RAISE EXCEPTION 'at least two active platform administrators must remain'; END IF;
    UPDATE admin_session SET ended_at = now() WHERE sub = p->>'sub' AND ended_at IS NULL AND coalesce(p->>'state','active') = 'disabled';
    RETURN jsonb_build_object('before', b, 'after', p - 'action', 'restore', null);
  END IF;
  RAISE EXCEPTION 'unsupported change % / %', c.kind, act;
END $$;

CREATE FUNCTION cfg_request(p_kind text, p_target text, p_payload jsonb, p_requester text, p_org uuid, p_rollback_of bigint)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE u admin_user; pol config_role_policy; bv bigint; new_id uuid; h config_history;
BEGIN
  SELECT * INTO u FROM admin_user WHERE sub = p_requester AND state = 'active';
  IF NOT FOUND THEN RAISE EXCEPTION 'unknown or disabled requester' USING ERRCODE='42501'; END IF;
  SELECT * INTO pol FROM config_role_policy WHERE kind = p_kind;
  IF NOT FOUND OR NOT (u.role = ANY(pol.can_request)) THEN RAISE EXCEPTION 'role % may not request % changes', u.role, p_kind USING ERRCODE='42501'; END IF;
  IF u.org_id IS NOT NULL AND p_org IS DISTINCT FROM u.org_id THEN RAISE EXCEPTION 'restricted users may only request changes for their own organisation' USING ERRCODE='42501'; END IF;
  IF p_rollback_of IS NOT NULL THEN
    SELECT * INTO h FROM config_history WHERE version = p_rollback_of AND kind = p_kind AND target = p_target;
    IF NOT FOUND OR h.restore IS NULL THEN RAISE EXCEPTION 'that version cannot be rolled back'; END IF;
    IF h.restore <> p_payload THEN RAISE EXCEPTION 'rollback payload must equal the recorded restore state'; END IF;
  END IF;
  SELECT max(version) INTO bv FROM config_history WHERE kind = p_kind AND target = p_target;
  INSERT INTO config_change(kind, target, payload, payload_hash, base_version, org_id, rollback_of, requested_by, requested_role)
    VALUES (p_kind, p_target, p_payload, sha256(convert_to(p_payload::text, 'UTF8')), bv, p_org, p_rollback_of, p_requester, u.role) RETURNING id INTO new_id;
  RETURN new_id;
END $$;

CREATE FUNCTION cfg_decide(p_id uuid, p_decider text, p_approve boolean, p_note text, p_auth_age_s integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE c config_change; d admin_user; pol config_role_policy; bv bigint; res jsonb;
BEGIN
  SELECT * INTO c FROM config_change WHERE id = p_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'no such change'; END IF;
  IF c.status <> 'pending' THEN RAISE EXCEPTION 'change is not pending'; END IF;
  SELECT * INTO d FROM admin_user WHERE sub = p_decider AND state = 'active';
  IF NOT FOUND THEN RAISE EXCEPTION 'unknown or disabled approver' USING ERRCODE='42501'; END IF;
  SELECT * INTO pol FROM config_role_policy WHERE kind = c.kind;
  IF d.org_id IS NOT NULL OR NOT (d.role = ANY(pol.can_approve)) THEN RAISE EXCEPTION 'role % may not decide % changes', d.role, c.kind USING ERRCODE='42501'; END IF;
  IF d.sub = c.requested_by THEN RAISE EXCEPTION 'the approver must be a different person from the requester' USING ERRCODE='42501'; END IF;
  IF c.requested_at < now() - interval '24 hours' THEN
    UPDATE config_change SET status = 'expired' WHERE id = c.id;
    RETURN jsonb_build_object('status', 'expired');
  END IF;
  IF NOT p_approve THEN
    UPDATE config_change SET status = 'rejected', decided_by = p_decider, decided_at = now(), decision_note = p_note WHERE id = c.id;
    RETURN jsonb_build_object('status', 'rejected');
  END IF;
  IF p_auth_age_s IS NULL OR p_auth_age_s > 300 THEN RAISE EXCEPTION 'recent re-authentication required to approve' USING ERRCODE='42501'; END IF;
  IF c.payload_hash <> sha256(convert_to(c.payload::text, 'UTF8')) THEN RAISE EXCEPTION 'payload integrity check failed' USING ERRCODE='42501'; END IF;
  SELECT max(version) INTO bv FROM config_history WHERE kind = c.kind AND target = c.target;
  IF bv IS DISTINCT FROM c.base_version THEN RAISE EXCEPTION 'stale: the configuration changed after this request was made; request it again'; END IF;
  res := cfg_apply(c);
  INSERT INTO config_history(change_id, kind, target, before_state, after_state, restore, requested_by, applied_by)
    VALUES (c.id, c.kind, c.target, res->'before', res->'after', CASE WHEN res->'restore' = 'null'::jsonb THEN NULL ELSE res->'restore' END, c.requested_by, p_decider);
  UPDATE config_change SET status = 'applied', decided_by = p_decider, decided_at = now(), decision_note = p_note WHERE id = c.id;
  RETURN jsonb_build_object('status', 'applied', 'before', res->'before', 'after', res->'after');
END $$;

CREATE FUNCTION cfg_withdraw(p_id uuid, p_actor text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  UPDATE config_change SET status = 'withdrawn' WHERE id = p_id AND status = 'pending' AND requested_by = p_actor;
  RETURN FOUND;
END $$;

-- ---------- deliberately single-person actions (safety first), still role-checked and audited by the caller ----------
CREATE FUNCTION admin_role_ok(p_sub text, p_roles text[]) RETURNS admin_user LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE u admin_user;
BEGIN
  SELECT * INTO u FROM admin_user WHERE sub = p_sub AND state = 'active';
  IF NOT FOUND OR NOT (u.role = ANY(p_roles)) THEN RAISE EXCEPTION 'not permitted' USING ERRCODE='42501'; END IF;
  RETURN u;
END $$;
CREATE FUNCTION onb_create_org(p_name text, p_kind text, p_actor text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE new_id uuid;
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,integration_engineer,operations}');
  INSERT INTO organisations(name, kind, state) VALUES (p_name, p_kind, 'draft') RETURNING id INTO new_id;
  RETURN new_id;
END $$;
CREATE FUNCTION onb_advance(p_org uuid, p_to text, p_actor text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE s text; u admin_user;
BEGIN
  u := admin_role_ok(p_actor, '{platform_admin,integration_engineer}');
  IF u.org_id IS NOT NULL THEN RAISE EXCEPTION 'not permitted' USING ERRCODE='42501'; END IF;
  SELECT state INTO s FROM organisations WHERE id = p_org FOR UPDATE;
  IF NOT ((s = 'draft' AND p_to = 'testing') OR (s = 'testing' AND p_to = 'pending_approval') OR (s = 'pending_approval' AND p_to = 'testing')) THEN RAISE EXCEPTION 'transition % -> % is not allowed here', s, p_to; END IF;
  IF p_to = 'pending_approval' AND cardinality(onb_missing_tests(p_org)) > 0 THEN RAISE EXCEPTION 'required tests have not passed: %', array_to_string(onb_missing_tests(p_org), ', '); END IF;
  UPDATE organisations SET state = p_to WHERE id = p_org;
  UPDATE telcos SET state = 'testing' WHERE org_id = p_org AND p_to = 'testing' AND state = 'draft';
END $$;
CREATE FUNCTION onb_suspend(p_org uuid, p_actor text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,operations}');
  UPDATE organisations SET state = 'suspended' WHERE id = p_org AND state IN ('testing','pending_approval','active');
  IF NOT FOUND THEN RAISE EXCEPTION 'organisation cannot be suspended from its current state'; END IF;
  UPDATE telcos SET state = 'suspended' WHERE org_id = p_org AND state IN ('testing','active');
END $$;
CREATE FUNCTION admin_kill_switch_engage(p_scope text, p_key text, p_actor text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,operations}');
  IF (p_scope = 'participant' AND NOT EXISTS (SELECT 1 FROM clients WHERE client_id = p_key))
     OR (p_scope = 'telco' AND NOT EXISTS (SELECT 1 FROM telcos WHERE id = p_key))
     OR (p_scope = 'signal' AND NOT EXISTS (SELECT 1 FROM signals WHERE id = p_key)) THEN RAISE EXCEPTION 'unknown kill-switch target'; END IF;
  INSERT INTO kill_switch(scope, key, enabled) VALUES (p_scope, p_key, true) ON CONFLICT (scope, key) DO UPDATE SET enabled = true;
END $$;
CREATE FUNCTION admin_revoke_key(p_client text, p_kid text, p_actor text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE u admin_user; co uuid;
BEGIN
  u := admin_role_ok(p_actor, '{platform_admin,operations,integration_engineer,bank_user,telco_user}');
  SELECT org_id INTO co FROM clients WHERE client_id = p_client;
  IF u.org_id IS NOT NULL AND co IS DISTINCT FROM u.org_id THEN RAISE EXCEPTION 'not permitted' USING ERRCODE='42501'; END IF;
  UPDATE client_keys SET revoked_at = now() WHERE client_id = p_client AND kid = p_kid AND revoked_at IS NULL;
  RETURN FOUND;
END $$;
CREATE FUNCTION onb_record_test(p_org uuid, p_key text, p_status text, p_evidence jsonb, p_actor text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,integration_engineer}');
  IF NOT (p_key = ANY(cfg_required_tests(p_org))) OR p_key LIKE 'cert%' THEN RAISE EXCEPTION 'this test cannot be recorded by hand'; END IF;   -- bank certification is computed from evidence, never asserted
  INSERT INTO onboarding_test(org_id, test_key, status, evidence, run_by) VALUES (p_org, p_key, p_status, p_evidence, p_actor);
END $$;
CREATE FUNCTION onb_eval_bank_cert(p_org uuid, p_actor text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE s text; ok boolean; res jsonb := '{}'::jsonb; n int;
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,integration_engineer}');
  IF (SELECT kind FROM organisations WHERE id = p_org) <> 'bank' THEN RAISE EXCEPTION 'only bank organisations are certified this way'; END IF;
  FOR s IN SELECT signal FROM org_entitlement WHERE org_id = p_org LOOP
    SELECT count(*) INTO n FROM usage_record WHERE org_id = p_org AND signal = s AND outcome IN ('TRUE','FALSE');
    INSERT INTO onboarding_test(org_id, test_key, status, evidence, run_by) VALUES (p_org, 'cert:' || s, CASE WHEN n > 0 THEN 'pass' ELSE 'fail' END, jsonb_build_object('successful_calls', n), p_actor);
    res := res || jsonb_build_object('cert:' || s, n > 0);
  END LOOP;
  SELECT count(*) INTO n FROM usage_record WHERE org_id = p_org AND outcome = 'REJECTED';
  INSERT INTO onboarding_test(org_id, test_key, status, evidence, run_by) VALUES (p_org, 'cert_unconsented_rejected', CASE WHEN n > 0 THEN 'pass' ELSE 'fail' END, jsonb_build_object('rejections_observed', n), p_actor);
  RETURN res || jsonb_build_object('cert_unconsented_rejected', n > 0);
END $$;
CREATE FUNCTION admin_lookup_session(p_id_hash bytea) RETURNS TABLE(sub text, role text, org_id uuid, display_name text, csrf text, auth_time timestamptz, created_at timestamptz, last_seen_at timestamptz, expires_at timestamptz)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.sub, u.role, u.org_id, u.display_name, s.csrf, s.auth_time, s.created_at, s.last_seen_at, s.expires_at
  FROM admin_session s JOIN admin_user u ON u.sub = s.sub WHERE s.id_hash = p_id_hash AND s.ended_at IS NULL AND u.state = 'active' $$;
CREATE FUNCTION admin_lookup_user(p_sub text) RETURNS TABLE(sub text, role text, org_id uuid, display_name text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$ SELECT sub, role, org_id, display_name FROM admin_user WHERE sub = p_sub AND state = 'active' $$;

-- ---------- ownership, grants ----------
GRANT CREATE ON SCHEMA public TO ts_config;
DO $$ DECLARE f text; BEGIN
  FOR f IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public' AND p.proname IN ('cfg_required_tests','onb_missing_tests','cfg_apply','cfg_request','cfg_decide','cfg_withdraw','admin_role_ok','onb_create_org','onb_advance','onb_suspend','admin_kill_switch_engage','admin_revoke_key','onb_record_test','onb_eval_bank_cert','admin_lookup_session','admin_lookup_user')
  LOOP EXECUTE 'ALTER FUNCTION ' || f || ' OWNER TO ts_config'; EXECUTE 'REVOKE ALL ON FUNCTION ' || f || ' FROM PUBLIC'; END LOOP;
END $$;
REVOKE CREATE ON SCHEMA public FROM ts_config;
GRANT USAGE ON SCHEMA public TO ts_admin, ts_config;
GRANT EXECUTE ON FUNCTION cfg_request(text,text,jsonb,text,uuid,bigint), cfg_decide(uuid,text,boolean,text,integer), cfg_withdraw(uuid,text), onb_create_org(text,text,text), onb_advance(uuid,text,text),
  onb_suspend(uuid,text), admin_kill_switch_engage(text,text,text), admin_revoke_key(text,text,text), onb_record_test(uuid,text,text,jsonb,text), onb_eval_bank_cert(uuid,text),
  admin_lookup_session(bytea), admin_lookup_user(text), onb_missing_tests(uuid), cfg_required_tests(uuid), audit_append(text,text,text,text,text,text) TO ts_admin;
GRANT EXECUTE ON FUNCTION admin_staff(), admin_visible(uuid), current_org() TO ts_admin, ts_config;
-- the definer role's own table privileges (it is the ONLY non-owner that can write high-risk configuration)
GRANT SELECT ON admin_user, config_role_policy, signals, usage_record, audit_log TO ts_config;
GRANT SELECT, INSERT, UPDATE ON config_change, organisations TO ts_config;
GRANT SELECT, INSERT ON config_history, price_plan, org_price_plan, porting, endpoint_allowlist, client_keys, clients, onboarding_test TO ts_config;
GRANT UPDATE ON client_keys TO ts_config; GRANT UPDATE (revoked_at, expires_at) ON client_keys TO ts_config;
GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_override, platform_setting, route_prefix, telcos, telco_signal_coverage, org_entitlement, kill_switch TO ts_config;
GRANT INSERT, UPDATE, DELETE ON endpoint_allowlist TO ts_config; GRANT DELETE ON endpoint_allowlist TO ts_config;
GRANT SELECT, INSERT, UPDATE ON admin_user, admin_session TO ts_config;
GRANT USAGE ON SEQUENCE config_history_version_seq, onboarding_test_id_seq TO ts_config;
GRANT SELECT ON porting, telco_cost TO ts_config;
-- the portal role: reads, plus the session table and low-risk API-version management; nothing else is writable
GRANT SELECT ON organisations, clients, client_keys, org_entitlement, onboarding_test, config_change, config_history, config_role_policy, kill_switch, telcos, telco_signal_coverage,
  route_prefix, endpoint_allowlist, platform_setting, price_plan, org_price_plan, telco_cost, rate_limit_override, api_version, signals, usage_record, statement, abuse_flag, admin_user TO ts_admin;
GRANT SELECT, INSERT ON admin_session TO ts_admin; GRANT UPDATE (last_seen_at, ended_at) ON admin_session TO ts_admin;
GRANT INSERT, UPDATE ON api_version TO ts_admin;
GRANT SELECT ON organisations, org_entitlement, onboarding_test, config_change, config_history, platform_setting, endpoint_allowlist, api_version TO ts_reporting;
GRANT SELECT ON organisations TO ts_billing;
GRANT SELECT ON platform_setting, org_entitlement, endpoint_allowlist TO ts_app;

-- ---------- row-level security ----------
DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['organisations','telcos','telco_signal_coverage','route_prefix','kill_switch','price_plan','org_price_plan','telco_cost','rate_limit_override','abuse_flag','org_entitlement','onboarding_test','config_change','config_history','endpoint_allowlist','platform_setting','admin_user','admin_session','config_role_policy','api_version']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR ALL TO ts_app, ts_reporting, ts_billing, ts_config, ts_migrator, ts_switch USING (true) WITH CHECK (true)', t || '_system', t);
  END LOOP;
END $$;
-- ts_admin: staff see everything; restricted users only rows of their own organisation
CREATE POLICY org_admin   ON organisations      FOR SELECT TO ts_admin USING (admin_visible(id));
CREATE POLICY telco_admin ON telcos             FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY cov_admin   ON telco_signal_coverage FOR SELECT TO ts_admin USING (admin_staff() OR telco_id IN (SELECT id FROM telcos WHERE org_id = current_org()));
CREATE POLICY ent_admin   ON org_entitlement    FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY onb_admin   ON onboarding_test    FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY chg_admin   ON config_change      FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY opp_admin   ON org_price_plan     FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY rlo_admin   ON rate_limit_override FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY usr_admin   ON admin_user         FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY sess_admin  ON admin_session      FOR ALL TO ts_admin USING (true) WITH CHECK (true);
CREATE POLICY api_admin   ON api_version        FOR ALL TO ts_admin USING (true) WITH CHECK (true);
CREATE POLICY hist_admin  ON config_history     FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_ks      ON kill_switch        FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_rp      ON route_prefix       FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_pp      ON price_plan         FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_tc      ON telco_cost         FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_ab      ON abuse_flag         FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_ea      ON endpoint_allowlist FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_ps      ON platform_setting   FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY stf_crp     ON config_role_policy FOR SELECT TO ts_admin USING (true);
CREATE POLICY clients_admin     ON clients       FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY client_keys_admin ON client_keys   FOR SELECT TO ts_admin USING (admin_staff() OR client_id IN (SELECT client_id FROM clients WHERE org_id = current_org()));
CREATE POLICY clients_cfg       ON clients       FOR ALL TO ts_config USING (true) WITH CHECK (true);
CREATE POLICY client_keys_cfg   ON client_keys   FOR ALL TO ts_config USING (true) WITH CHECK (true);
CREATE POLICY usage_cfg         ON usage_record  FOR SELECT TO ts_config USING (true);
CREATE POLICY usage_admin       ON usage_record  FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY statement_admin   ON statement     FOR SELECT TO ts_admin USING (admin_visible(org_id));
