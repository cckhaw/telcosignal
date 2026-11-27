-- 005 (M4b): request log (search + trace), rollups for dashboards, alerting, incident notes, retention. Synthetic data only.
-- Privacy by construction: no free-text column may contain an E.164-shaped string (CHECK constraints), so a raw phone number cannot
-- be stored in the request log even by a bug. Subjects appear only as an 8-hex prefix of a KEYED hash.

ALTER TABLE usage_record ADD COLUMN api_version text NOT NULL DEFAULT 'v1' CHECK (api_version ~ '^v[0-9]{1,3}$');
ALTER TABLE usage_record ADD COLUMN reason_class text NOT NULL DEFAULT 'ok'
  CHECK (reason_class IN ('ok','timeout','telco_fault','client_data','circuit_open','bulkhead','limit','kill_switch','no_route','unsupported','disabled','rejected','other'));

ALTER TABLE platform_setting DROP CONSTRAINT platform_setting_key_check;
ALTER TABLE platform_setting ADD CONSTRAINT platform_setting_key_check CHECK (key IN ('consent.max_days','sandbox.allow_loopback','logs.retention_days','consent.retention_days'));
INSERT INTO platform_setting VALUES ('logs.retention_days','90'), ('consent.retention_days','180');

CREATE TABLE request_log (
  id             bigserial PRIMARY KEY,
  ts             timestamptz NOT NULL DEFAULT now(),
  correlation_id text NOT NULL CHECK (correlation_id ~ '^[A-Za-z0-9-]{8,64}$'),
  org_id         uuid REFERENCES organisations(id),                 -- null for failures before the caller was identified
  client_id      text CHECK (client_id ~ '^[a-z0-9][a-z0-9_-]{2,62}$'),
  method         text NOT NULL CHECK (method IN ('GET','POST')),
  route          text NOT NULL CHECK (length(route) <= 80 AND route !~ '\+[1-9][0-9]{4,14}'),
  api_version    text NOT NULL DEFAULT 'v1' CHECK (api_version ~ '^v[0-9]{1,3}$'),
  signal         text,
  http_status    integer NOT NULL CHECK (http_status BETWEEN 100 AND 599),
  outcome        text NOT NULL CHECK (outcome IN ('TRUE','FALSE','UNAVAILABLE','NOT_SUPPORTED','REJECTED','ERROR','OK')),
  error_code     text CHECK (error_code ~ '^[A-Z_]{3,40}$'),
  telco_id       text,
  reason_class   text NOT NULL DEFAULT 'ok',
  reason         text NOT NULL DEFAULT '' CHECK (length(reason) <= 200 AND reason !~ '\+[1-9][0-9]{4,14}'),
  total_ms       integer NOT NULL CHECK (total_ms >= 0),
  telco_ms       integer NOT NULL DEFAULT 0 CHECK (telco_ms >= 0),
  steps          jsonb NOT NULL DEFAULT '[]' CHECK (pg_column_size(steps) < 2048 AND steps::text !~ '\+[1-9][0-9]{4,14}'),
  subject_ref    text CHECK (subject_ref ~ '^[0-9a-f]{8}$')
);
CREATE INDEX request_log_ts ON request_log(ts DESC);
CREATE INDEX request_log_corr ON request_log(correlation_id);
CREATE INDEX request_log_org_ts ON request_log(org_id, ts DESC);

-- Logs cannot be edited, and cannot be deleted until they are older than the configured retention, and then only by the worker role.
CREATE FUNCTION request_log_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE days int;
BEGIN
  IF TG_OP = 'UPDATE' THEN RAISE EXCEPTION 'request log is append-only' USING ERRCODE='42501'; END IF;
  IF TG_OP = 'TRUNCATE' THEN RAISE EXCEPTION 'request log is append-only' USING ERRCODE='42501'; END IF;
  SELECT (value #>> '{}')::int INTO days FROM platform_setting WHERE key = 'logs.retention_days';
  IF current_user <> 'ts_worker' OR OLD.ts >= now() - make_interval(days => greatest(coalesce(days, 90), 7)) THEN
    RAISE EXCEPTION 'request log rows may only be deleted by the retention job after the retention period' USING ERRCODE='42501';
  END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER request_log_no_update BEFORE UPDATE ON request_log FOR EACH ROW EXECUTE FUNCTION request_log_guard();
CREATE TRIGGER request_log_retention BEFORE DELETE ON request_log FOR EACH ROW EXECUTE FUNCTION request_log_guard();
CREATE TRIGGER request_log_no_truncate BEFORE TRUNCATE ON request_log FOR EACH STATEMENT EXECUTE FUNCTION request_log_guard();

-- Rollups (time-bucketed, rebuilt by the worker; dashboards read only these so they never slow the request path).
-- Latency histograms: bucket upper bounds (ms) 5,10,25,50,100,250,500,1000,2000 and an open last bucket.
CREATE TABLE rollup_minute (
  bucket timestamptz NOT NULL, org_id uuid NOT NULL REFERENCES organisations(id), signal text NOT NULL, telco_id text NOT NULL DEFAULT '', api_version text NOT NULL,
  outcome text NOT NULL, reason_class text NOT NULL,
  requests integer NOT NULL CHECK (requests >= 0), billable integer NOT NULL CHECK (billable >= 0),
  total_ms_sum bigint NOT NULL, telco_ms_sum bigint NOT NULL,
  h_total integer[] NOT NULL, h_over integer[] NOT NULL, h_telco integer[] NOT NULL,
  PRIMARY KEY (bucket, org_id, signal, telco_id, api_version, outcome, reason_class)
);
CREATE TABLE rollup_security_minute (
  bucket timestamptz NOT NULL, org_key text NOT NULL, org_id uuid REFERENCES organisations(id), error_code text NOT NULL, events integer NOT NULL CHECK (events >= 0),
  PRIMARY KEY (bucket, org_key, error_code)
);
CREATE TABLE rollup_state (name text PRIMARY KEY, watermark timestamptz NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE kpi_target (kpi text PRIMARY KEY, target numeric NOT NULL, note text NOT NULL DEFAULT '');
INSERT INTO kpi_target VALUES ('success_rate', 0.995, 'placeholder'), ('availability', 0.999, 'placeholder'), ('overhead_p95_ms', 100, 'placeholder'), ('timeout_rate', 0.005, 'placeholder');

-- Alerting: configurable rules, alerts with acknowledgement and escalation, incident notes.
CREATE TABLE alert_rule (
  id text PRIMARY KEY CHECK (id ~ '^[a-z0-9_-]{3,40}$'),
  metric text NOT NULL CHECK (metric IN ('auth_failures','rate_limit_hits','replay_rejections','abuse_flags','unavailable_rate','success_rate_min','timeout_rate','circuit_open','overhead_p95_ms','creds_expiring','consent_denials')),
  comparator text NOT NULL CHECK (comparator IN ('gt','lt')),
  threshold numeric NOT NULL,
  window_minutes integer NOT NULL CHECK (window_minutes BETWEEN 1 AND 1440),
  severity text NOT NULL CHECK (severity IN ('info','warning','critical')),
  escalate_after_minutes integer NOT NULL CHECK (escalate_after_minutes BETWEEN 1 AND 10080),
  enabled boolean NOT NULL DEFAULT true,
  updated_by text NOT NULL DEFAULT 'system', updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE alert_rule_history (version bigserial PRIMARY KEY, rule_id text NOT NULL, before_state jsonb, after_state jsonb, changed_by text NOT NULL, changed_at timestamptz NOT NULL DEFAULT now());
CREATE TRIGGER alert_rule_history_ro BEFORE UPDATE OR DELETE ON alert_rule_history FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TABLE alert (
  id bigserial PRIMARY KEY, rule_id text NOT NULL REFERENCES alert_rule(id), opened_at timestamptz NOT NULL DEFAULT now(),
  severity text NOT NULL, observed numeric NOT NULL, threshold numeric NOT NULL,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','escalated','resolved')),
  acknowledged_by text, acknowledged_at timestamptz, escalated_at timestamptz, resolved_at timestamptz
);
CREATE UNIQUE INDEX alert_one_open_per_rule ON alert(rule_id) WHERE status IN ('open','acknowledged','escalated');
CREATE TABLE incident_note (
  id bigserial PRIMARY KEY, ts timestamptz NOT NULL DEFAULT now(), author text NOT NULL, alert_id bigint REFERENCES alert(id), correlation_id text,
  body text NOT NULL CHECK (length(body) BETWEEN 1 AND 2000 AND body !~ '\+[1-9][0-9]{4,14}')            -- notes can never carry a phone number
);
CREATE TRIGGER incident_note_ro BEFORE UPDATE OR DELETE ON incident_note FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
INSERT INTO alert_rule(id, metric, comparator, threshold, window_minutes, severity, escalate_after_minutes) VALUES
  ('auth-failures-high','auth_failures','gt',20,10,'warning',30), ('replay-rejections','replay_rejections','gt',5,10,'critical',15), ('enumeration-suspected','abuse_flags','gt',0,60,'critical',15),
  ('success-rate-low','success_rate_min','lt',0.95,15,'critical',20), ('timeouts-high','timeout_rate','gt',0.05,15,'warning',30), ('credentials-expiring','creds_expiring','gt',0,1440,'warning',1440),
  ('circuit-breaker-open','circuit_open','gt',0,10,'critical',15), ('rate-limit-hits','rate_limit_hits','gt',200,10,'warning',60);

-- ---------- functions (definer, narrow) ----------
CREATE FUNCTION alert_rule_set(p_id text, p_metric text, p_comparator text, p_threshold numeric, p_window integer, p_severity text, p_escalate integer, p_enabled boolean, p_actor text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE b jsonb;
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,operations}');
  SELECT to_jsonb(r) INTO b FROM alert_rule r WHERE id = p_id;
  INSERT INTO alert_rule(id, metric, comparator, threshold, window_minutes, severity, escalate_after_minutes, enabled, updated_by) VALUES (p_id, p_metric, p_comparator, p_threshold, p_window, p_severity, p_escalate, p_enabled, p_actor)
    ON CONFLICT (id) DO UPDATE SET metric=EXCLUDED.metric, comparator=EXCLUDED.comparator, threshold=EXCLUDED.threshold, window_minutes=EXCLUDED.window_minutes, severity=EXCLUDED.severity,
      escalate_after_minutes=EXCLUDED.escalate_after_minutes, enabled=EXCLUDED.enabled, updated_by=EXCLUDED.updated_by, updated_at=now();
  INSERT INTO alert_rule_history(rule_id, before_state, after_state, changed_by) VALUES (p_id, b, (SELECT to_jsonb(r) FROM alert_rule r WHERE id = p_id), p_actor);
END $$;
CREATE FUNCTION alert_ack(p_alert bigint, p_actor text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,operations,security_auditor}');
  UPDATE alert SET status = 'acknowledged', acknowledged_by = p_actor, acknowledged_at = now() WHERE id = p_alert AND status IN ('open','escalated');
  RETURN FOUND;
END $$;
CREATE FUNCTION incident_note_add(p_alert bigint, p_corr text, p_body text, p_actor text) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE new_id bigint;
BEGIN
  PERFORM admin_role_ok(p_actor, '{platform_admin,operations,security_auditor,integration_engineer}');
  INSERT INTO incident_note(author, alert_id, correlation_id, body) VALUES (p_actor, p_alert, p_corr, p_body) RETURNING id INTO new_id;
  RETURN new_id;
END $$;
-- Audit trail search for the portal: staff auditors only; the audit log itself is never writable or deletable from the portal.
CREATE FUNCTION audit_search(p_from timestamptz, p_to timestamptz, p_actor text, p_action text, p_corr text, p_limit integer, p_actor_sub text)
RETURNS TABLE(seq bigint, ts timestamptz, correlation_id text, actor text, action text, org_id text, outcome text, detail_text text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM admin_role_ok(p_actor_sub, '{platform_admin,security_auditor}');
  RETURN QUERY SELECT a.seq, to_timestamp(a.ts_us / 1000000.0), a.correlation_id, a.actor, a.action, a.org_id, a.outcome, a.detail_text FROM audit_log a
    WHERE to_timestamp(a.ts_us / 1000000.0) >= p_from AND to_timestamp(a.ts_us / 1000000.0) < p_to AND (p_actor IS NULL OR a.actor = p_actor) AND (p_action IS NULL OR a.action = p_action) AND (p_corr IS NULL OR a.correlation_id = p_corr)
    ORDER BY a.seq DESC LIMIT least(coalesce(p_limit, 200), 2000);
END $$;
CREATE FUNCTION audit_verify() RETURNS TABLE(ok boolean, rows bigint, problem text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE r record; prev bytea := decode(repeat('00', 32), 'hex'); expect bigint := 1; n bigint := 0; h bytea;
BEGIN
  FOR r IN SELECT * FROM audit_log ORDER BY seq LOOP
    IF r.seq <> expect THEN RETURN QUERY SELECT false, n, 'gap at ' || expect; RETURN; END IF;
    IF r.prev_hash <> prev THEN RETURN QUERY SELECT false, n, 'prev_hash mismatch at ' || r.seq; RETURN; END IF;
    h := sha256(prev || convert_to(r.seq || '|' || r.ts_us || '|' || r.correlation_id || '|' || r.actor || '|' || r.action || '|' || r.org_id || '|' || r.outcome || '|' || r.detail_text, 'UTF8'));
    IF h <> r.hash THEN RETURN QUERY SELECT false, n, 'hash mismatch at ' || r.seq; RETURN; END IF;
    prev := h; expect := expect + 1; n := n + 1;
  END LOOP;
  RETURN QUERY SELECT true, n, NULL::text;
END $$;
GRANT CREATE ON SCHEMA public TO ts_config;
ALTER FUNCTION alert_rule_set(text,text,text,numeric,integer,text,integer,boolean,text) OWNER TO ts_config;
ALTER FUNCTION alert_ack(bigint,text) OWNER TO ts_config;
ALTER FUNCTION incident_note_add(bigint,text,text,text) OWNER TO ts_config;
ALTER FUNCTION audit_search(timestamptz,timestamptz,text,text,text,integer,text) OWNER TO ts_config;
ALTER FUNCTION audit_verify() OWNER TO ts_config;
REVOKE CREATE ON SCHEMA public FROM ts_config;
REVOKE ALL ON FUNCTION alert_rule_set(text,text,text,numeric,integer,text,integer,boolean,text), alert_ack(bigint,text), incident_note_add(bigint,text,text,text), audit_search(timestamptz,timestamptz,text,text,text,integer,text), audit_verify() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION alert_rule_set(text,text,text,numeric,integer,text,integer,boolean,text), alert_ack(bigint,text), incident_note_add(bigint,text,text,text), audit_search(timestamptz,timestamptz,text,text,text,integer,text), audit_verify() TO ts_admin;
GRANT SELECT, INSERT, UPDATE ON alert_rule, alert_rule_history, alert, incident_note TO ts_config;
GRANT SELECT ON audit_log TO ts_config;
GRANT USAGE ON SEQUENCE alert_rule_history_version_seq, incident_note_id_seq TO ts_config;

-- ---------- grants and row-level security ----------
GRANT INSERT ON request_log TO ts_app; GRANT USAGE ON SEQUENCE request_log_id_seq TO ts_app;
GRANT SELECT ON request_log, rollup_minute, rollup_security_minute, rollup_state, kpi_target, alert_rule, alert, incident_note, alert_rule_history TO ts_admin;
GRANT SELECT ON request_log, rollup_minute, rollup_security_minute, rollup_state, kpi_target, alert_rule, alert, incident_note TO ts_reporting;
-- the worker: builds rollups, evaluates alerts, runs retention. Reads usage/log data; writes only derived tables; deletes only what retention allows.
GRANT USAGE ON SCHEMA public TO ts_worker;
GRANT SELECT ON usage_record, request_log, abuse_flag, client_keys, clients, platform_setting, kpi_target, alert_rule, organisations TO ts_worker;
GRANT DELETE ON request_log, consents, admin_session, abuse_flag TO ts_worker; GRANT SELECT ON consents, admin_session TO ts_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON rollup_minute, rollup_security_minute, rollup_state TO ts_worker;
GRANT SELECT, INSERT, UPDATE ON alert TO ts_worker; GRANT USAGE ON SEQUENCE alert_id_seq TO ts_worker;
GRANT UPDATE ON platform_setting TO ts_migrator;

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['request_log','rollup_minute','rollup_security_minute','rollup_state','kpi_target','alert_rule','alert_rule_history','alert','incident_note'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t); EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY %I ON %I FOR ALL TO ts_app, ts_reporting, ts_billing, ts_config, ts_migrator, ts_worker USING (true) WITH CHECK (true)', t || '_system', t);
  END LOOP;
END $$;
-- the portal: staff see everything; restricted users only rows belonging to their organisation (never alerts, notes or rules)
CREATE POLICY rl_admin   ON request_log            FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY ru_admin   ON rollup_minute          FOR SELECT TO ts_admin USING (admin_visible(org_id) OR telco_id IN (SELECT id FROM telcos WHERE org_id = current_org()));
CREATE POLICY rs_admin   ON rollup_security_minute FOR SELECT TO ts_admin USING (admin_visible(org_id));
CREATE POLICY rst_admin  ON rollup_state           FOR SELECT TO ts_admin USING (true);
CREATE POLICY kt_admin   ON kpi_target             FOR SELECT TO ts_admin USING (true);
CREATE POLICY ar_admin   ON alert_rule             FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY arh_admin  ON alert_rule_history     FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY al_admin   ON alert                  FOR SELECT TO ts_admin USING (admin_staff());
CREATE POLICY in_admin   ON incident_note          FOR SELECT TO ts_admin USING (admin_staff());
-- worker needs to read/delete tenant tables that have forced RLS
CREATE POLICY usage_worker    ON usage_record  FOR SELECT TO ts_worker USING (true);
CREATE POLICY consents_worker ON consents      FOR ALL    TO ts_worker USING (true) WITH CHECK (true);
CREATE POLICY clients_worker  ON clients       FOR SELECT TO ts_worker USING (true);
CREATE POLICY ckeys_worker    ON client_keys   FOR SELECT TO ts_worker USING (true);
CREATE POLICY sess_worker     ON admin_session FOR ALL    TO ts_worker USING (true) WITH CHECK (true);
CREATE POLICY abuse_worker    ON abuse_flag    FOR ALL    TO ts_worker USING (true) WITH CHECK (true);
CREATE POLICY org_worker      ON organisations FOR SELECT TO ts_worker USING (true);
CREATE POLICY ps_worker       ON platform_setting FOR SELECT TO ts_worker USING (true);
