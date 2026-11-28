-- 007 (R-033): an organisation cannot be entitled to a signal its current price plan does not price, and cannot be moved to a plan that leaves
-- an entitled signal unpriced. Before this, the statement run refused to produce ANY statement for such an organisation (fail closed, but it
-- blocked billing for every signal). Enforced in the database so it holds for the two-person admin flow and for direct writes alike.
-- An organisation with no price plan yet is not checked here (a plan is assigned during onboarding); the statement run still refuses to bill it.
CREATE FUNCTION chk_entitlement_priced() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE pid text; prices jsonb;
BEGIN
  SELECT o.plan_id INTO pid FROM org_price_plan o WHERE o.org_id = NEW.org_id AND o.effective_from <= now() ORDER BY o.effective_from DESC LIMIT 1;
  IF pid IS NULL THEN RETURN NEW; END IF;
  SELECT signal_price_minor INTO prices FROM price_plan WHERE id = pid;
  IF prices IS NULL OR jsonb_typeof(prices -> NEW.signal) IS DISTINCT FROM 'number' THEN
    RAISE EXCEPTION 'price plan % has no price for signal %: add the price before granting the entitlement', pid, NEW.signal USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER org_entitlement_priced BEFORE INSERT OR UPDATE ON org_entitlement FOR EACH ROW EXECUTE FUNCTION chk_entitlement_priced();

CREATE FUNCTION chk_plan_covers_entitlements() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE prices jsonb; missing text;
BEGIN
  SELECT signal_price_minor INTO prices FROM price_plan WHERE id = NEW.plan_id;
  SELECT string_agg(e.signal, ', ' ORDER BY e.signal) INTO missing FROM org_entitlement e WHERE e.org_id = NEW.org_id AND jsonb_typeof(prices -> e.signal) IS DISTINCT FROM 'number';
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'price plan % has no price for entitled signal(s): %', NEW.plan_id, missing USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER org_price_plan_covers BEFORE INSERT ON org_price_plan FOR EACH ROW EXECUTE FUNCTION chk_plan_covers_entitlements();

REVOKE ALL ON FUNCTION chk_entitlement_priced(), chk_plan_covers_entitlements() FROM PUBLIC;
