-- 0014_notify_rules_changed_trigger.sql
-- Trigger to automatically notify the capture engine when detection rules are updated from the UI

CREATE OR REPLACE FUNCTION notify_rule_update_event()
RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('rules_changed', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_notify_rule_update ON detection_rules;
CREATE TRIGGER trigger_notify_rule_update
    AFTER INSERT OR UPDATE OR DELETE ON detection_rules
    FOR EACH ROW
    EXECUTE FUNCTION notify_rule_update_event();
