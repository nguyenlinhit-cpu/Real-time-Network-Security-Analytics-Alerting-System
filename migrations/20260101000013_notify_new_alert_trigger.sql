-- 0013_notify_new_alert_trigger.sql
-- Trigger to automatically notify the backend of newly inserted security alerts via pg_notify

CREATE OR REPLACE FUNCTION notify_new_alert_event()
RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('new_alert', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_notify_new_alert ON alerts;
CREATE TRIGGER trigger_notify_new_alert
    AFTER INSERT ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION notify_new_alert_event();
