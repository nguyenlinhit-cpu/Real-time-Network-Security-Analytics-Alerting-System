-- 0016_fix_traffic_flags_and_rule_notify.sql
-- 1. traffic_events.flags was VARCHAR(20): DNS events store "DNS:<query name>", which is longer,
--    and a single oversize value made the whole batched INSERT fail (lost traffic).
-- 2. The rules_changed trigger referenced NEW on DELETE (NULL payload).
-- 3. Seed notification channels ship with placeholder configs that can never deliver; keep them
--    disabled until an admin fills in real settings.

DO $$
DECLARE
    has_timescale BOOLEAN := EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb');
BEGIN
    IF (SELECT data_type FROM information_schema.columns
        WHERE table_name = 'traffic_events' AND column_name = 'flags') <> 'text' THEN
        BEGIN
            ALTER TABLE traffic_events ALTER COLUMN flags TYPE TEXT;
        EXCEPTION WHEN OTHERS THEN
            IF NOT has_timescale THEN
                RAISE;
            END IF;
            -- TimescaleDB refuses type changes while compression is enabled: decompress,
            -- disable, alter, then restore the original compression settings and policy.
            RAISE NOTICE 'Re-applying flags type change with compression temporarily disabled: %', SQLERRM;
            PERFORM remove_compression_policy('traffic_events', if_exists => TRUE);
            PERFORM decompress_chunk(c, if_compressed => TRUE) FROM show_chunks('traffic_events') c;
            ALTER TABLE traffic_events SET (timescaledb.compress = false);
            ALTER TABLE traffic_events ALTER COLUMN flags TYPE TEXT;
            ALTER TABLE traffic_events SET (
                timescaledb.compress,
                timescaledb.compress_segmentby = 'protocol, interface_name',
                timescaledb.compress_orderby = 'time DESC'
            );
            PERFORM add_compression_policy('traffic_events', INTERVAL '7 days', if_not_exists => TRUE);
        END;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION notify_rule_update_event()
RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('rules_changed', COALESCE(NEW.id, OLD.id)::text);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

UPDATE notification_channels
SET is_enabled = FALSE, updated_at = CURRENT_TIMESTAMP
WHERE (id = 'e0000000-0000-0000-0000-000000000001' AND NOT (config_json ? 'smtp_username'))
   OR (id = 'e0000000-0000-0000-0000-000000000002' AND NOT (config_json ? 'bot_token'))
   OR (id = 'e0000000-0000-0000-0000-000000000003'
       AND config_json->>'endpoint_url' = 'http://localhost:9000/api/v1/alerts');
