-- 0012_hypertable_compression_retention_and_cagg.sql
-- Optimizations for TimescaleDB:
-- 1. Chunk Compression Policy (compress raw chunks older than 7 days)
-- 2. Data Retention Policy (drop raw chunks older than 30 days)
-- 3. Continuous Aggregate Rollup View (hourly aggregated network metrics for SOC dashboard)
-- 4. Continuous Aggregate Policy & Retention Policy (365 days long-term analytics)

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        -- 1. Enable compression settings on traffic_events hypertable
        BEGIN
            ALTER TABLE traffic_events SET (
                timescaledb.compress,
                timescaledb.compress_segmentby = 'protocol, interface_name',
                timescaledb.compress_orderby = 'time DESC'
            );
            RAISE NOTICE 'Configured compression settings on traffic_events hypertable.';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Compression already configured or skipped: %', SQLERRM;
        END;

        -- 2. Add compression policy (compress chunks after 7 days)
        BEGIN
            PERFORM add_compression_policy('traffic_events', INTERVAL '7 days', if_not_exists => TRUE);
            RAISE NOTICE 'Added 7-day compression policy to traffic_events.';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Compression policy skipped: %', SQLERRM;
        END;

        -- 3. Add data retention policy (purge raw chunks older than 30 days)
        BEGIN
            PERFORM add_retention_policy('traffic_events', INTERVAL '30 days', if_not_exists => TRUE);
            RAISE NOTICE 'Added 30-day retention policy to traffic_events.';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Retention policy skipped: %', SQLERRM;
        END;

        -- 4. Create Continuous Aggregate View for hourly rollup
        BEGIN
            EXECUTE $sql$
                CREATE MATERIALIZED VIEW IF NOT EXISTS traffic_hourly_rollup
                WITH (timescaledb.continuous) AS
                SELECT
                    time_bucket('1 hour', time) AS bucket,
                    protocol,
                    src_ip,
                    dst_port,
                    COUNT(*)::BIGINT AS total_events,
                    SUM(bytes_transferred)::BIGINT AS total_bytes,
                    SUM(packet_count)::BIGINT AS total_packets
                FROM traffic_events
                GROUP BY bucket, protocol, src_ip, dst_port
                WITH NO DATA;
            $sql$;
            RAISE NOTICE 'Created continuous aggregate view traffic_hourly_rollup.';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Continuous aggregate creation skipped: %', SQLERRM;
        END;

        -- 5. Add refresh policy for continuous aggregate (refreshes between 3 days ago and 1 hour ago)
        BEGIN
            PERFORM add_continuous_aggregate_policy('traffic_hourly_rollup',
                start_offset => INTERVAL '3 days',
                end_offset => INTERVAL '1 hour',
                schedule_interval => INTERVAL '30 minutes',
                if_not_exists => TRUE
            );
            RAISE NOTICE 'Added continuous aggregate refresh policy to traffic_hourly_rollup.';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Continuous aggregate policy skipped: %', SQLERRM;
        END;

        -- 6. Add retention policy for continuous aggregate (retain rollups for 365 days)
        BEGIN
            PERFORM add_retention_policy('traffic_hourly_rollup', INTERVAL '365 days', if_not_exists => TRUE);
            RAISE NOTICE 'Added 365-day retention policy to traffic_hourly_rollup.';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Rollup retention policy skipped: %', SQLERRM;
        END;
    ELSE
        RAISE NOTICE 'TimescaleDB extension not active; creating standard fallback view for hourly analytics.';
        EXECUTE $sql$
            CREATE OR REPLACE VIEW traffic_hourly_rollup AS
            SELECT
                date_trunc('hour', time) AS bucket,
                protocol,
                src_ip,
                dst_port,
                COUNT(*)::BIGINT AS total_events,
                SUM(bytes_transferred)::BIGINT AS total_bytes,
                SUM(packet_count)::BIGINT AS total_packets
            FROM traffic_events
            GROUP BY date_trunc('hour', time), protocol, src_ip, dst_port;
        $sql$;
    END IF;
END $$;
