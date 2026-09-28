-- 0011_seed_sample_data.sql
-- Seed initial mock and administrative data for development & testing

-- Seed Users:
-- Admin: admin / Admin@SecNet2026!
-- Analyst: analyst, analyst_linh / Analyst@SecNet2026!
-- Viewer: viewer, viewer_demo / Viewer@SecNet2026!
INSERT INTO users (id, username, email, password_hash, role)
VALUES 
    ('a0000000-0000-0000-0000-000000000001', 'admin', 'admin@secnet.local', 
     '$argon2id$v=19$m=19456,t=2,p=1$EUZQYeJ8Tsigy2wK3l4JXg$BI3EPWSF8ZQ2Jo3YwH44Izo/l3svF8r8vEYl94Aw808', 'admin'),
    ('a0000000-0000-0000-0000-000000000002', 'analyst', 'analyst@secnet.local', 
     '$argon2id$v=19$m=19456,t=2,p=1$VvoGopV4MJWMaLlSvHCFmA$LT62pukpUUB39IuIa+n3QPmuBMxPpingGLTbcuxKN9E', 'analyst'),
    ('a0000000-0000-0000-0000-000000000003', 'viewer', 'viewer@secnet.local', 
     '$argon2id$v=19$m=19456,t=2,p=1$3lGzeapZELWpC5pMrhAlwQ$9hp0Qrq17T0Hgnvl/pZVznbou4506J9y2AGb5iR6ShA', 'viewer'),
    ('a0000000-0000-0000-0000-000000000012', 'analyst_linh', 'analyst_linh@secnet.local', 
     '$argon2id$v=19$m=19456,t=2,p=1$VvoGopV4MJWMaLlSvHCFmA$LT62pukpUUB39IuIa+n3QPmuBMxPpingGLTbcuxKN9E', 'analyst'),
    ('a0000000-0000-0000-0000-000000000013', 'viewer_demo', 'viewer_demo@secnet.local', 
     '$argon2id$v=19$m=19456,t=2,p=1$3lGzeapZELWpC5pMrhAlwQ$9hp0Qrq17T0Hgnvl/pZVznbou4506J9y2AGb5iR6ShA', 'viewer')
ON CONFLICT (username) DO NOTHING;

-- Seed Detection Rules
INSERT INTO detection_rules (id, name, rule_type, condition_json, severity, is_enabled, threshold_value, time_window_seconds)
VALUES
    ('b0000000-0000-0000-0000-000000000001', 'Port Scan Detection', 'threshold', 
     '{"metric": "distinct_dst_ports", "group_by": "src_ip"}', 'high', true, 15.0, 10),
    ('b0000000-0000-0000-0000-000000000002', 'SYN Flood / DDoS Detection', 'threshold', 
     '{"flags": ["SYN"], "metric": "packet_rate", "group_by": "dst_ip"}', 'critical', true, 200.0, 5),
    ('b0000000-0000-0000-0000-000000000003', 'Brute-force Attack Detection', 'pattern', 
     '{"dst_ports": [21, 22, 23, 3389, 5432, 3306], "metric": "failed_connection_attempts", "group_by": "src_ip"}', 'high', true, 5.0, 30),
    ('b0000000-0000-0000-0000-000000000004', 'ARP Spoofing / Poisoning Detection', 'pattern', 
     '{"metric": "mac_flapping", "group_by": "ip_address"}', 'critical', true, 1.0, 1),
    ('b0000000-0000-0000-0000-000000000005', 'DNS Tunneling Detection', 'anomaly', 
     '{"metric": "subdomain_entropy", "dst_port": 53}', 'medium', true, 3.8, 30),
    ('b0000000-0000-0000-0000-000000000006', 'Traffic Volume Anomaly (Z-Score)', 'anomaly', 
     '{"metric": "z_score", "window": "5m"}', 'medium', true, 3.0, 100),
    ('b0000000-0000-0000-0000-000000000007', 'ICMP Flood / Smurf Attack Detection', 'threshold', 
     '{"metric": "icmp_packet_rate", "group_by": "dst_ip"}', 'high', true, 50.0, 5),
    ('b0000000-0000-0000-0000-000000000008', 'C2 Beaconing / Periodic Callback Detection', 'pattern', 
     '{"metric": "beaconing_jitter", "min_connections": 6, "max_jitter": 0.15}', 'high', true, 6.0, 60)
ON CONFLICT (name) DO UPDATE SET 
    threshold_value = EXCLUDED.threshold_value,
    time_window_seconds = EXCLUDED.time_window_seconds,
    severity = EXCLUDED.severity,
    condition_json = EXCLUDED.condition_json;

-- Seed Sample Network Devices
INSERT INTO devices (id, ip_address, mac_address, hostname, device_type, is_trusted)
VALUES
    ('c0000000-0000-0000-0000-000000000001', '192.168.1.1', '00:1a:2b:3c:4d:01', 'gateway.secnet.local', 'router', true),
    ('c0000000-0000-0000-0000-000000000002', '192.168.1.50', '00:1a:2b:3c:4d:50', 'db01.secnet.local', 'server', true),
    ('c0000000-0000-0000-0000-000000000003', '192.168.1.100', '00:1a:2b:3c:4d:65', 'analyst-ws.secnet.local', 'workstation', true),
    ('c0000000-0000-0000-0000-000000000004', '10.0.0.99', 'fa:16:3e:7b:8a:99', 'unknown-external.probe', 'unknown', false)
ON CONFLICT (ip_address) DO NOTHING;

-- Seed Sample Traffic Events
INSERT INTO traffic_events (time, id, src_ip, dst_ip, src_port, dst_port, protocol, bytes_transferred, packet_count, flags, interface_name)
VALUES
    (CURRENT_TIMESTAMP - INTERVAL '10 minutes', gen_random_uuid(), '192.168.1.100', '192.168.1.50', 52341, 5432, 'TCP', 4096, 8, 'ACK', 'eth0'),
    (CURRENT_TIMESTAMP - INTERVAL '8 minutes', gen_random_uuid(), '192.168.1.100', '1.1.1.1', 54220, 53, 'UDP', 128, 1, '', 'eth0'),
    (CURRENT_TIMESTAMP - INTERVAL '5 minutes', gen_random_uuid(), '10.0.0.99', '192.168.1.50', 49152, 22, 'TCP', 64, 1, 'SYN', 'eth0'),
    (CURRENT_TIMESTAMP - INTERVAL '5 minutes', gen_random_uuid(), '10.0.0.99', '192.168.1.50', 49153, 80, 'TCP', 64, 1, 'SYN', 'eth0'),
    (CURRENT_TIMESTAMP - INTERVAL '5 minutes', gen_random_uuid(), '10.0.0.99', '192.168.1.50', 49154, 443, 'TCP', 64, 1, 'SYN', 'eth0'),
    (CURRENT_TIMESTAMP - INTERVAL '1 minute', gen_random_uuid(), '192.168.1.100', '192.168.1.1', 51000, 443, 'TCP', 10240, 15, 'PSH,ACK', 'eth0');

-- Seed Sample Alerts
INSERT INTO alerts (id, rule_id, severity, title, description, src_ip, dst_ip, detected_at, status)
VALUES
    ('d0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000001', 'high', 
     'Port Scan Detected from 10.0.0.99', 
     'Source IP 10.0.0.99 connected to 25 ports on target 192.168.1.50 within 5 seconds.', 
     '10.0.0.99', '192.168.1.50', CURRENT_TIMESTAMP - INTERVAL '5 minutes', 'open'),
    ('d0000000-0000-0000-0000-000000000002', 'b0000000-0000-0000-0000-000000000003', 'high', 
     'SSH Brute-Force Attempt Detected', 
     'Multiple failed authentication attempts detected towards 192.168.1.50:22 from 10.0.0.99.', 
     '10.0.0.99', '192.168.1.50', CURRENT_TIMESTAMP - INTERVAL '3 minutes', 'acknowledged')
ON CONFLICT (id) DO NOTHING;

-- Seed Notification Channels
INSERT INTO notification_channels (id, name, type, config_json, min_severity, is_enabled)
VALUES
    ('e0000000-0000-0000-0000-000000000001', 'Security Operations Email', 'email', 
     '{"smtp_host": "smtp.mailtrap.io", "to_email": "soc@secnet.local"}', 'high', true),
    ('e0000000-0000-0000-0000-000000000002', 'SOC Telegram Incident Feed', 'telegram', 
     '{"chat_id": "-1001234567890"}', 'high', true),
    ('e0000000-0000-0000-0000-000000000003', 'SIEM Webhook Integration', 'webhook', 
     '{"endpoint_url": "http://localhost:9000/api/v1/alerts"}', 'medium', true)
ON CONFLICT DO NOTHING;
