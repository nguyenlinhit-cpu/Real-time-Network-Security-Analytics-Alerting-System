-- 0015_add_mitre_and_heartbeat.sql
-- Add MITRE ATT&CK mapping columns and sensor health monitoring table

-- 1. MITRE ATT&CK columns for detection rules
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(50);
ALTER TABLE detection_rules ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(50);

-- 2. MITRE ATT&CK columns for alerts
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(50);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(50);

-- 3. Populate MITRE ATT&CK mappings on seed detection rules
UPDATE detection_rules SET mitre_tactic = 'Discovery', mitre_technique = 'T1046' WHERE name = 'Port Scan Detection';
UPDATE detection_rules SET mitre_tactic = 'Impact', mitre_technique = 'T1498' WHERE name = 'SYN Flood / DDoS Detection';
UPDATE detection_rules SET mitre_tactic = 'Credential Access', mitre_technique = 'T1110' WHERE name = 'Brute-force Attack Detection';
UPDATE detection_rules SET mitre_tactic = 'Credential Access', mitre_technique = 'T1110' WHERE name = 'SSH/RDP Brute-Force Detection';
UPDATE detection_rules SET mitre_tactic = 'Credential Access', mitre_technique = 'T1557' WHERE name LIKE 'ARP Spoofing%';
UPDATE detection_rules SET mitre_tactic = 'Exfiltration', mitre_technique = 'T1071.004' WHERE name = 'DNS Tunneling Detection';
UPDATE detection_rules SET mitre_tactic = 'Exfiltration', mitre_technique = 'T1020' WHERE name LIKE 'Traffic Volume Anomaly%';
UPDATE detection_rules SET mitre_tactic = 'Impact', mitre_technique = 'T1498.001' WHERE name LIKE 'ICMP Flood%';
UPDATE detection_rules SET mitre_tactic = 'Command and Control', mitre_technique = 'T1071' WHERE name LIKE 'C2 Beaconing%';

-- 4. Sensor health & heartbeat tracking table (Mục 40 / C1.40)
CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    sensor_id VARCHAR(100) PRIMARY KEY,
    sensor_version VARCHAR(50) NOT NULL,
    interface_name VARCHAR(50) NOT NULL,
    packets_captured BIGINT NOT NULL DEFAULT 0,
    packets_dropped BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'healthy',
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
