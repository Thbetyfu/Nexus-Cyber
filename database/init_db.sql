-- ===========================
-- NEXUS-CYBER DATABASE INIT SCRIPT
-- ===========================

USE ktp_database;

-- ===========================
-- TABLE 1: KTP_DATA (Main dummy data)
-- ===========================
CREATE TABLE IF NOT EXISTS ktp_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- KTP Fields
    nik VARCHAR(16) UNIQUE NOT NULL COMMENT 'National ID Number',
    nama VARCHAR(255) NOT NULL COMMENT 'Full name',
    alamat TEXT COMMENT 'Address',
    
    -- Personal Info
    tanggal_lahir DATE COMMENT 'Date of birth',
    tempat_lahir VARCHAR(100),
    jenis_kelamin ENUM('L', 'P') DEFAULT 'L',
    
    -- Contact
    telp VARCHAR(12) COMMENT 'Phone number',
    email VARCHAR(255),
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_nik (nik),
    INDEX idx_email (email),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Dummy KTP data for security testing';

-- ===========================
-- TABLE 2: QUERY_AUDIT_LOG (Track all queries)
-- ===========================
CREATE TABLE IF NOT EXISTS query_audit_log (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Query Info
    query TEXT NOT NULL COMMENT 'SQL query executed',
    query_hash VARCHAR(64) UNIQUE COMMENT 'Hash of query for dedup',
    
    -- Client Info
    source_ip VARCHAR(45) NOT NULL COMMENT 'Client IP (IPv4 or IPv6)',
    source_port INT,
    
    -- Timing
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms INT COMMENT 'Query execution time in ms',
    
    -- Risk Assessment
    risk_level ENUM('SAFE', 'SUSPICIOUS', 'DANGEROUS', 'CRITICAL') DEFAULT 'SAFE',
    detection_patterns JSON COMMENT 'Matched threat patterns',
    
    -- AI Verdict
    ai_verdict JSON COMMENT 'AI verdict from Qwen/Llama',
    confidence_score DECIMAL(3, 2) COMMENT 'AI confidence 0-1',
    
    -- Response Action
    action_taken ENUM('FORWARD', 'LOG', 'BLOCK', 'KILL') DEFAULT 'FORWARD',
    block_reason VARCHAR(255),
    
    -- Forensic Report (background analysis)
    forensic_report JSON COMMENT 'Detailed forensic from Llama3',
    
    -- Affected Data
    tables_accessed JSON COMMENT 'Which tables accessed',
    rows_estimated INT COMMENT 'Estimated rows returned',
    
    -- Indexes
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_risk_level (risk_level),
    INDEX idx_action (action_taken),
    FULLTEXT INDEX ft_query (query)
    
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Audit log for all database queries';

-- ===========================
-- TABLE 3: BLOCKED_IPS (IP Ban List)
-- ===========================
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- IP Info
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    
    -- Block Details
    reason VARCHAR(255) NOT NULL,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Unblock Schedule
    block_duration_hours INT DEFAULT 24 COMMENT 'Duration of block in hours',
    unblock_at TIMESTAMP NULL COMMENT 'When to auto-unblock',
    
    -- Tracking
    incidents_count INT DEFAULT 1,
    last_incident_at TIMESTAMP,
    
    INDEX idx_ip (ip_address),
    INDEX idx_unblock_at (unblock_at)
    
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Blacklist of malicious IPs';

-- ===========================
-- TABLE 4: INCIDENTS (Major threat events)
-- ===========================
CREATE TABLE IF NOT EXISTS incidents (
    id INT PRIMARY KEY AUTO_INCREMENT,
    
    -- Incident Info
    incident_type ENUM('SQL_INJECTION', 'MASS_EXFILTRATION', 'RATE_LIMIT', 'ANOMALY') NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    
    -- Detection Info
    query_id INT REFERENCES query_audit_log(id),
    source_ip VARCHAR(45) NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Forensic Details
    forensic_data JSON,
    summary TEXT,
    
    -- Response
    response_action VARCHAR(100),
    resolved_at TIMESTAMP NULL,
    
    INDEX idx_severity (severity),
    INDEX idx_detected_at (detected_at),
    INDEX idx_source_ip (source_ip)
    
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Major security incidents';

-- ===========================
-- Initial Data
-- ===========================

-- Insert sample KTP records (will be populated by Python script)
-- See: generate_ktp_data.py

-- Create a test record for verification
INSERT INTO ktp_data (nik, nama, alamat, tanggal_lahir, telp, email)
VALUES 
('0000000000000001', 'Test User 1', 'Jl. Test No. 1, Jakarta', '1990-01-01', '081234567890', 'test1@example.com'),
('0000000000000002', 'Test User 2', 'Jl. Test No. 2, Bandung', '1991-02-02', '082345678901', 'test2@example.com');

-- ===========================
-- Views for Common Queries
-- ===========================

-- View: Recent Threats
CREATE OR REPLACE VIEW v_recent_threats AS
SELECT 
    id,
    timestamp,
    source_ip,
    risk_level,
    action_taken,
    query
FROM query_audit_log
WHERE risk_level IN ('DANGEROUS', 'CRITICAL')
ORDER BY timestamp DESC
LIMIT 100;

-- View: Top Attackers
CREATE OR REPLACE VIEW v_top_attackers AS
SELECT 
    source_ip,
    COUNT(*) as attempt_count,
    MAX(timestamp) as last_attempt,
    SUM(CASE WHEN risk_level='CRITICAL' THEN 1 ELSE 0 END) as critical_count
FROM query_audit_log
WHERE risk_level IN ('DANGEROUS', 'CRITICAL')
GROUP BY source_ip
ORDER BY critical_count DESC;

-- ===========================
-- Permissions
-- ===========================

-- ktp_user permissions (limited, read-focused)
GRANT SELECT ON ktp_database.ktp_data TO 'ktp_user'@'%';
GRANT SELECT, INSERT, UPDATE ON ktp_database.query_audit_log TO 'ktp_user'@'%';

-- FLUSH PRIVILEGES to apply
FLUSH PRIVILEGES;

-- ===========================
-- Initial Log Entry
-- ===========================
INSERT INTO query_audit_log (query, source_ip, risk_level, action_taken)
VALUES 
('INIT: Database initialized', '127.0.0.1', 'SAFE', 'FORWARD');

-- ===========================
-- VERIFY SETUP
-- ===========================
SELECT 'Database initialized successfully' as status;
SELECT COUNT(*) as ktp_record_count FROM ktp_data;
SELECT @@version as mysql_version;
