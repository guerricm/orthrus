CREATE TABLE IF NOT EXISTS "scan_results" (
    id VARCHAR(255) PRIMARY KEY,
    target_url VARCHAR(2048),
    scan_start_time TIMESTAMP,
    scan_end_time TIMESTAMP,
    operations_discovered INT,
    operations_scanned INT
);

CREATE TABLE IF NOT EXISTS "vulnerabilities" (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_result_id VARCHAR(255),
    vulnerability_title VARCHAR(255),
    vulnerability_description TEXT,
    risk_level VARCHAR(50),
    confidence VARCHAR(50),
    scanner_id VARCHAR(100),
    operation_url VARCHAR(2048),
    operation_method VARCHAR(20),
    cwe_id VARCHAR(50),
    cwe_name VARCHAR(255),
    capec_ids VARCHAR(255),
    cvss_base_score DOUBLE,
    evidence TEXT,
    recommendation TEXT,
    request_summary TEXT,
    response_summary TEXT,
    attack_vector VARCHAR(255),
    technical_impact VARCHAR(255),
    FOREIGN KEY (scan_result_id) REFERENCES "scan_results"(id) ON DELETE CASCADE
);

-- Index for fast evolution queries
CREATE INDEX IF NOT EXISTS idx_vuln_op ON "vulnerabilities"(operation_method, operation_url);

CREATE TABLE IF NOT EXISTS "slave_nodes" (
    id VARCHAR(255) PRIMARY KEY,
    url VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    max_concurrent_scans INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    last_seen_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "scan_jobs" (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    discoverer_id VARCHAR(100),
    target VARCHAR(2048),
    scan_configuration_json TEXT,
    status VARCHAR(50) NOT NULL,
    assigned_slave_id VARCHAR(255),
    created_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    result_id VARCHAR(255),
    vulns_count INT,
    tests_count INT
);
