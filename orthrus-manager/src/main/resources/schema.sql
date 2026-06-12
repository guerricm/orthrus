CREATE TABLE IF NOT EXISTS "scan_results" (
    id VARCHAR(255) PRIMARY KEY,
    target_url VARCHAR(2048),
    scan_start_time TIMESTAMP,
    scan_end_time TIMESTAMP,
    operations_discovered INT,
    operations_scanned INT
);

CREATE TABLE IF NOT EXISTS "scan_attempts" (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_result_id VARCHAR(255),
    scanner_id VARCHAR(100),
    scanner_name VARCHAR(100),
    operation_method VARCHAR(20),
    operation_url VARCHAR(2048),
    status VARCHAR(50),
    FOREIGN KEY (scan_result_id) REFERENCES "scan_results"(id) ON DELETE CASCADE
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

-- Indexes for fast lookups by scan result ID
CREATE INDEX IF NOT EXISTS idx_scan_attempts_result ON "scan_attempts"(scan_result_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_result ON "vulnerabilities"(scan_result_id);

CREATE TABLE IF NOT EXISTS "slave_nodes" (
    id VARCHAR(255) PRIMARY KEY,
    url VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    max_concurrent_scans INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    last_seen_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "test_plans" (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    discoverer_id VARCHAR(100),
    target VARCHAR(2048),
    scan_configuration_json TEXT,
    created_at TIMESTAMP,
    last_modified_at TIMESTAMP,
    created_by VARCHAR(255),
    last_modified_by VARCHAR(255)
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
    test_plan_id BIGINT,
    result_id VARCHAR(255),
    vulns_count INT,
    tests_count INT,
    FOREIGN KEY (result_id) REFERENCES "scan_results"(id) ON DELETE SET NULL,
    FOREIGN KEY (test_plan_id) REFERENCES "test_plans"(id) ON DELETE SET NULL
);

-- Index for fast lookups of jobs by result ID and test plan ID
CREATE INDEX IF NOT EXISTS idx_scanjobs_result ON "scan_jobs"(result_id);
CREATE INDEX IF NOT EXISTS idx_scanjobs_test_plan ON "scan_jobs"(test_plan_id);

-- Add auditing columns safely if they do not exist
ALTER TABLE "test_plans" ADD COLUMN IF NOT EXISTS created_at TIMESTAMP;
ALTER TABLE "test_plans" ADD COLUMN IF NOT EXISTS last_modified_at TIMESTAMP;
ALTER TABLE "test_plans" ADD COLUMN IF NOT EXISTS created_by VARCHAR(255);
ALTER TABLE "test_plans" ADD COLUMN IF NOT EXISTS last_modified_by VARCHAR(255);

CREATE TABLE IF NOT EXISTS "scan_tasks" (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    scan_job_id BIGINT NOT NULL,
    phase VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    assigned_slave_id VARCHAR(255),
    endpoints_payload TEXT,
    created_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (scan_job_id) REFERENCES "scan_jobs"(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scantasks_job ON "scan_tasks"(scan_job_id);
CREATE INDEX IF NOT EXISTS idx_scantasks_status ON "scan_tasks"(status);
