-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Alerts table (hypertable)
CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL,
    timestamp       TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    severity        VARCHAR(20)     NOT NULL,
    attack_type     VARCHAR(100)    NOT NULL,
    src_ip          INET            NOT NULL,
    dst_ip          INET,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        VARCHAR(10),
    confidence      DOUBLE PRECISION,
    description     TEXT,
    raw_flow        JSONB,
    model_version   VARCHAR(50),
    resolved        BOOLEAN         DEFAULT FALSE,
    resolved_at     TIMESTAMPTZ,
    PRIMARY KEY (id, timestamp)
);

-- Convert alerts to a TimescaleDB hypertable partitioned by timestamp
SELECT create_hypertable('alerts', 'timestamp', if_not_exists => TRUE);

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id              BIGSERIAL       PRIMARY KEY,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    title           VARCHAR(255)    NOT NULL,
    description     TEXT,
    severity        VARCHAR(20)     NOT NULL,
    status          VARCHAR(30)     NOT NULL DEFAULT 'open',
    assigned_to     VARCHAR(100),
    alert_ids       BIGINT[],
    src_ips         INET[],
    attack_types    VARCHAR(100)[],
    notes           TEXT
);

-- Analyst feedback table
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id              BIGSERIAL       PRIMARY KEY,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    alert_id        BIGINT          NOT NULL,
    alert_timestamp TIMESTAMPTZ     NOT NULL,
    analyst         VARCHAR(100)    NOT NULL,
    verdict         VARCHAR(30)     NOT NULL,
    confidence      DOUBLE PRECISION,
    notes           TEXT,
    FOREIGN KEY (alert_id, alert_timestamp) REFERENCES alerts(id, timestamp)
);

-- Threat intelligence IOCs table
CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    id              BIGSERIAL       PRIMARY KEY,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    ioc_type        VARCHAR(50)     NOT NULL,
    ioc_value       TEXT            NOT NULL,
    source          VARCHAR(100)    NOT NULL,
    confidence      DOUBLE PRECISION,
    severity        VARCHAR(20),
    tags            TEXT[],
    expires_at      TIMESTAMPTZ,
    active          BOOLEAN         DEFAULT TRUE
);

-- Model versions table
CREATE TABLE IF NOT EXISTS model_versions (
    id              BIGSERIAL       PRIMARY KEY,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    model_name      VARCHAR(100)    NOT NULL,
    version         VARCHAR(50)     NOT NULL,
    framework       VARCHAR(50),
    metrics         JSONB,
    parameters      JSONB,
    artifact_path   TEXT,
    is_active       BOOLEAN         DEFAULT FALSE,
    promoted_at     TIMESTAMPTZ,
    notes           TEXT,
    UNIQUE (model_name, version)
);

-- Indexes on alerts table
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts (attack_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);

-- Indexes on other tables
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_alert ON analyst_feedback (alert_id, alert_timestamp);
CREATE INDEX IF NOT EXISTS idx_threat_intel_ioc_type ON threat_intel_iocs (ioc_type, ioc_value);
CREATE INDEX IF NOT EXISTS idx_threat_intel_active ON threat_intel_iocs (active, expires_at);
CREATE INDEX IF NOT EXISTS idx_model_versions_active ON model_versions (model_name, is_active);
