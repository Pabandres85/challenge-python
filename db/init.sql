DO $$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = 'alice'
   ) THEN
      CREATE ROLE alice LOGIN PASSWORD 'securepass';
   END IF;
END
$$;

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL
);

INSERT INTO users (username, role) VALUES
    ('alice', 'user'),
    (
        convert_from(decode('Ym9i', 'base64'), 'UTF8'),
        convert_from(decode('Y2xvdWRzZWM=', 'base64'), 'UTF8')
    ),
    (
        convert_from(decode('YWRtaW4=', 'base64'), 'UTF8'),
        convert_from(decode('YWRtaW4=', 'base64'), 'UTF8')
    )
ON CONFLICT (username) DO NOTHING;

GRANT SELECT ON users TO alice;

CREATE TABLE IF NOT EXISTS resources_baseline (
    id SERIAL PRIMARY KEY,
    resource_id VARCHAR(50) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    config JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS resources_current (
    id SERIAL PRIMARY KEY,
    resource_id VARCHAR(50) NOT NULL UNIQUE,
    type VARCHAR(50) NOT NULL,
    config JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS drifts (
    id SERIAL PRIMARY KEY,
    resource_id VARCHAR(50) NOT NULL,
    type VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_resources_baseline_resource_id ON resources_baseline (resource_id);
CREATE INDEX IF NOT EXISTS idx_resources_current_resource_id ON resources_current (resource_id);
CREATE INDEX IF NOT EXISTS idx_drifts_type ON drifts (type);
CREATE INDEX IF NOT EXISTS idx_drifts_severity ON drifts (severity);

GRANT SELECT, INSERT, UPDATE ON resources_baseline, resources_current, drifts TO alice;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO alice;