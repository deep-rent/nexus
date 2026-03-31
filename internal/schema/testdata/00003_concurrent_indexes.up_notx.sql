-- Migration: 00003_concurrent_indexes
-- Description: Creates concurrent indexes on high-traffic tables.
-- Execution: MUST run outside of a transaction (_notx).

/*
  Creating indexes concurrently avoids locking the table against writes.
  This is crucial for production environments with zero downtime requirements.
*/
CREATE INDEX CONCURRENTLY idx_audit_logs_table_record
ON audit_logs(table_name, record_id);

CREATE INDEX CONCURRENTLY idx_audit_logs_action
ON audit_logs(action);

-- Add a complex view containing double quotes (identifiers) and single quotes
CREATE OR REPLACE VIEW active_user_summary AS
SELECT
    t.name AS "Tenant Name",
    COUNT(u.id) AS "Total Active Users",
    MAX(u.created_at) AS "Latest Registration"
FROM
    tenants t
JOIN
    users u ON t.id = u.tenant_id
WHERE
    u.status = 'active'
    AND u.email NOT LIKE '%@system.local' /* Ignore system accounts */
GROUP BY
    t.id, t.name;
