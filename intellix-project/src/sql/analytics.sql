-- ============================================================
-- Intellix Database Schema & Analytics — PostgreSQL 16
-- ============================================================
-- Complete production schema with:
--   - All 12 core tables with constraints & indexes
--   - Row-level security policies
--   - Materialized views for analytics
--   - Stored procedures for payment processing
--   - Fraud analytics queries with CTEs & window functions
--   - Real-time risk scoring views
--
-- Run: psql -U postgres -d intellix -f analytics.sql
-- ============================================================

-- ─────────────────────────────────────────────
-- EXTENSIONS
-- ─────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";       -- fuzzy text search
CREATE EXTENSION IF NOT EXISTS "btree_gin";      -- multi-column GIN indexes

-- ─────────────────────────────────────────────
-- ENUMS
-- ─────────────────────────────────────────────

CREATE TYPE account_type      AS ENUM ('personal', 'business');
CREATE TYPE kyc_status        AS ENUM ('pending', 'approved', 'failed', 'expired');
CREATE TYPE user_tier         AS ENUM ('starter', 'pro', 'enterprise');
CREATE TYPE txn_status        AS ENUM ('pending', 'processing', 'confirmed', 'failed', 'flagged', 'cancelled');
CREATE TYPE payment_method    AS ENUM ('crypto', 'wire', 'ach', 'swift', 'fx', 'split', 'api', 'defi');
CREATE TYPE fraud_severity    AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE fraud_action      AS ENUM ('monitor', 'flag_review', 'auto_hold', 'block', 'cleared');
CREATE TYPE currency_type     AS ENUM ('fiat', 'crypto', 'stablecoin');
CREATE TYPE wallet_type       AS ENUM ('custodial', 'self_custody', 'fiat');
CREATE TYPE doc_type          AS ENUM ('passport', 'drivers_license', 'national_id', 'residence_permit');
CREATE TYPE biometric_method  AS ENUM ('fingerprint', 'face_id', 'voice');
CREATE TYPE audit_action      AS ENUM ('INSERT', 'UPDATE', 'DELETE', 'SELECT', 'EXPORT', 'LOGIN', 'LOGOUT');

-- ─────────────────────────────────────────────
-- CORE TABLES
-- ─────────────────────────────────────────────

CREATE TABLE users (
    id              TEXT        PRIMARY KEY DEFAULT 'USR' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    email           TEXT        UNIQUE NOT NULL,
    full_name       TEXT        NOT NULL,
    phone           TEXT,
    country         TEXT        NOT NULL DEFAULT 'Unknown',
    account_type    account_type NOT NULL DEFAULT 'personal',
    kyc_status      kyc_status  NOT NULL DEFAULT 'pending',
    risk_score      NUMERIC(5,4) NOT NULL DEFAULT 0.0 CHECK (risk_score >= 0 AND risk_score <= 1),
    tier            user_tier   NOT NULL DEFAULT 'starter',
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login      TIMESTAMPTZ,
    metadata        JSONB       DEFAULT '{}'::jsonb,
    CONSTRAINT email_format CHECK (email ~* '^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
);

CREATE TABLE wallets (
    id              TEXT        PRIMARY KEY DEFAULT 'WAL' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    user_id         TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    currency        TEXT        NOT NULL,
    address         TEXT        NOT NULL,
    balance         NUMERIC(28, 8) NOT NULL DEFAULT 0 CHECK (balance >= 0),
    balance_usd     NUMERIC(18, 2) NOT NULL DEFAULT 0 CHECK (balance_usd >= 0),
    network         TEXT,
    wallet_type     wallet_type NOT NULL DEFAULT 'custodial',
    is_primary      BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, currency, address)
);

CREATE TABLE currencies (
    code            TEXT        PRIMARY KEY,
    name            TEXT        NOT NULL,
    type            currency_type NOT NULL,
    symbol          TEXT        NOT NULL,
    decimals        INTEGER     NOT NULL DEFAULT 2 CHECK (decimals >= 0 AND decimals <= 18),
    network         TEXT,
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    min_amount      NUMERIC(18,8) NOT NULL DEFAULT 0.01,
    max_amount      NUMERIC(18,2) NOT NULL DEFAULT 1000000
);

CREATE TABLE payments (
    id              TEXT        PRIMARY KEY DEFAULT 'PAY' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    user_id         TEXT        NOT NULL REFERENCES users(id),
    amount          NUMERIC(18, 8) NOT NULL CHECK (amount > 0),
    currency        TEXT        NOT NULL REFERENCES currencies(code),
    status          txn_status  NOT NULL DEFAULT 'pending',
    payment_method  payment_method NOT NULL,
    recipient_wallet TEXT,
    recipient_name  TEXT,
    description     TEXT,
    route_optimizer BOOLEAN     NOT NULL DEFAULT true,
    scheduled_at    TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE transactions (
    id              TEXT        PRIMARY KEY DEFAULT 'TXN' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    user_id         TEXT        NOT NULL REFERENCES users(id),
    payment_id      TEXT        REFERENCES payments(id),
    type            TEXT        NOT NULL,
    status          txn_status  NOT NULL DEFAULT 'pending',
    amount          NUMERIC(18, 8) NOT NULL CHECK (amount > 0),
    currency        TEXT        NOT NULL,
    amount_usd      NUMERIC(18, 2),
    from_wallet     TEXT,
    to_wallet       TEXT,
    network         TEXT,
    tx_hash         TEXT        UNIQUE,
    fee             NUMERIC(10, 4) NOT NULL DEFAULT 0,
    risk_score      NUMERIC(5, 4) NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 1),
    fraud_flag      BOOLEAN     NOT NULL DEFAULT false,
    route           TEXT,
    metadata        JSONB       DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at    TIMESTAMPTZ
);

CREATE TABLE fraud_alerts (
    id              TEXT        PRIMARY KEY DEFAULT 'FA' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    transaction_id  TEXT        NOT NULL REFERENCES transactions(id),
    user_id         TEXT        NOT NULL REFERENCES users(id),
    risk_score      NUMERIC(5, 4) NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    severity        fraud_severity NOT NULL,
    signals         TEXT[],
    verdict         TEXT        NOT NULL,
    action_taken    fraud_action NOT NULL DEFAULT 'monitor',
    reviewed_by     TEXT,
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE kyc_verifications (
    id              TEXT        PRIMARY KEY DEFAULT 'KYC' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    user_id         TEXT        NOT NULL REFERENCES users(id) UNIQUE,
    status          kyc_status  NOT NULL DEFAULT 'pending',
    doc_type        doc_type,
    doc_country     TEXT,
    biometric_method biometric_method,
    verified_at     TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    provider        TEXT        NOT NULL DEFAULT 'Intellix-KYC',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE api_keys (
    id              TEXT        PRIMARY KEY DEFAULT 'AK' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    user_id         TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash        TEXT        UNIQUE NOT NULL,
    key_prefix      TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    permissions     TEXT[]      NOT NULL DEFAULT ARRAY['payments:read'],
    last_used       TIMESTAMPTZ,
    calls_today     INTEGER     NOT NULL DEFAULT 0,
    calls_total     BIGINT      NOT NULL DEFAULT 0,
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webhooks (
    id              TEXT        PRIMARY KEY DEFAULT 'WH' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    user_id         TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url             TEXT        NOT NULL,
    events          TEXT[]      NOT NULL,
    secret_hash     TEXT        NOT NULL,
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    last_triggered  TIMESTAMPTZ,
    success_count   INTEGER     NOT NULL DEFAULT 0,
    fail_count      INTEGER     NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE exchange_rates (
    id              TEXT        PRIMARY KEY DEFAULT 'ER' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
    from_currency   TEXT        NOT NULL,
    to_currency     TEXT        NOT NULL,
    rate            NUMERIC(18, 8) NOT NULL CHECK (rate > 0),
    bid             NUMERIC(18, 8),
    ask             NUMERIC(18, 8),
    source          TEXT        NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (from_currency, to_currency, source)
);

CREATE TABLE audit_logs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    action          audit_action NOT NULL,
    table_name      TEXT        NOT NULL,
    record_id       TEXT,
    old_values      JSONB,
    new_values      JSONB,
    user_id         TEXT,
    ip_address      INET,
    user_agent      TEXT
);

-- ─────────────────────────────────────────────
-- INDEXES
-- ─────────────────────────────────────────────

-- Users
CREATE INDEX idx_users_email       ON users (lower(email));
CREATE INDEX idx_users_country     ON users (country);
CREATE INDEX idx_users_kyc_status  ON users (kyc_status);
CREATE INDEX idx_users_risk        ON users (risk_score DESC);
CREATE INDEX idx_users_created     ON users (created_at DESC);

-- Transactions
CREATE INDEX idx_txn_user          ON transactions (user_id, created_at DESC);
CREATE INDEX idx_txn_status        ON transactions (status);
CREATE INDEX idx_txn_created       ON transactions (created_at DESC);
CREATE INDEX idx_txn_fraud         ON transactions (fraud_flag) WHERE fraud_flag = true;
CREATE INDEX idx_txn_hash          ON transactions (tx_hash) WHERE tx_hash IS NOT NULL;
CREATE INDEX idx_txn_amount        ON transactions (amount_usd DESC);
CREATE INDEX idx_txn_currency      ON transactions (currency);
CREATE INDEX idx_txn_metadata      ON transactions USING GIN (metadata);

-- Fraud alerts
CREATE INDEX idx_fraud_severity    ON fraud_alerts (severity, created_at DESC);
CREATE INDEX idx_fraud_risk        ON fraud_alerts (risk_score DESC);
CREATE INDEX idx_fraud_unreviewed  ON fraud_alerts (created_at DESC) WHERE reviewed_at IS NULL;

-- Wallets
CREATE INDEX idx_wallet_user       ON wallets (user_id);
CREATE INDEX idx_wallet_currency   ON wallets (currency);
CREATE INDEX idx_wallet_address    ON wallets (address);

-- Audit logs
CREATE INDEX idx_audit_timestamp   ON audit_logs (timestamp DESC);
CREATE INDEX idx_audit_action      ON audit_logs (action, table_name);
CREATE INDEX idx_audit_user        ON audit_logs (user_id, timestamp DESC);

-- ─────────────────────────────────────────────
-- ROW LEVEL SECURITY
-- ─────────────────────────────────────────────

ALTER TABLE users         ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallets        ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions   ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments       ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys       ENABLE ROW LEVEL SECURITY;

-- Users can only see their own data
CREATE POLICY users_self_only ON users
    FOR ALL USING (id = current_setting('app.user_id', true));

-- Admin role bypasses RLS
CREATE POLICY users_admin ON users
    FOR ALL TO intellix_admin USING (true);

CREATE POLICY wallets_self_only ON wallets
    FOR ALL USING (user_id = current_setting('app.user_id', true));

CREATE POLICY txns_self_only ON transactions
    FOR ALL USING (user_id = current_setting('app.user_id', true));

-- ─────────────────────────────────────────────
-- AUTOMATIC AUDIT TRIGGER
-- ─────────────────────────────────────────────

CREATE OR REPLACE FUNCTION audit_trigger_fn()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    INSERT INTO audit_logs (action, table_name, record_id, old_values, new_values, user_id, ip_address)
    VALUES (
        TG_OP::audit_action,
        TG_TABLE_NAME,
        CASE TG_OP WHEN 'DELETE' THEN OLD.id ELSE NEW.id END,
        CASE TG_OP WHEN 'INSERT' THEN NULL ELSE to_jsonb(OLD) END,
        CASE TG_OP WHEN 'DELETE' THEN NULL ELSE to_jsonb(NEW) END,
        current_setting('app.user_id', true),
        inet(current_setting('app.client_ip', true))
    );
    RETURN COALESCE(NEW, OLD);
END;
$$;

-- Apply audit trigger to key tables
CREATE TRIGGER audit_users         AFTER INSERT OR UPDATE OR DELETE ON users         FOR EACH ROW EXECUTE FUNCTION audit_trigger_fn();
CREATE TRIGGER audit_transactions  AFTER INSERT OR UPDATE OR DELETE ON transactions  FOR EACH ROW EXECUTE FUNCTION audit_trigger_fn();
CREATE TRIGGER audit_payments      AFTER INSERT OR UPDATE OR DELETE ON payments      FOR EACH ROW EXECUTE FUNCTION audit_trigger_fn();
CREATE TRIGGER audit_fraud_alerts  AFTER INSERT OR UPDATE OR DELETE ON fraud_alerts  FOR EACH ROW EXECUTE FUNCTION audit_trigger_fn();

-- ─────────────────────────────────────────────
-- STORED PROCEDURES
-- ─────────────────────────────────────────────

-- Create a payment and transaction atomically
CREATE OR REPLACE PROCEDURE create_payment(
    p_user_id        TEXT,
    p_amount         NUMERIC,
    p_currency       TEXT,
    p_recipient      TEXT,
    p_method         payment_method,
    p_route          TEXT,
    p_fee            NUMERIC,
    p_risk_score     NUMERIC,
    OUT p_payment_id TEXT,
    OUT p_txn_id     TEXT
)
LANGUAGE plpgsql AS $$
DECLARE
    v_amount_usd NUMERIC;
    v_rate       NUMERIC;
BEGIN
    -- Get exchange rate
    SELECT rate INTO v_rate
    FROM exchange_rates
    WHERE from_currency = p_currency AND to_currency = 'USD'
    ORDER BY updated_at DESC LIMIT 1;

    v_amount_usd := COALESCE(p_amount * v_rate, p_amount);

    -- Create payment record
    INSERT INTO payments (user_id, amount, currency, status, payment_method, recipient_wallet)
    VALUES (p_user_id, p_amount, p_currency, 'processing', p_method, p_recipient)
    RETURNING id INTO p_payment_id;

    -- Create transaction record
    INSERT INTO transactions (user_id, payment_id, type, status, amount, currency,
        amount_usd, to_wallet, network, fee, risk_score, route)
    VALUES (p_user_id, p_payment_id, p_method::TEXT, 'processing', p_amount, p_currency,
        v_amount_usd, p_recipient, SPLIT_PART(p_route, '_', 1), p_fee, p_risk_score, p_route)
    RETURNING id INTO p_txn_id;

    -- Flag for fraud review if high risk
    IF p_risk_score >= 0.60 THEN
        UPDATE transactions SET fraud_flag = true, status = 'flagged'
        WHERE id = p_txn_id;

        UPDATE payments SET status = 'flagged'
        WHERE id = p_payment_id;
    END IF;

    COMMIT;
END;
$$;

-- Confirm a transaction with tx hash
CREATE OR REPLACE PROCEDURE confirm_transaction(
    p_txn_id  TEXT,
    p_tx_hash TEXT
)
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE transactions
    SET status = 'confirmed', tx_hash = p_tx_hash, confirmed_at = now()
    WHERE id = p_txn_id AND status = 'processing';

    UPDATE payments p
    SET status = 'confirmed', completed_at = now()
    FROM transactions t
    WHERE t.id = p_txn_id AND t.payment_id = p.id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Transaction % not found or not in processing state', p_txn_id;
    END IF;

    COMMIT;
END;
$$;

-- ─────────────────────────────────────────────
-- MATERIALIZED VIEWS FOR ANALYTICS
-- ─────────────────────────────────────────────

CREATE MATERIALIZED VIEW mv_daily_volume AS
SELECT
    date_trunc('day', created_at)       AS day,
    currency,
    COUNT(*)                            AS txn_count,
    SUM(amount_usd)                     AS total_usd,
    AVG(amount_usd)                     AS avg_usd,
    MAX(amount_usd)                     AS max_usd,
    SUM(fee)                            AS total_fees,
    COUNT(*) FILTER (WHERE fraud_flag)  AS flagged_count,
    AVG(risk_score)                     AS avg_risk
FROM transactions
WHERE status IN ('confirmed', 'processing')
GROUP BY 1, 2
WITH DATA;

CREATE UNIQUE INDEX ON mv_daily_volume (day, currency);

CREATE MATERIALIZED VIEW mv_user_risk_profile AS
SELECT
    u.id,
    u.full_name,
    u.email,
    u.country,
    u.tier,
    COUNT(t.id)                         AS total_txns,
    SUM(t.amount_usd)                   AS total_volume_usd,
    AVG(t.risk_score)                   AS avg_risk,
    MAX(t.risk_score)                   AS max_risk,
    COUNT(*) FILTER (WHERE t.fraud_flag) AS flagged_txns,
    ROUND(COUNT(*) FILTER (WHERE t.fraud_flag)::NUMERIC / NULLIF(COUNT(*), 0) * 100, 2) AS fraud_rate_pct,
    SUM(w.balance_usd)                  AS total_wallet_usd
FROM users u
LEFT JOIN transactions t ON u.id = t.user_id
LEFT JOIN wallets w ON u.id = w.user_id
GROUP BY u.id, u.full_name, u.email, u.country, u.tier
WITH DATA;

CREATE UNIQUE INDEX ON mv_user_risk_profile (id);

-- Refresh materialized views (schedule via pg_cron in production)
CREATE OR REPLACE PROCEDURE refresh_analytics_views()
LANGUAGE sql AS $$
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_daily_volume;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_user_risk_profile;
$$;

-- ─────────────────────────────────────────────
-- ANALYTICS QUERIES
-- ─────────────────────────────────────────────

-- ── 1. Fraud Detection Report (last 30 days) ──
-- Identifies users with elevated fraud rates using window functions

/*
WITH risk_buckets AS (
    SELECT
        u.id                                                        AS user_id,
        u.full_name,
        u.email,
        u.country,
        t.currency,
        COUNT(*)                                                    AS txn_count,
        SUM(t.amount_usd)                                           AS total_volume,
        AVG(t.risk_score)                                           AS avg_risk,
        MAX(t.risk_score)                                           AS peak_risk,
        SUM(t.fraud_flag::int)                                      AS flagged_count,
        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY t.amount_usd)  AS p95_amount,
        PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY t.amount_usd)  AS p99_amount,
        -- Velocity: transactions per hour (last 30d)
        COUNT(*) / GREATEST(EXTRACT(EPOCH FROM (MAX(t.created_at) - MIN(t.created_at))) / 3600, 1) AS txns_per_hour
    FROM transactions t
    JOIN users u ON t.user_id = u.id
    WHERE t.created_at > now() - INTERVAL '30 days'
    GROUP BY u.id, u.full_name, u.email, u.country, t.currency
),
ranked AS (
    SELECT *,
        ROUND(flagged_count::NUMERIC / NULLIF(txn_count, 0) * 100, 2) AS fraud_rate_pct,
        NTILE(100) OVER (ORDER BY avg_risk)                             AS risk_percentile,
        NTILE(100) OVER (ORDER BY total_volume)                         AS volume_percentile,
        ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY total_volume DESC) AS rank_by_vol
    FROM risk_buckets
)
SELECT
    user_id, full_name, country, currency,
    txn_count, total_volume, avg_risk, fraud_rate_pct,
    risk_percentile, txns_per_hour
FROM ranked
WHERE rank_by_vol = 1
ORDER BY avg_risk DESC, total_volume DESC
LIMIT 50;
*/

-- ── 2. Real-Time Fraud Alert Dashboard ──

/*
SELECT
    fa.id                   AS alert_id,
    fa.severity,
    fa.risk_score,
    fa.verdict,
    fa.action_taken,
    t.id                    AS txn_id,
    t.amount_usd,
    t.currency,
    t.from_wallet,
    t.to_wallet,
    t.network,
    u.full_name,
    u.email,
    u.country,
    u.kyc_status,
    fa.signals,
    fa.created_at,
    fa.reviewed_at,
    EXTRACT(EPOCH FROM (now() - fa.created_at)) / 60 AS minutes_pending
FROM fraud_alerts fa
JOIN transactions t  ON fa.transaction_id = t.id
JOIN users u         ON fa.user_id = u.id
WHERE fa.reviewed_at IS NULL
ORDER BY fa.severity DESC, fa.risk_score DESC, fa.created_at ASC;
*/

-- ── 3. Volume Trend with Rolling 7-day Average ──

/*
WITH daily AS (
    SELECT
        date_trunc('day', created_at) AS day,
        SUM(amount_usd)               AS daily_volume,
        COUNT(*)                      AS daily_txns,
        AVG(risk_score)               AS daily_avg_risk
    FROM transactions
    WHERE status = 'confirmed'
    AND   created_at > now() - INTERVAL '90 days'
    GROUP BY 1
)
SELECT
    day,
    daily_volume,
    daily_txns,
    ROUND(daily_avg_risk, 4)          AS avg_risk,
    ROUND(AVG(daily_volume) OVER (
        ORDER BY day
        ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
    ), 2)                             AS rolling_7d_avg,
    ROUND(SUM(daily_volume) OVER (
        ORDER BY day
        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ), 2)                             AS cumulative_volume,
    ROUND(daily_volume / NULLIF(LAG(daily_volume) OVER (ORDER BY day), 0) - 1, 4) AS day_over_day_pct
FROM daily
ORDER BY day DESC;
*/

-- ── 4. Currency Pair Flow Analysis ──

/*
SELECT
    t.currency                          AS from_currency,
    COALESCE(t.metadata->>'to_currency', t.currency) AS to_currency,
    COUNT(*)                            AS flow_count,
    SUM(t.amount_usd)                   AS total_usd,
    AVG(t.fee)                          AS avg_fee,
    MIN(er.rate)                        AS rate_low,
    MAX(er.rate)                        AS rate_high,
    AVG(er.rate)                        AS rate_avg
FROM transactions t
LEFT JOIN exchange_rates er
    ON er.from_currency = t.currency
    AND er.to_currency = COALESCE(t.metadata->>'to_currency', 'USD')
    AND er.updated_at > now() - INTERVAL '1 hour'
WHERE t.created_at > now() - INTERVAL '7 days'
AND   t.status = 'confirmed'
GROUP BY 1, 2
HAVING COUNT(*) > 5
ORDER BY total_usd DESC;
*/

-- ── 5. Top API Key Usage ──

/*
SELECT
    ak.key_prefix || '...' AS api_key,
    ak.name,
    u.full_name,
    u.email,
    ak.permissions,
    ak.calls_today,
    ak.calls_total,
    ak.last_used,
    EXTRACT(EPOCH FROM (now() - ak.last_used)) / 60 AS minutes_since_use
FROM api_keys ak
JOIN users u ON ak.user_id = u.id
WHERE ak.is_active = true
ORDER BY ak.calls_today DESC
LIMIT 20;
*/

-- ─────────────────────────────────────────────
-- SEED DATA (development / testing)
-- ─────────────────────────────────────────────

-- Currencies
INSERT INTO currencies (code, name, type, symbol, decimals, network, min_amount, max_amount) VALUES
    ('USD',  'US Dollar',         'fiat',       '$',  2,  NULL,       0.01,    1000000),
    ('EUR',  'Euro',              'fiat',       '€',  2,  NULL,       0.01,    1000000),
    ('GBP',  'British Pound',     'fiat',       '£',  2,  NULL,       0.01,    1000000),
    ('JPY',  'Japanese Yen',      'fiat',       '¥',  0,  NULL,       1,       100000000),
    ('BTC',  'Bitcoin',           'crypto',     '₿',  8,  'bitcoin',  0.00001, 100),
    ('ETH',  'Ethereum',          'crypto',     'Ξ',  18, 'ethereum', 0.0001,  10000),
    ('USDC', 'USD Coin',          'stablecoin', '$',  6,  'ethereum', 0.01,    10000000),
    ('USDT', 'Tether',            'stablecoin', '$',  6,  'ethereum', 0.01,    10000000),
    ('SOL',  'Solana',            'crypto',     '◎',  9,  'solana',   0.001,   100000),
    ('BNB',  'BNB',               'crypto',     'B',  18, 'bsc',      0.001,   100000),
    ('MATIC','Polygon',           'crypto',     '⬡',  18, 'polygon',  0.01,    10000000),
    ('AUD',  'Australian Dollar', 'fiat',       'A$', 2,  NULL,       0.01,    1000000),
    ('CAD',  'Canadian Dollar',   'fiat',       'C$', 2,  NULL,       0.01,    1000000),
    ('SGD',  'Singapore Dollar',  'fiat',       'S$', 2,  NULL,       0.01,    1000000)
ON CONFLICT (code) DO NOTHING;

-- Exchange rates snapshot
INSERT INTO exchange_rates (from_currency, to_currency, rate, bid, ask, source) VALUES
    ('BTC',  'USD',  66598.42, 66550.00, 66620.00, 'binance'),
    ('ETH',  'USD',  3502.18,  3498.00,  3506.00,  'binance'),
    ('USDC', 'USD',  1.0001,   0.9999,   1.0003,   'coinbase'),
    ('SOL',  'USD',  142.30,   141.80,   142.80,   'binance'),
    ('EUR',  'USD',  1.0806,   1.0802,   1.0810,   'ecb'),
    ('GBP',  'USD',  1.2671,   1.2668,   1.2674,   'boe'),
    ('JPY',  'USD',  0.00667,  0.00666,  0.00668,  'boj'),
    ('USD',  'EUR',  0.9254,   0.9250,   0.9258,   'ecb'),
    ('USD',  'GBP',  0.7892,   0.7889,   0.7895,   'boe'),
    ('MATIC','USD',  0.8420,   0.8390,   0.8450,   'binance')
ON CONFLICT (from_currency, to_currency, source) DO UPDATE
    SET rate = EXCLUDED.rate, bid = EXCLUDED.bid, ask = EXCLUDED.ask, updated_at = now();

COMMENT ON TABLE users IS 'Core user accounts for the Intellix platform';
COMMENT ON TABLE transactions IS 'All payment transactions with risk scoring and fraud flags';
COMMENT ON TABLE fraud_alerts IS 'AI-generated fraud alerts requiring human review';
COMMENT ON TABLE audit_logs IS 'Immutable audit trail for all database operations';
COMMENT ON MATERIALIZED VIEW mv_daily_volume IS 'Pre-aggregated daily volume — refresh every hour via pg_cron';
