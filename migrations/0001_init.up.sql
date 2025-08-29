CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS citext;

DO $$ BEGIN
  CREATE TYPE user_role AS ENUM ('journalist', 'guide', 'restaurant');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS users (
  id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email            CITEXT UNIQUE NOT NULL,
  phone            TEXT UNIQUE,
  first_name       TEXT NOT NULL,
  last_name        TEXT NOT NULL,
  role             user_role NOT NULL,
  password_hash    TEXT,
  email_confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
  phone_confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
  is_blocked       BOOLEAN NOT NULL DEFAULT FALSE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash TEXT NOT NULL,
  device_name        TEXT,
  ip_address         INET,
  user_agent         TEXT,
  last_active        TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

DO $$ BEGIN
  CREATE TYPE code_kind AS ENUM ('signup', 'twofa', 'reset');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS verification_codes (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        code_kind NOT NULL,
  code        TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  sent_to     TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_codes_user_kind ON verification_codes(user_id, kind) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_logs (
  id         BIGSERIAL PRIMARY KEY,
  user_id    UUID,
  action     TEXT NOT NULL,
  ip_address INET,
  user_agent TEXT,
  payload    JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
