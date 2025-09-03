ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_enabled boolean NOT NULL DEFAULT false;
