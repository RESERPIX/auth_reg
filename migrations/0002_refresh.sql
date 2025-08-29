ALTER TABLE sessions
  ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days';
