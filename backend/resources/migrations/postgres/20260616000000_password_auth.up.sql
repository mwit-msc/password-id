-- pocket-id-password fork: password + TOTP authentication

ALTER TABLE users
    ADD COLUMN password_hash       TEXT,
    ADD COLUMN failed_login_count  INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN locked_until        TIMESTAMPTZ,
    ADD COLUMN totp_secret         TEXT,
    ADD COLUMN totp_enabled        BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN totp_last_used_step BIGINT      NOT NULL DEFAULT 0;

CREATE TABLE password_reset_tokens
(
    id         UUID        PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    token_hash TEXT        NOT NULL UNIQUE,
    purpose    TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    user_id    UUID        NOT NULL REFERENCES users ON DELETE CASCADE
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);

CREATE TABLE mfa_challenges
(
    id            UUID        PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL,
    token_hash    TEXT        NOT NULL UNIQUE,
    expires_at    TIMESTAMPTZ NOT NULL,
    attempt_count INTEGER     NOT NULL DEFAULT 0,
    user_id       UUID        NOT NULL REFERENCES users ON DELETE CASCADE
);

CREATE INDEX idx_mfa_challenges_user_id ON mfa_challenges (user_id);
CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);

CREATE TABLE totp_recovery_codes
(
    id         UUID        PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    code_hash  TEXT        NOT NULL,
    used_at    TIMESTAMPTZ,
    user_id    UUID        NOT NULL REFERENCES users ON DELETE CASCADE
);

CREATE INDEX idx_totp_recovery_codes_user_id ON totp_recovery_codes (user_id);
