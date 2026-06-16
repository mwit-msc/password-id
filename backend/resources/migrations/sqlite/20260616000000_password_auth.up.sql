-- pocket-id-password fork: password + TOTP authentication
PRAGMA foreign_keys= OFF;
BEGIN;

ALTER TABLE users ADD COLUMN password_hash TEXT;
ALTER TABLE users ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until DATETIME;
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE password_reset_tokens
(
    id         TEXT     PRIMARY KEY,
    created_at DATETIME NOT NULL,
    token_hash TEXT     NOT NULL UNIQUE,
    purpose    TEXT     NOT NULL,
    expires_at DATETIME NOT NULL,
    user_id    TEXT     NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);

CREATE TABLE mfa_challenges
(
    id            TEXT     PRIMARY KEY,
    created_at    DATETIME NOT NULL,
    expires_at    DATETIME NOT NULL,
    attempt_count INTEGER  NOT NULL DEFAULT 0,
    user_id       TEXT     NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_mfa_challenges_user_id ON mfa_challenges (user_id);
CREATE INDEX idx_mfa_challenges_expires_at ON mfa_challenges (expires_at);

CREATE TABLE totp_recovery_codes
(
    id         TEXT     PRIMARY KEY,
    created_at DATETIME NOT NULL,
    code_hash  TEXT     NOT NULL,
    used_at    DATETIME,
    user_id    TEXT     NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_totp_recovery_codes_user_id ON totp_recovery_codes (user_id);

COMMIT;
PRAGMA foreign_keys= ON;
