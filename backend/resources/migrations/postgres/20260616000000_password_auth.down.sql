-- pocket-id-password fork: password + TOTP authentication

DROP TABLE totp_recovery_codes;
DROP TABLE mfa_challenges;
DROP TABLE password_reset_tokens;

ALTER TABLE users
    DROP COLUMN password_hash,
    DROP COLUMN failed_login_count,
    DROP COLUMN locked_until,
    DROP COLUMN totp_secret,
    DROP COLUMN totp_enabled,
    DROP COLUMN totp_last_used_step;
