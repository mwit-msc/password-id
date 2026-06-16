-- pocket-id-password fork: password + TOTP authentication
PRAGMA foreign_keys= OFF;
BEGIN;

DROP TABLE totp_recovery_codes;
DROP TABLE mfa_challenges;
DROP TABLE password_reset_tokens;

ALTER TABLE users DROP COLUMN password_hash;
ALTER TABLE users DROP COLUMN failed_login_count;
ALTER TABLE users DROP COLUMN locked_until;
ALTER TABLE users DROP COLUMN totp_secret;
ALTER TABLE users DROP COLUMN totp_enabled;
ALTER TABLE users DROP COLUMN totp_last_used_step;

COMMIT;
PRAGMA foreign_keys= ON;
