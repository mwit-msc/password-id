-- pocket-id-password fork: external OIDC providers
PRAGMA foreign_keys= OFF;
BEGIN;
DROP TABLE IF EXISTS external_idp_auth_sessions;
DROP TABLE IF EXISTS user_external_identities;
DROP TABLE IF EXISTS external_idp_providers;
COMMIT;
PRAGMA foreign_keys= ON;
