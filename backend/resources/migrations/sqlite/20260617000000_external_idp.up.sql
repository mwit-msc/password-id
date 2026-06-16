-- pocket-id-password fork: external OIDC providers (social login / account linking)
PRAGMA foreign_keys= OFF;
BEGIN;

CREATE TABLE external_idp_providers
(
    id              TEXT     PRIMARY KEY,
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME,
    slug            TEXT     NOT NULL UNIQUE,
    name            TEXT     NOT NULL,
    client_id       TEXT     NOT NULL,
    client_secret   TEXT,
    issuer_url      TEXT     NOT NULL,
    scopes          TEXT     NOT NULL DEFAULT 'openid profile email',
    enabled         BOOLEAN  NOT NULL DEFAULT FALSE,
    allow_login     BOOLEAN  NOT NULL DEFAULT TRUE,
    allow_signup    BOOLEAN  NOT NULL DEFAULT FALSE,
    allowed_domains TEXT     NOT NULL DEFAULT '',
    managed_by_env  BOOLEAN  NOT NULL DEFAULT FALSE
);

CREATE TABLE user_external_identities
(
    id          TEXT     PRIMARY KEY,
    created_at  DATETIME NOT NULL,
    updated_at  DATETIME,
    user_id     TEXT     NOT NULL,
    provider_id TEXT     NOT NULL,
    subject     TEXT     NOT NULL,
    email       TEXT,
    UNIQUE (provider_id, subject),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id) REFERENCES external_idp_providers (id) ON DELETE CASCADE
);

CREATE INDEX idx_user_external_identities_user_id ON user_external_identities (user_id);

CREATE TABLE external_idp_auth_sessions
(
    id            TEXT     PRIMARY KEY,
    created_at    DATETIME NOT NULL,
    state         TEXT     NOT NULL UNIQUE,
    provider_id   TEXT     NOT NULL,
    code_verifier TEXT     NOT NULL,
    nonce         TEXT     NOT NULL,
    redirect_uri  TEXT     NOT NULL,
    mode          TEXT     NOT NULL,
    user_id       TEXT,
    expires_at    DATETIME NOT NULL,
    FOREIGN KEY (provider_id) REFERENCES external_idp_providers (id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX idx_external_idp_auth_sessions_expires_at ON external_idp_auth_sessions (expires_at);

COMMIT;
PRAGMA foreign_keys= ON;
