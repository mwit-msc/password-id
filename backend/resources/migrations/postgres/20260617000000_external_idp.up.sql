-- pocket-id-password fork: external OIDC providers (social login / account linking)

CREATE TABLE external_idp_providers
(
    id              UUID        PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ,
    slug            TEXT        NOT NULL UNIQUE,
    name            TEXT        NOT NULL,
    client_id       TEXT        NOT NULL,
    client_secret   TEXT,
    issuer_url      TEXT        NOT NULL,
    scopes          TEXT        NOT NULL DEFAULT 'openid profile email',
    enabled         BOOLEAN     NOT NULL DEFAULT FALSE,
    allow_login     BOOLEAN     NOT NULL DEFAULT TRUE,
    allow_signup    BOOLEAN     NOT NULL DEFAULT FALSE,
    allowed_domains TEXT        NOT NULL DEFAULT '',
    managed_by_env  BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE TABLE user_external_identities
(
    id          UUID        PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ,
    user_id     UUID        NOT NULL REFERENCES users ON DELETE CASCADE,
    provider_id UUID        NOT NULL REFERENCES external_idp_providers ON DELETE CASCADE,
    subject     TEXT        NOT NULL,
    email       TEXT,
    UNIQUE (provider_id, subject)
);

CREATE INDEX idx_user_external_identities_user_id ON user_external_identities (user_id);

CREATE TABLE external_idp_auth_sessions
(
    id            UUID        PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL,
    state         TEXT        NOT NULL UNIQUE,
    provider_id   UUID        NOT NULL REFERENCES external_idp_providers ON DELETE CASCADE,
    code_verifier TEXT        NOT NULL,
    nonce         TEXT        NOT NULL,
    redirect_uri  TEXT        NOT NULL,
    mode          TEXT        NOT NULL,
    user_id       UUID        REFERENCES users ON DELETE CASCADE,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_external_idp_auth_sessions_expires_at ON external_idp_auth_sessions (expires_at);
