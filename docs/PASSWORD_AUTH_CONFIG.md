# Password + TOTP Authentication — Configuration

This fork adds username/password login (with optional TOTP second factor) alongside
Pocket ID's passkey auth. Everything is **disabled by default**, so a fresh install behaves
exactly like upstream until you turn it on.

## Enabling

Password auth and TOTP are runtime settings stored in the database and editable in the
admin UI (**Settings → Application Configuration**), or via the config API. Three flags:

| Setting (admin UI / API key)   | Default | Effect |
|--------------------------------|---------|--------|
| `passwordAuthEnabled`          | `false` | Enables the password login routes and UI. |
| `totpEnabled`                  | `false` | Allows users to enroll a TOTP second factor; enforced at login for users who have it. |
| `breachCheckEnabled`           | `false` | Checks new passwords against HaveIBeenPwned (k-anonymity range API). Fail-open. |

`passwordAuthEnabled` and `totpEnabled` are **public** config (the login UI reads them to
decide what to show). `breachCheckEnabled` is private.

## Environment variables (policy / cost)

These tune the credential layer and are read from the environment (same mechanism as all
other Pocket ID env config). All optional — sane defaults shown.

| Env var                              | Default | Meaning |
|--------------------------------------|---------|---------|
| `PASSWORD_MIN_LENGTH`                | `10`    | Minimum password length. |
| `PASSWORD_ARGON2_MEMORY`             | `65536` | Argon2id memory cost, in KiB (64 MiB). |
| `PASSWORD_ARGON2_ITERATIONS`         | `3`     | Argon2id time cost (passes). |
| `PASSWORD_ARGON2_PARALLELISM`        | `2`     | Argon2id parallelism (lanes). |
| `PASSWORD_LOCKOUT_MAX_ATTEMPTS`      | `5`     | Failed logins before the account is temporarily locked. |
| `PASSWORD_LOCKOUT_DURATION_MINUTES`  | `15`    | Lockout duration. |

> **`ENCRYPTION_KEY` is required when using TOTP.** TOTP secrets are stored encrypted at
> rest (AES-GCM, key derived from `ENCRYPTION_KEY`). Pocket ID already requires this key
> (≥16 bytes) for other encrypted fields, so no new requirement in practice.

## Security model (summary)

- **Passwords are hashed with Argon2id**, never encrypted. Stored as PHC strings.
- **Reset / invite tokens** are random 32-char strings, stored only as SHA-256 hashes,
  single-use, short TTL (reset 15 min, invite 7 days), constant-time compared.
- **TOTP** is RFC 6238 (SHA-1, 6 digits, 30 s, ±1 step skew) — standard authenticator-app
  compatible. Secrets encrypted at rest. 10 single-use recovery codes (hashed) per user.
- **Account lockout** via per-user failed-attempt counter + `locked_until`.
- **Rate limiting** on login (5 / 10 s), TOTP (5 / 10 s) and reset-request (3 / 10 min).
- **No user enumeration**: login returns a generic error and runs a dummy Argon2 verify
  for unknown users; `reset-request` always returns success.
- **Audit logging** for `PASSWORD_SIGN_IN`, `MFA_SIGN_IN`, `PASSWORD_CHANGED`,
  `PASSWORD_SET`, `PASSWORD_RESET`, `ACCOUNT_LOCKED`, `TOTP_ENABLED`, `TOTP_DISABLED`.
- **OIDC is untouched**: password/TOTP login converges on the same `GenerateAccessToken`
  used by passkeys, so token signing (RS256/ES256/EdDSA), groups and custom claims are
  unchanged. JWTs are **not** PQC-signed.

### PQC / "quantum-secure"

Handled at the **transport** layer (hybrid X25519 + ML-KEM TLS terminated at the reverse
proxy, e.g. Traefik) — zero app changes. Argon2id is already quantum-adequate for storage.
Token signing stays on standard JOSE algorithms.

## Provisioning a user with a password

1. Create the user as usual (admin UI or API).
2. Either:
   - **Set an initial password**: `POST /api/password/admin/{userId}/set` `{ "password": "..." }`, or
   - **Send an invite**: `POST /api/password/admin/{userId}/invite` — emails a set-password link.
3. Self-service afterwards: change password in **Settings → Account**; forgot-password via
   the **Reset password** page (emails a reset link).

## API reference

| Method & path | Auth | Body | Notes |
|---|---|---|---|
| `POST /api/password/login` | public | `{identifier, password}` | `identifier` = username or email. Returns `{complete}` or `{mfaRequired}`. |
| `POST /api/password/login/totp` | challenge cookie | `{code}` | TOTP or recovery code. |
| `GET  /api/password/policy` | public | — | `{minLength}`. |
| `POST /api/password/reset-request` | public | `{email}` | Always 204. |
| `POST /api/password/reset` | public | `{token, newPassword}` | Reset / invite consume. |
| `POST /api/password/change` | user | `{currentPassword, newPassword}` | — |
| `POST /api/users/me/totp/enroll` | user | — | `{secret, uri}` for QR. |
| `POST /api/users/me/totp/confirm` | user | `{code}` | `{recoveryCodes}` (shown once). |
| `POST /api/users/me/totp/disable` | user | — | — |
| `POST /api/password/admin/{id}/set` | admin | `{password}` | — |
| `POST /api/password/admin/{id}/invite` | admin | — | — |
