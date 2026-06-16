# Feasibility Spike: Password Auth for Pocket ID

**Date:** 2026-06-16
**Base:** pocket-id `main` @ `212c574` (upstream releases up to v2.8.0)
**Goal:** Add username/password login alongside passkeys as a small, isolated, rebasable diff. Do not touch OIDC/crypto core.

---

## 1. Verdict

**Feasible and clean.** Pocket ID's auth architecture has a single token-issuance convergence point that both passkey and one-time-code flows already share. Password auth plugs in as a third flow that converges at the same point. No OIDC/JWT/crypto changes required. Existing subsystems (email, audit log, DB-backed settings, rate-limit, migrations, form UI) are all reusable as-is.

The base already does most of the supporting work:
- `golang.org/x/crypto` v0.51.0 is already a dependency → **Argon2id is free** (`golang.org/x/crypto/argon2`), no new dep.
- Email transport, templating, audit logging, DB-backed admin settings, per-IP rate limiting, secure-random token gen — all present and reusable.
- User model already has `Username` (unique, case-insensitive CITEXT on PG), `Email *string` (nullable), `EmailVerified bool`.

**Main gaps to build:** password hash storage, password verify→session flow, reset-token table+flow, account lockout (not present today), and the SvelteKit screens.

---

## 2. Architecture: the convergence point

Every successful login in Pocket ID ends at **one** function:

```
backend/internal/service/jwt_service.go
  GenerateAccessToken(user model.User, authenticationMethod string) (string, error)   // ~line 199
```

Then the controller sets the cookie:

```
backend/internal/utils/cookie/add_cookie.go
  AddAccessTokenCookie(c, maxAge, token)   // line 9 — sets __Host-access_token
```

Existing callers (the pattern to copy):
- **Passkey:** `service/webauthn_service.go` `VerifyLogin()` (~226–282) → `GenerateAccessToken(user, AuthenticationMethodPhishingResistant)` at ~269; cookie set in `controller/webauthn_controller.go` `verifyLoginHandler()` (~86–115).
- **Email code:** `service/one_time_access_service.go` `ExchangeOneTimeAccessToken()` (176–221) → `GenerateAccessToken(user, AuthenticationMethodOneTimePassword)` at ~200; cookie set in `controller/user_controller.go` `exchangeOneTimeAccessTokenHandler()` (510–528).

**Password auth = a third caller of the exact same two lines.** New auth-method constant (e.g. `AuthenticationMethodPassword = "pwd"`). This is why the diff stays small and OIDC stays untouched: downstream token signing, groups, and custom claims all flow through `GenerateAccessToken` unchanged.

---

## 3. Insertion points (file:line)

### Backend
| Concern | Location | Action |
|---|---|---|
| User model | `internal/model/user.go:14-32` | Add `PasswordHash *string` (nullable) |
| New token model | `internal/model/` (new `password_reset_token.go`) | Mirror `one_time_access_token.go` |
| Migrations | `resources/migrations/{postgres,sqlite}/` | New `2026…_password_auth.{up,down}.sql` ×2 dialects. Latest existing: `20260601154900_par` |
| Hashing util | `internal/utils/crypto/` (new `password.go`) | Argon2id hash + constant-time verify |
| Token gen | reuse `internal/utils/string_util.go` `GenerateRandomAlphanumericString()` | reset tokens (store **hashed**) |
| Password service | `internal/service/` (new `password_service.go`) | verify, set, change, reset; calls `jwtService.GenerateAccessToken` |
| Password controller | `internal/controller/` (new `password_controller.go`) | routes below, copy webauthn_controller rate-limit pattern |
| Route registration | `internal/bootstrap/router_bootstrap.go:110-147` | Register new controller |
| Service wiring (DI) | `internal/bootstrap/services_bootstrap.go` | Construct `passwordService` |
| Rate limit | `internal/middleware/rate_limit.go` `Add(limit, burst)` | reuse: 5/10s login, 3/10m reset-request |
| Admin setting | `internal/model/app_config.go:35-84` + `service/app_config_service.go` | Add `passwordAuthEnabled` (DB-backed, UI-editable) |
| Env policy | `internal/common/env_config.go:40-85` | Add `PASSWORD_MIN_LENGTH` etc. + validation |
| Email template | `internal/service/email_service_templates.go` + `resources/email-templates/password-reset_{html,text}.tmpl` | new `password-reset` template; send via `SendEmail[V]()` |
| Audit events | `internal/model/audit_log.go:29-39` | Add `PASSWORD_SIGN_IN`, `PASSWORD_CHANGED`, `PASSWORD_RESET`, `ACCOUNT_LOCKED` |

### Frontend (SvelteKit)
| Concern | Location | Action |
|---|---|---|
| Login page | `src/routes/login/+page.svelte` (passkey) + `login/alternative/email/+page.svelte` (pattern) | New `login/password/+page.svelte` using `SignInWrapper` + `FormInput` |
| API client | `src/lib/services/` (new `password-service.ts` extends `api-service.ts`) | login / change / reset calls |
| Account self-service | `src/routes/settings/account/+page.svelte` (next to Passkeys card ~164) | Add "Change password" card/modal |
| Admin config | `src/routes/settings/admin/application-configuration/` + `lib/types/application-configuration.type.ts` | Add `passwordAuthEnabled` toggle |
| i18n | `frontend/messages/*.json` (Paraglide) | Add keys to all locales |
| Forms/validation | `lib/utils/form-util.ts` `createForm()` + Zod | reuse existing pattern |

---

## 4. Proposed API surface

```
POST /api/password/login            {username, password}      → sets cookie, rate 5/10s
POST /api/password/change           {currentPassword, new}    → auth required
POST /api/password/reset-request    {email}                   → rate 3/10m, always 200 (no user enum)
POST /api/password/reset            {token, newPassword}      → rate 5/10s
GET  /api/password/policy           → min length etc. (for client-side hints)
```

Admin sets initial password / triggers invite via existing user-management endpoints (extend, don't replace).

---

## 5. Schema change (minimal)

```sql
-- users: one nullable column
ALTER TABLE users ADD COLUMN password_hash TEXT;   -- VARCHAR not needed; Argon2id encoded string

-- new table (mirrors one_time_access_tokens)
CREATE TABLE password_reset_tokens (
  id          <uuid/text> PRIMARY KEY,
  created_at  <ts>        NOT NULL,
  token_hash  TEXT        NOT NULL UNIQUE,   -- store HASH of token, never raw
  expires_at  <ts>        NOT NULL,
  user_id     <uuid/text> NOT NULL REFERENCES users ON DELETE CASCADE
);
CREATE INDEX ... ON password_reset_tokens(user_id);
CREATE INDEX ... ON password_reset_tokens(expires_at);
```

Lockout state: small `failed_login_attempts` table **or** counter columns on users (`failed_login_count int`, `locked_until timestamp`). Recommend separate column approach — keeps it on the user row, simple to read in the login path.

---

## 6. Security checklist (maps to spec §"non-negotiable")

| Requirement | Plan |
|---|---|
| Argon2id, never encrypt | `golang.org/x/crypto/argon2.IDKey`, params m=64MB t=3 p=2 (tunable via env), encoded PHC string in `password_hash` |
| Rate limiting | Reuse `middleware/rate_limit.go` on login + reset routes |
| Account lockout | **NEW** — not in base today. Counter + `locked_until`; reset on success; audit `ACCOUNT_LOCKED` |
| Reset tokens | Single-use, short TTL (e.g. 15m), **hashed at rest**, constant-time compare, deleted on use (copy one-time-access locking pattern w/ `clause.Locking{Strength:"UPDATE"}`) |
| Email verification | Reuse `EmailVerified` field + existing email transport |
| Audit logging | Reuse `auditLogService.Create()` with new event constants |
| No user enumeration | reset-request always returns 200; login returns generic error |
| Constant-time | Argon2 verify is constant-time; use `crypto/subtle` for token compare |
| OWASP ASVS | covered by above; password policy configurable |

**PQC (spec §transport):** zero app work. Hybrid X25519+ML-KEM TLS terminates at Traefik. Argon2id already quantum-adequate. JWT signing stays standard (RS256/ES256/EdDSA) — untouched.

---

## 7. Rebase strategy (keep diff cheap)

- **Additive-only files** where possible: new `password_service.go`, `password_controller.go`, `password.go`, new migrations, new Svelte routes. These never conflict on rebase.
- **Touch-point files** (small, surgical): `user.go` (+1 field), `router_bootstrap.go` (+1 register), `services_bootstrap.go` (+1 construct), `app_config.go` (+1 setting), `account/+page.svelte` (+1 card). Keep each edit a tight, well-commented block tagged `// pocket-id-password fork:` so rebases are mechanical.
- **Feature flag:** `passwordAuthEnabled` (DB setting) gates routes + UI. Off by default = behaves like vanilla upstream.
- Track upstream as a remote; rebase fork branch onto each tagged release. Document in `REBASE.md`.

---

## 8. Effort estimate

Spec ballpark was **2–4 weeks** for one experienced Go+SvelteKit dev. Spike confirms the **low end is realistic** because the convergence point and all supporting subsystems already exist.

| Phase | Scope | Est. |
|---|---|---|
| 1. Core credential | migration, model, Argon2id util, password_service, login route+controller, convergence, audit | 3–4 days |
| 2. Self-service | change-password (backend+UI), policy enforcement, account settings card | 2 days |
| 3. Reset flow | reset-token table, request/consume, email template, UI screens, hashing+TTL+single-use | 2–3 days |
| 4. Hardening | account lockout, rate-limit wiring, no-enumeration, security tests | 2–3 days |
| 5. Admin config | `passwordAuthEnabled` setting + admin UI toggle, feature-flag gating | 1 day |
| 6. Tests + review | table-driven service tests (reuse `NewDatabaseForTest`), security review of credential layer | 2–3 days |
| 7. Packaging | Docker image, env docs, REBASE.md | 1 day |

**Total: ~13–18 working days (2.5–3.5 weeks).** Phase 2 MFA/TOTP from spec §3 deferred (nice-to-have).

---

## 9. Open decisions (defaults chosen, flag if wrong)

1. **Lockout storage:** counter columns on `users` (chosen) vs separate table. → columns, simpler.
2. **Login identifier:** username OR email both accepted (chosen) vs username-only.
3. **Reset token TTL:** 15 min (chosen).
4. **Argon2id params:** m=64MB, t=3, p=2 (OWASP baseline, chosen); env-tunable.
5. **Default flag state:** `passwordAuthEnabled=false` on fresh install (chosen) — safest, opt-in.
6. **Breach check (HIBP k-anon):** deferred — it's an outbound call, borderline vs "no new infra". Make it an optional, off-by-default toggle if wanted.
