# Implementation Plan: Password + TOTP Auth for Pocket ID

**Base:** pocket-id `main` @ `212c574` · **Companion:** [PASSWORD_AUTH_FINDINGS.md](./PASSWORD_AUTH_FINDINGS.md)
**Decisions locked:** login id = username **or** email · breach check (HIBP) **included, off by default** · **TOTP second factor included now** · primary DB = Postgres (SQLite kept working).

---

## 0. Design decisions (resolved)

| # | Decision | Choice | Rationale |
|---|---|---|---|
| 1 | Login identifier | username OR email | Matches Logto UX. Lookup tries username then email. |
| 2 | MFA-pending state | new temp `mfa_challenge` table (mirrors `WebauthnSession`) | **No edits to jwt_service.go** → OIDC/crypto untouched, rebase-safe. |
| 3 | TOTP impl | hand-rolled RFC-6238 in stdlib (`crypto/hmac`+`crypto/sha1`+`encoding/base32`) | **Zero new backend deps.** ~40 LOC, fully testable against RFC test vectors. |
| 4 | TOTP QR | built backend as `otpauth://totp/...` URI, rendered by frontend `qrcode` (already a dep) | No backend QR dep. |
| 5 | Recovery codes | N single-use codes, hashed at rest; reuse `GenerateRandomUnambiguousString` | Satisfies spec "preserve one-time-code recovery". |
| 6 | Reset/invite tokens | new `password_reset_tokens` table; tokens **hashed at rest**, single-use, short TTL | Mirrors existing `EmailVerificationToken`. |
| 7 | Lockout state | counter columns on `users` (`failed_login_count`, `locked_until`) | Read in-line on login path; no extra table/join. |
| 8 | Admin initial password | optional `initialPassword` on `UserCreateDto` + admin-only field on update | Reuses existing create/update plumbing. |
| 9 | Invite flow | admin sends "set password" email = `password_reset_token` w/ longer TTL → `/set-password` | Reuses reset machinery + email transport. |
| 10 | Lockout vs reset | successful reset clears lockout | Recovery path must not be lockout-blocked. |
| 11 | Feature flags (DB-backed) | `passwordAuthEnabled`, `totpEnabled`, `breachCheckEnabled` — all **default false** | Fresh install = vanilla upstream. |
| 12 | Breach check | HIBP k-anonymity (range API, SHA-1 prefix), off by default, fail-open | Only outbound call; toggleable; no infra. |

**Argon2id params:** `m=64MB, t=3, p=2, keyLen=32, saltLen=16`, env-tunable (`PASSWORD_ARGON2_*`). Stored as PHC-encoded string in `users.password_hash`.

---

## 1. Auth flow (password + TOTP)

```
POST /api/password/login {identifier, password}
   ├─ lockout check (locked_until > now → 423 + audit ACCOUNT_LOCKED)
   ├─ lookup user by username OR email
   ├─ Argon2id verify (constant-time; dummy-hash compare if user/hash absent → no enumeration, no timing leak)
   ├─ fail → failed_login_count++; maybe set locked_until; generic 401
   └─ success → reset failed_login_count
        ├─ user has TOTP?  NO  → GenerateAccessToken(user, "pwd") → set cookie → 200 {complete}
        └─                 YES → create mfa_challenge (5 min, hashed id in cookie) → 200 {mfaRequired:true}

POST /api/password/login/totp {code}            (rate 5/10s; reads mfa_challenge cookie)
   ├─ validate challenge (exists, unexpired, single-use) → else 401
   ├─ verify TOTP code (±1 step skew) OR recovery code (single-use, mark consumed)
   ├─ fail → challenge attempt++ (cap 5 → invalidate); generic 401
   └─ success → consume challenge → GenerateAccessToken(user, "pwd+otp") → set cookie → 200 {complete}
```

`GenerateAccessToken` + `AddAccessTokenCookie` are the **only** convergence points — identical to passkey/email-code flows. `amr` claim already supported.

---

## 2. Schema (4 migrations × 2 dialects = 8 files)

`resources/migrations/{postgres,sqlite}/2026XXXX_password_auth.{up,down}.sql`

```sql
-- users: add columns (nullable / defaulted)
ALTER TABLE users ADD COLUMN password_hash       TEXT;
ALTER TABLE users ADD COLUMN failed_login_count  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until         <ts> NULL;
ALTER TABLE users ADD COLUMN totp_secret          TEXT NULL;     -- encrypted via existing EncryptedString type
ALTER TABLE users ADD COLUMN totp_enabled         BOOLEAN NOT NULL DEFAULT false;

-- password reset / invite tokens (mirror one_time_access_tokens)
CREATE TABLE password_reset_tokens (
  id <pk>, created_at <ts> NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,        -- SHA-256 of raw token; raw only ever emailed
  purpose    TEXT NOT NULL,               -- 'reset' | 'invite'
  expires_at <ts> NOT NULL,
  user_id <fk> NOT NULL REFERENCES users ON DELETE CASCADE );

-- short-lived MFA-pending challenge (mirror webauthn_sessions)
CREATE TABLE mfa_challenges (
  id <pk>, created_at <ts> NOT NULL,
  expires_at <ts> NOT NULL, attempt_count INTEGER NOT NULL DEFAULT 0,
  user_id <fk> NOT NULL REFERENCES users ON DELETE CASCADE );

-- TOTP recovery codes (single-use)
CREATE TABLE totp_recovery_codes (
  id <pk>, created_at <ts> NOT NULL,
  code_hash TEXT NOT NULL, used_at <ts> NULL,
  user_id <fk> NOT NULL REFERENCES users ON DELETE CASCADE );
```

> `totp_secret` stored using the existing `EncryptedString` type (`model/types/encrypted_string.go`, AES-GCM + HKDF) so secrets are encrypted at rest with `ENCRYPTION_KEY`. (Reversible-encryption is correct here — TOTP needs the secret back; this does NOT violate the "passwords are hashed" rule, which is about passwords.)

Postgres `<ts>`=`TIMESTAMPTZ`, `<pk>`=`UUID PRIMARY KEY`, `<fk>`=`UUID`. SQLite `<ts>`=`DATETIME`, `<pk>`=`TEXT PRIMARY KEY`, `<fk>`=`TEXT`. SQLite wraps in `PRAGMA foreign_keys=OFF; BEGIN; … COMMIT; PRAGMA foreign_keys=ON;`.

---

## 3. Backend work items (file-level)

**Foundation (shared files — built first, serially):**
- `model/user.go` +5 fields · `model/audit_log.go` +events (`PASSWORD_SIGN_IN`,`PASSWORD_CHANGED`,`PASSWORD_RESET`,`PASSWORD_SET`,`ACCOUNT_LOCKED`,`TOTP_ENABLED`,`TOTP_DISABLED`,`MFA_SIGN_IN`)
- New models: `password_reset_token.go`, `mfa_challenge.go`, `totp_recovery_code.go`
- `utils/crypto/password.go` (Argon2id hash/verify + dummy-compare), `utils/crypto/totp.go` (RFC-6238), `utils/crypto/tokenhash.go` (SHA-256 + `crypto/subtle` compare)
- `service/jwt_service.go`: add constant `AuthenticationMethodPassword="pwd"` (+ `"pwd+otp"` via amr). **No logic change.**
- 8 migration files.

**Feature services/controllers (new files — parallelizable in worktrees):**
- A. `service/password_service.go` (verify/set/change) + `controller/password_controller.go` (login, totp, change)
- B. reset/invite: extend password_service (`RequestReset`,`ConsumeReset`,`Invite`) + routes + email templates `password-reset_{html,text}.tmpl`, `password-invite_{html,text}.tmpl`
- C. `service/totp_service.go` (enroll/confirm/disable/verify/recovery) + `controller/totp_controller.go`
- D. lockout logic (in password_service login path) + `service/breach_service.go` (HIBP, fail-open, off by default)
- E. provisioning: extend `dto/user_dto.go` (`+InitialPassword`), `user_service.go` create/update paths, admin reset endpoint

**Integration (shared files — serial, last):**
- `bootstrap/services_bootstrap.go` (+construct passwordService, totpService, breachService)
- `bootstrap/router_bootstrap.go` (+register 2 controllers)
- `model/app_config.go` + `service/app_config_service.go` (+3 settings)
- `common/env_config.go` (+Argon2/policy/lockout env vars + validation)
- A background job to purge expired `password_reset_tokens`/`mfa_challenges` (mirror existing cleanup jobs in `internal/job`).

**API surface:**
```
POST /api/password/login                 5/10s   {identifier,password}
POST /api/password/login/totp            5/10s   {code}
POST /api/password/change                auth    {currentPassword,newPassword}
POST /api/password/reset-request         3/10m   {email}            → always 200
POST /api/password/reset                 5/10s   {token,newPassword}
GET  /api/password/policy                        → {minLength,...}
POST /api/users/me/totp/enroll           auth    → {secret,uri}
POST /api/users/me/totp/confirm          auth    {code} → {recoveryCodes[]}
POST /api/users/me/totp/disable          auth    {code|password}
POST /api/users/{id}/set-password        admin   {password}
POST /api/users/{id}/send-invite         admin   → emails set-password link
```

---

## 4. Frontend work items

shadcn-svelte + Tailwind + Paraglide i18n + Zod `createForm()`. Reuse `SignInWrapper`, `FormInput`, `Card`, `Button`.

- `lib/services/password-service.ts`, `lib/services/totp-service.ts` (extend `api-service.ts`)
- `routes/login/password/+page.svelte` (identifier+password) · `routes/login/password/totp/+page.svelte` (code / "use recovery code")
- `routes/login/alternative/+page.svelte` — add "Sign in with password" entry (gated on `passwordAuthEnabled`)
- `routes/login/+page.svelte` — optional "use password instead" link
- `routes/reset-password/+page.svelte` (request) · `routes/set-password/+page.svelte` (token consume; reset + invite)
- `routes/settings/account/+page.svelte` — add "Password" card (change) + "Two-factor (TOTP)" card (enroll QR via `qrcode`, show recovery codes, disable)
- `routes/settings/admin/application-configuration/` — toggles for the 3 settings + `application-configuration.type.ts`
- `routes/settings/admin/users/user-form.svelte` — optional initial-password field + "send invite" action
- `messages/*.json` (18+ locales) — new keys (English authoritative; others can be English-fallback initially, flagged for crowdin)

---

## 5. Test + verification plan

- **Backend unit** (`go test -tags=exclude_frontend ./...`, reuse `NewDatabaseForTest`): Argon2 hash/verify, TOTP against **RFC-6238 test vectors**, token hashing constant-time, login (success/fail/lockout/unlock), reset (single-use/expiry/no-enum), MFA challenge lifecycle, recovery-code single-use, policy enforcement, breach-check fail-open.
- **E2E** (Playwright in `tests/specs/`): full password login, password+TOTP login, reset round-trip, change password, admin invite, feature-flag off → routes 404/hidden.
- **Lint:** `golangci-lint run --build-tags=exclude_frontend` (gosec must pass) · frontend `pnpm --filter pocket-id-frontend lint && check`.
- **Security review** (adversarial): user enumeration (timing + responses), lockout bypass, reset-token reuse/leak, TOTP replay/skew window, rate-limit coverage, Argon2 params, constant-time compares, cookie flags, no secrets in logs/audit. Map to OWASP ASVS V2 (auth) + V3 (session).

---

## 6. Multi-agent execution design

Goal: maximize parallel wall-clock while protecting the **shared-file** seams (`user.go`, `audit_log.go`, the two `bootstrap/*.go`, `app_config*.go`, `messages/*.json`) that cause merge conflicts. Strategy: **serial foundation → parallel features in git worktrees → serial integration → parallel quality → adversarial verify.** Opus on security-critical + integration + review; Sonnet on mechanical/UI/tests. **No Haiku.**

```
Phase F · FOUNDATION  (1 agent, Opus, serial — owns all shared-schema files)
  migrations ×8, model fields/events, crypto utils (argon2/totp/tokenhash), auth-method const
  → gate: `go build` + crypto unit tests (RFC vectors) green before fan-out

Phase B · BACKEND FEATURES  (parallel, worktree isolation — new files only)
  B1 Opus    password_service + password_controller + login/change + LOCKOUT      (security-critical)
  B2 Opus    reset/invite service + email templates + token consume               (security-critical)
  B3 Opus    totp_service + totp_controller + recovery codes + mfa_challenge       (security-critical)
  B4 Sonnet  breach_service (HIBP, off-default, fail-open)                          (mechanical)
  B5 Sonnet  provisioning: user DTO/create/update + admin set-password/invite      (follows patterns)

Phase I · INTEGRATION  (1 agent, Opus, serial — merges worktrees, owns shared files)
  services_bootstrap, router_bootstrap, app_config (+settings), env_config, cleanup job
  resolve any overlap from B1–B5 · → gate: full backend build + `go test ./...` green

Phase UI · FRONTEND  (parallel — mostly separate route files)
  U1 Opus    login/password + login/password/totp pages (auth state flow)          (stateful, careful)
  U2 Sonnet  reset-password + set-password pages                                    (forms)
  U3 Sonnet  account settings: password card + TOTP card (QR + recovery)           (UI)
  U4 Sonnet  admin config toggles + user-form invite/initial-password              (UI)
  U5 Sonnet  password-service.ts + totp-service.ts + i18n keys (owns messages/*)    (single owner = no conflict)
  → gate: `pnpm check` + `lint` green

Phase Q · QUALITY  (parallel)
  Q1 Sonnet  backend unit tests (all services)
  Q2 Sonnet  Playwright E2E specs
  Q3 Opus    docs: CONFIG.md (env + admin settings) + REBASE.md (upstream rebase runbook)

Phase V · VERIFY  (parallel adversarial panel, Opus, high effort — independent skeptics)
  V1 enumeration/timing   V2 lockout+rate-limit bypass   V3 token/TOTP replay+reuse
  V4 Argon2/crypto params + constant-time + cookie flags + secret leakage
  each tries to REFUTE that a control holds; majority-refute → finding → back to owning phase
  → final: OWASP ASVS V2/V3 checklist signed off
```

**Conflict control:** Phases F and I are the only writers of shared files and run **serially with one agent each** — eliminates the merge hazard. B1–B5 and U1–U5 touch disjoint new files, run concurrently in worktrees. U5 is sole owner of `messages/*.json` to avoid i18n conflicts.

**Why this shape:** security-critical credential code (login, reset, TOTP, lockout) gets Opus + an adversarial verify pass; high-volume mechanical work (breach util, UI forms, tests) gets Sonnet to keep cost/time down. Foundation and integration are the dependency bottlenecks, so they're isolated and gated rather than parallelized.

> When greenlit, this maps directly onto a `Workflow` run: Phase F as a single gated agent, B/U/Q/V as `parallel()`/`pipeline()` stages with `isolation:'worktree'` on B and U, and V as a refute-panel over each security control. Estimated **6 orchestrated phases**.

---

## 7. Revised effort

| | Solo (1 dev) | Orchestrated wall-clock |
|---|---|---|
| Core password (login/change/lockout) | 4d | — |
| Reset + invite | 3d | — |
| TOTP + recovery | 4d | — |
| Breach check | 0.5d | — |
| Provisioning | 1.5d | — |
| Frontend (all screens) | 4d | — |
| Tests + E2E | 3d | — |
| Security review + docs | 3d | — |
| **Total** | **~23 working days (~4.5 wk)** | parallel phases compress build to a fraction; serial gates (F, I, V) + review dominate |

TOTP-now + breach + invite added ~5d over the password-only estimate in the findings doc. Orchestration cuts *wall-clock* sharply but F→I→V remain serial dependency gates.

---

## 8. Risks / watch-items

- **Rebase seams:** every shared-file edit tagged `// pocket-id-password fork:` for mechanical conflict resolution. Keep B/U new-file-only.
- **TOTP correctness:** validate against RFC-6238 vectors in CI before trusting it (non-negotiable gate in Phase F).
- **No enumeration:** login + reset-request must be constant-shape regardless of user existence (dummy Argon2 verify; reset-request always 200). Verified adversarially in Phase V.
- **EncryptedString for totp_secret** depends on `ENCRYPTION_KEY` being set — document as required when `totpEnabled`.
- **gosec** in `golangci-lint` will scrutinize the crypto — write it to pass (no `math/rand`, no weak compares).
- **New dep audit:** plan adds **zero** backend deps (TOTP hand-rolled, QR on frontend). Keep it that way.
