# Password + TOTP Auth — Progress TODO

Durable progress tracker for the password/TOTP feature on this pocket-id fork.
Branch: `password-auth`. All gates green; all phases complete.

## Phases

- [x] **F — Foundation** — 8 migrations (Postgres + SQLite), model structs
  (`user.go` cols, `password_reset_token`, `mfa_challenge`, `totp_recovery_code`),
  audit events, Argon2id + RFC-6238 TOTP + token-hash crypto utils, crypto tests
  (incl. RFC 6238 vectors). _commit 1fcae41_
- [x] **B — Backend features** — `password_service` (login, lockout, change, reset,
  invite, MFA), `totp_service` (enroll, confirm, disable, verify, recovery codes),
  `breach_service` (HIBP k-anonymity), controllers, DTOs, error types, email templates.
  _commits 91289b1, d44bec5_
- [x] **I — Integration** — bootstrap wiring (services + routes), 3 DB-backed config
  flags (default OFF = vanilla upstream), env policy vars, MFA-challenge cookie,
  app-config DTO parity. _commit d44bec5_
- [x] **UI — Frontend** — login/password + TOTP pages, reset-password + set-password,
  account password & two-factor cards (QR enroll + one-time recovery codes), admin
  auth-config toggles, admin set-password/invite, `password-service.ts` + `totp-service.ts`,
  i18n keys. `svelte-check` 0/0. _commit 6266b89_
- [x] **V — Security audit** — adversarial review; fixed: C1 MFA bearer→hashed token,
  C2 recheck disabled/locked in VerifyMfa, H2 TOTP replay (step tracking), H3 cookie
  prefix (`__Secure-`), M1 lockout enumeration oracle, M2 dummy-hash from live params,
  L3 enroll rate-limit. _commit b05dc4e_
- [x] **Q — Tests + docs** — backend unit/service tests (login/lockout/change/reset/MFA/
  recovery/replay/forged-token), Playwright E2E spec, CONFIG + REBASE docs.
  _commits 71337f2, 636b954, 8a65aca_
- [x] **Final — Verification gate** — whole-repo build/test/lint green (see below).

## Verification (last run)

- [x] Backend `go build -tags=exclude_frontend ./...` — OK
- [x] Backend `go test -tags=exclude_frontend ./internal/...` — 14 packages pass, 0 fail
- [x] Backend `golangci-lint run --build-tags=exclude_frontend ./...` — 0 issues
- [x] Frontend `pnpm check` (svelte-check) — 0 errors, 0 warnings
- [x] Frontend `pnpm build` — succeeds
- [x] All 9 commits free of Co-Authored-By trailer
- [x] Zero new backend dependencies

## Known follow-ups (environmental, not code gaps)

- [ ] Run `password-auth.spec.ts` against the live e2e docker stack (compiles + lists clean;
      selectors may need a tweak on first real run).
- [ ] Build the Docker image (changes are additive and compile; Dockerfile path unchanged).
- [ ] `pnpm lint` is blocked by a **pre-existing** missing `@eslint/js` dev-dep in upstream
      `package.json` (fork did not touch it) — unrelated to this feature.
