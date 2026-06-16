# Rebasing the password-auth fork onto upstream Pocket ID

This fork keeps the password + TOTP feature as a small, well-isolated additive layer so
rebasing onto new upstream releases stays cheap. Most of the code lives in **new files**
that never conflict. A handful of **shared upstream files** carry small, tagged edits.

## Strategy

- The fork branch is `password-auth`.
- Add upstream as a remote and rebase the fork branch onto each tagged release:
  ```sh
  git remote add upstream https://github.com/pocket-id/pocket-id.git
  git fetch upstream --tags
  git rebase v<next-release>        # onto the new tag
  ```
- Every edit to an upstream file is marked with the comment `pocket-id-password fork:` so
  conflicts are easy to find and re-apply. `git grep "pocket-id-password fork"` lists them.

## New files (no conflicts expected)

Backend:
- `internal/utils/crypto/password.go`, `totp.go`, `tokenhash.go` (+ `password_totp_test.go`)
- `internal/model/password_reset_token.go`, `mfa_challenge.go`, `totp_recovery_code.go`
- `internal/service/password_service.go`, `totp_service.go`, `breach_service.go` (+ tests)
- `internal/controller/password_controller.go`, `totp_controller.go`
- `internal/dto/password_dto.go`
- `internal/common/errors_password.go`
- `resources/migrations/{postgres,sqlite}/20260616000000_password_auth.{up,down}.sql`
- `resources/email-templates/password-reset_*.tmpl`, `password-invite_*.tmpl`

Frontend (new routes/services/forms) — see `git diff --stat` for the current list.

## Shared upstream files with tagged edits (re-apply on conflict)

Backend:
| File | Edit |
|------|------|
| `internal/model/user.go` | 5 credential columns on `User`. |
| `internal/model/audit_log.go` | new audit event constants. |
| `internal/model/app_config.go` | `passwordAuthEnabled`, `totpEnabled`, `breachCheckEnabled`. |
| `internal/service/app_config_service.go` | defaults for the 3 settings. |
| `internal/dto/app_config_dto.go` | the 3 settings in the update DTO. |
| `internal/service/email_service_templates.go` | register reset + invite templates. |
| `internal/service/jwt_service.go` | `AuthenticationMethodPassword = "pwd"` constant only. |
| `internal/common/env_config.go` | password policy env vars + defaults. |
| `internal/utils/cookie/cookie_names.go`, `add_cookie.go` | MFA-challenge cookie. |
| `internal/bootstrap/services_bootstrap.go` | construct 3 services. |
| `internal/bootstrap/router_bootstrap.go` | register 2 controllers. |

Frontend:
| File | Edit |
|------|------|
| `src/routes/login/alternative/+page.svelte` | "Sign in with password" entry. |
| `src/routes/settings/account/+page.svelte` | Password + TOTP cards. |
| `src/routes/settings/admin/application-configuration/**` | toggles for the 3 settings. |
| `src/lib/types/application-configuration.type.ts` | the 3 settings. |
| `src/routes/settings/admin/users/**` | invite / set-password actions. |
| `frontend/messages/*.json` | new i18n keys. |

## After every rebase — verification gate

```sh
# Backend
cd backend
go build -tags=exclude_frontend ./...
go test  -tags=exclude_frontend ./...
golangci-lint run --build-tags=exclude_frontend

# Frontend
cd ../frontend
pnpm install
pnpm --filter pocket-id-frontend check
pnpm --filter pocket-id-frontend lint
```

If upstream adds a new field to `AppConfig`, the parity test
`TestAppConfigStructMatchesUpdateDto` will fail until the field is mirrored in
`AppConfigUpdateDto` — that's upstream's own invariant, unrelated to this fork.

## Watch-items on upstream changes

- **Auth convergence point** — if upstream changes `JwtService.GenerateAccessToken` or the
  access-token cookie helper, re-verify the password/TOTP login still issues a valid
  session (the whole fork hangs off that single function).
- **Migrations** — if upstream adds migrations after `20260616000000`, there's no conflict
  (timestamps order them); just confirm `m.Up()` runs clean.
- **App config** — new upstream settings don't conflict, but keep the 3 fork settings in
  both `AppConfig` and `AppConfigUpdateDto`.
