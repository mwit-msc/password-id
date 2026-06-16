package common

// pocket-id-password fork: error types for the password + TOTP credential layer.

import "net/http"

// PasswordAuthDisabledError is returned when password auth is attempted while disabled.
type PasswordAuthDisabledError struct{}

func (e PasswordAuthDisabledError) Error() string       { return "password authentication is disabled" }
func (e PasswordAuthDisabledError) HttpStatusCode() int { return http.StatusForbidden }

// InvalidCredentialsError is the generic login failure. The message is intentionally
// vague to avoid leaking whether the username or the password was wrong (user enumeration).
type InvalidCredentialsError struct{}

func (e InvalidCredentialsError) Error() string       { return "invalid credentials" }
func (e InvalidCredentialsError) HttpStatusCode() int { return http.StatusUnauthorized }

// AccountLockedError is returned when too many failed attempts have locked the account.
type AccountLockedError struct{}

func (e AccountLockedError) Error() string {
	return "account temporarily locked due to too many failed login attempts"
}
func (e AccountLockedError) HttpStatusCode() int { return http.StatusTooManyRequests }

// PasswordPolicyError is returned when a new password does not meet the configured policy.
type PasswordPolicyError struct {
	Reason string
}

func (e PasswordPolicyError) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	return "password does not meet the required policy"
}
func (e PasswordPolicyError) HttpStatusCode() int { return http.StatusBadRequest }

// MfaRequiredError signals the client that a second factor is needed to complete login.
type MfaRequiredError struct{}

func (e MfaRequiredError) Error() string       { return "second factor required" }
func (e MfaRequiredError) HttpStatusCode() int { return http.StatusUnauthorized }

// MfaInvalidError is returned for a wrong/expired TOTP or recovery code.
type MfaInvalidError struct{}

func (e MfaInvalidError) Error() string       { return "invalid or expired second-factor code" }
func (e MfaInvalidError) HttpStatusCode() int { return http.StatusUnauthorized }

// TotpNotEnabledError is returned when a TOTP operation is attempted but TOTP is not set up.
type TotpNotEnabledError struct{}

func (e TotpNotEnabledError) Error() string       { return "TOTP is not enabled for this user" }
func (e TotpNotEnabledError) HttpStatusCode() int { return http.StatusBadRequest }

// TotpAlreadyEnabledError is returned when enrolling TOTP that is already active.
type TotpAlreadyEnabledError struct{}

func (e TotpAlreadyEnabledError) Error() string       { return "TOTP is already enabled" }
func (e TotpAlreadyEnabledError) HttpStatusCode() int { return http.StatusBadRequest }

// PasswordNotSetError is returned when changing a password for a user that has none.
type PasswordNotSetError struct{}

func (e PasswordNotSetError) Error() string       { return "no password is set for this user" }
func (e PasswordNotSetError) HttpStatusCode() int { return http.StatusBadRequest }
