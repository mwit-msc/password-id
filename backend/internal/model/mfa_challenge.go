package model

import datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"

// pocket-id-password fork: short-lived "password verified, second factor pending" state.
// Mirrors WebauthnSession: created after a successful password check, consumed once the
// TOTP (or recovery) code verifies, at which point the real access token is issued.
type MfaChallenge struct {
	Base
	ExpiresAt    datatype.DateTime
	AttemptCount int

	UserID string
	User   User
}
