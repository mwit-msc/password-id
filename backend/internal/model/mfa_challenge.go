package model

import datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"

// pocket-id-password fork: short-lived "password verified, second factor pending" state.
// Mirrors WebauthnSession: created after a successful password check, consumed once the
// TOTP (or recovery) code verifies, at which point the real access token is issued.
type MfaChallenge struct {
	Base
	// TokenHash is the SHA-256 of the random challenge token handed to the client in a
	// cookie. The token (not the primary key) is the bearer secret, compared by hash.
	TokenHash    string `gorm:"column:token_hash"`
	ExpiresAt    datatype.DateTime
	AttemptCount int

	UserID string
	User   User
}
