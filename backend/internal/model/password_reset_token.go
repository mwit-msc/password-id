package model

import datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"

// pocket-id-password fork: token for password reset and invite-to-set-password flows.
// The raw token is only ever emailed to the user; TokenHash stores its SHA-256 hash.

type PasswordResetTokenPurpose string

const (
	PasswordResetPurposeReset  PasswordResetTokenPurpose = "reset"
	PasswordResetPurposeInvite PasswordResetTokenPurpose = "invite"
)

type PasswordResetToken struct {
	Base
	TokenHash string `gorm:"column:token_hash"`
	Purpose   PasswordResetTokenPurpose
	ExpiresAt datatype.DateTime

	UserID string
	User   User
}
