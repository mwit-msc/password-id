package model

import datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"

// pocket-id-password fork: single-use TOTP recovery codes.
// Only the SHA-256 hash of each code is stored; UsedAt marks consumption.
type TotpRecoveryCode struct {
	Base
	CodeHash string `gorm:"column:code_hash"`
	UsedAt   *datatype.DateTime

	UserID string
	User   User
}
