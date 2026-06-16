package dto

// pocket-id-password fork: request/response DTOs for the password + TOTP credential layer.

type PasswordLoginDto struct {
	// Identifier is the username or email.
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type PasswordMfaDto struct {
	Code string `json:"code" binding:"required"`
}

type PasswordLoginResponseDto struct {
	// Complete is true when login is fully done and the access token cookie was set.
	Complete bool `json:"complete"`
	// MfaRequired is true when a second factor is needed; the client should prompt for a code.
	MfaRequired bool     `json:"mfaRequired"`
	User        *UserDto `json:"user,omitempty"`
}

type ChangePasswordDto struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword" binding:"required"`
}

type PasswordResetRequestDto struct {
	Email string `json:"email" binding:"required,email"`
}

type PasswordResetDto struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"newPassword" binding:"required"`
}

type AdminSetPasswordDto struct {
	Password string `json:"password" binding:"required"`
}

type PasswordPolicyDto struct {
	MinLength int `json:"minLength"`
}

type TotpEnrollResponseDto struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type TotpConfirmDto struct {
	Code string `json:"code" binding:"required"`
}

type TotpConfirmResponseDto struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

type TotpDisableDto struct {
	// Code is a current TOTP code or a recovery code, used to authorize disabling.
	Code string `json:"code"`
}
