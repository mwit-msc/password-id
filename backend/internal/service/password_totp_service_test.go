package service

// pocket-id-password fork: unit tests for the password + TOTP credential layer.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/utils/crypto"
	"gorm.io/gorm"
)

func strPtr(s string) *string { return &s }

func setupPasswordTest(t *testing.T, passwordEnabled bool) (*PasswordService, *TotpService, *gorm.DB, model.User) {
	t.Helper()

	enabled := "false"
	if passwordEnabled {
		enabled = "true"
	}
	mockConfig := NewTestAppConfigService(&model.AppConfig{
		SessionDuration:     model.AppConfigVariable{Value: "60"},
		AppName:             model.AppConfigVariable{Value: "Pocket ID"},
		PasswordAuthEnabled: model.AppConfigVariable{Value: enabled},
		TotpEnabled:         model.AppConfigVariable{Value: "true"},
		BreachCheckEnabled:  model.AppConfigVariable{Value: "false"},
	})

	jwtService, db, _ := setupJwtService(t, mockConfig)
	geo := NewGeoLiteService(nil)
	audit := NewAuditLogService(db, mockConfig, nil, geo)
	totp := NewTotpService(db, mockConfig, audit)
	breach := NewBreachService()
	pw := NewPasswordService(db, jwtService, audit, nil, mockConfig, totp, breach)

	user := model.User{
		Base:     model.Base{ID: "u1"},
		Username: "alice",
		Email:    strPtr("alice@example.com"),
	}
	require.NoError(t, db.Create(&user).Error)

	return pw, totp, db, user
}

func TestPasswordLoginSuccessAndDisabled(t *testing.T) {
	t.Run("disabled returns error", func(t *testing.T) {
		pw, _, _, _ := setupPasswordTest(t, false)
		ctx := t.Context()
		_, err := pw.Login(ctx, "alice", "whatever", "", "")
		require.ErrorIs(t, err, &common.PasswordAuthDisabledError{})
	})

	t.Run("set then login by username and by email", func(t *testing.T) {
		pw, _, _, _ := setupPasswordTest(t, true)
		ctx := t.Context()
		require.NoError(t, pw.AdminSetPassword(ctx, "u1", "correct horse battery", "", ""))

		res, err := pw.Login(ctx, "alice", "correct horse battery", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, res.AccessToken)
		require.Empty(t, res.MfaChallenge)

		res, err = pw.Login(ctx, "alice@example.com", "correct horse battery", "", "")
		require.NoError(t, err)
		require.NotEmpty(t, res.AccessToken)
	})
}

func TestPasswordLoginFailuresAndLockout(t *testing.T) {
	ctx := t.Context()
	pw, _, db, _ := setupPasswordTest(t, true)
	require.NoError(t, pw.AdminSetPassword(ctx, "u1", "correct horse battery", "", ""))

	// Unknown user => invalid credentials (not "not found").
	_, err := pw.Login(ctx, "nobody", "x", "", "")
	require.ErrorIs(t, err, &common.InvalidCredentialsError{})

	// Five wrong attempts (default max) should lock the account.
	for i := 0; i < 5; i++ {
		_, err = pw.Login(ctx, "alice", "wrong", "", "")
		require.ErrorIs(t, err, &common.InvalidCredentialsError{})
	}

	// Now even the correct password is rejected — with the SAME generic error (lockout is
	// enforced but not advertised, to avoid an enumeration oracle).
	_, err = pw.Login(ctx, "alice", "correct horse battery", "", "")
	require.ErrorIs(t, err, &common.InvalidCredentialsError{})

	// Sanity: lockout was persisted.
	var u model.User
	require.NoError(t, db.Where("id = ?", "u1").First(&u).Error)
	require.NotNil(t, u.LockedUntil)
}

func TestPasswordChange(t *testing.T) {
	ctx := t.Context()
	pw, _, _, _ := setupPasswordTest(t, true)
	require.NoError(t, pw.AdminSetPassword(ctx, "u1", "first password", "", ""))

	// Wrong current password is rejected.
	err := pw.ChangePassword(ctx, "u1", "nope", "second password", "", "")
	require.ErrorIs(t, err, &common.InvalidCredentialsError{})

	// Correct current password works.
	require.NoError(t, pw.ChangePassword(ctx, "u1", "first password", "second password", "", ""))

	// New password logs in; old one does not.
	_, err = pw.Login(ctx, "alice", "second password", "", "")
	require.NoError(t, err)
	_, err = pw.Login(ctx, "alice", "first password", "", "")
	require.ErrorIs(t, err, &common.InvalidCredentialsError{})

	// Too-short password rejected by policy.
	err = pw.ChangePassword(ctx, "u1", "second password", "short", "", "")
	require.ErrorIs(t, err, &common.PasswordPolicyError{})
}

func TestPasswordResetSingleUse(t *testing.T) {
	ctx := t.Context()
	pw, _, db, user := setupPasswordTest(t, true)

	raw := "reset-token-abc123"
	require.NoError(t, db.Create(&model.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: crypto.HashToken(raw),
		Purpose:   model.PasswordResetPurposeReset,
		ExpiresAt: datatype.DateTime(time.Now().Add(15 * time.Minute)),
	}).Error)

	require.NoError(t, pw.ConsumeReset(ctx, raw, "brand new password", "", ""))

	// New password works.
	_, err := pw.Login(ctx, "alice", "brand new password", "", "")
	require.NoError(t, err)

	// Token is single-use.
	err = pw.ConsumeReset(ctx, raw, "another password", "", "")
	require.ErrorIs(t, err, &common.TokenInvalidOrExpiredError{})
}

func TestRequestResetUnknownEmailNoError(t *testing.T) {
	ctx := t.Context()
	pw, _, _, _ := setupPasswordTest(t, true)
	// Unknown email must not error (no enumeration) and must not create a token.
	require.NoError(t, pw.RequestReset(ctx, "ghost@example.com"))
}

func TestTotpEnrollConfirmAndLogin(t *testing.T) {
	ctx := t.Context()
	pw, totp, _, _ := setupPasswordTest(t, true)
	require.NoError(t, pw.AdminSetPassword(ctx, "u1", "correct horse battery", "", ""))

	secret, uri, err := totp.Enroll(ctx, "u1")
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.Contains(t, uri, "otpauth://totp/")

	// Wrong confirmation code rejected.
	_, err = totp.Confirm(ctx, "u1", "000000", "", "")
	require.ErrorIs(t, err, &common.MfaInvalidError{})

	// Correct code activates and returns recovery codes.
	code, err := crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	recoveryCodes, err := totp.Confirm(ctx, "u1", code, "", "")
	require.NoError(t, err)
	require.Len(t, recoveryCodes, 10)

	// Login now requires a second factor.
	res, err := pw.Login(ctx, "alice", "correct horse battery", "", "")
	require.NoError(t, err)
	require.Empty(t, res.AccessToken)
	require.NotEmpty(t, res.MfaChallenge)

	// Completing with a TOTP code issues the token.
	code, err = crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	_, token, err := pw.VerifyMfa(ctx, res.MfaChallenge, code, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, token)
}

func TestTotpRecoveryCodeSingleUse(t *testing.T) {
	ctx := t.Context()
	pw, totp, _, _ := setupPasswordTest(t, true)
	require.NoError(t, pw.AdminSetPassword(ctx, "u1", "correct horse battery", "", ""))

	secret, _, err := totp.Enroll(ctx, "u1")
	require.NoError(t, err)
	code, err := crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	recoveryCodes, err := totp.Confirm(ctx, "u1", code, "", "")
	require.NoError(t, err)

	recovery := recoveryCodes[0]

	// First login via recovery code works.
	res, err := pw.Login(ctx, "alice", "correct horse battery", "", "")
	require.NoError(t, err)
	_, token, err := pw.VerifyMfa(ctx, res.MfaChallenge, recovery, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Second use of the same recovery code fails.
	res, err = pw.Login(ctx, "alice", "correct horse battery", "", "")
	require.NoError(t, err)
	_, _, err = pw.VerifyMfa(ctx, res.MfaChallenge, recovery, "", "")
	require.ErrorIs(t, err, &common.MfaInvalidError{})
}

func TestTotpCodeReplayRejected(t *testing.T) {
	ctx := t.Context()
	pw, totp, _, _ := setupPasswordTest(t, true)
	require.NoError(t, pw.AdminSetPassword(ctx, "u1", "correct horse battery", "", ""))

	secret, _, err := totp.Enroll(ctx, "u1")
	require.NoError(t, err)
	code, err := crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	_, err = totp.Confirm(ctx, "u1", code, "", "")
	require.NoError(t, err)

	// First login with a fresh code succeeds.
	loginCode, err := crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	res, err := pw.Login(ctx, "alice", "correct horse battery", "", "")
	require.NoError(t, err)
	_, token, err := pw.VerifyMfa(ctx, res.MfaChallenge, loginCode, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Replaying the SAME code in a new challenge within the window must be rejected.
	res2, err := pw.Login(ctx, "alice", "correct horse battery", "", "")
	require.NoError(t, err)
	_, _, err = pw.VerifyMfa(ctx, res2.MfaChallenge, loginCode, "", "")
	require.ErrorIs(t, err, &common.MfaInvalidError{})
}

func TestMfaRejectsForgedChallengeToken(t *testing.T) {
	ctx := t.Context()
	pw, totp, _, _ := setupPasswordTest(t, true)
	require.NoError(t, pw.AdminSetPassword(ctx, "u1", "correct horse battery", "", ""))
	secret, _, err := totp.Enroll(ctx, "u1")
	require.NoError(t, err)
	code, err := crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	_, err = totp.Confirm(ctx, "u1", code, "", "")
	require.NoError(t, err)

	// A made-up challenge token (not issued by Login) must not complete MFA.
	code, err = crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	_, _, err = pw.VerifyMfa(ctx, "totally-made-up-token", code, "", "")
	require.ErrorIs(t, err, &common.MfaInvalidError{})
}

func TestTotpDisable(t *testing.T) {
	ctx := t.Context()
	pw, totp, db, _ := setupPasswordTest(t, true)
	require.NoError(t, pw.AdminSetPassword(ctx, "u1", "correct horse battery", "", ""))

	secret, _, err := totp.Enroll(ctx, "u1")
	require.NoError(t, err)
	code, err := crypto.GenerateCodeAt(secret, time.Now())
	require.NoError(t, err)
	_, err = totp.Confirm(ctx, "u1", code, "", "")
	require.NoError(t, err)

	require.NoError(t, totp.Disable(ctx, "u1", "", ""))

	var u model.User
	require.NoError(t, db.Where("id = ?", "u1").First(&u).Error)
	require.False(t, u.TotpEnabled)

	// Login no longer requires MFA.
	res, err := pw.Login(ctx, "alice", "correct horse battery", "", "")
	require.NoError(t, err)
	require.NotEmpty(t, res.AccessToken)
	require.Empty(t, res.MfaChallenge)
}
