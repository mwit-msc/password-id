package service

// pocket-id-password fork: TOTP (RFC 6238) second-factor enrollment and verification,
// plus single-use recovery codes. The TOTP secret is stored encrypted (EncryptedString);
// recovery codes are stored only as SHA-256 hashes.

import (
	"context"
	"errors"
	"time"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
	"github.com/pocket-id/pocket-id/backend/internal/utils/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const totpRecoveryCodeCount = 10

type TotpService struct {
	db               *gorm.DB
	appConfigService *AppConfigService
	auditLogService  *AuditLogService
}

func NewTotpService(db *gorm.DB, appConfigService *AppConfigService, auditLogService *AuditLogService) *TotpService {
	return &TotpService{
		db:               db,
		appConfigService: appConfigService,
		auditLogService:  auditLogService,
	}
}

func (s *TotpService) ensureEnabled() error {
	if !s.appConfigService.GetDbConfig().TotpEnabled.IsTrue() {
		return &common.TotpNotEnabledError{}
	}
	return nil
}

// Enroll generates a new (not-yet-active) TOTP secret for the user and returns the
// secret and an otpauth:// provisioning URI for QR display. Activation happens in Confirm.
func (s *TotpService) Enroll(ctx context.Context, userID string) (secret string, uri string, err error) {
	if err = s.ensureEnabled(); err != nil {
		return "", "", err
	}

	var user model.User
	if err = s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return "", "", err
	}
	if user.TotpEnabled {
		return "", "", &common.TotpAlreadyEnabledError{}
	}

	secret, err = crypto.GenerateTotpSecret()
	if err != nil {
		return "", "", err
	}

	encrypted := datatype.EncryptedString(secret)
	if err = s.db.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).
		Update("totp_secret", &encrypted).Error; err != nil {
		return "", "", err
	}

	account := user.Username
	if user.Email != nil && *user.Email != "" {
		account = *user.Email
	}
	issuer := s.appConfigService.GetDbConfig().AppName.Value
	if issuer == "" {
		issuer = "Pocket ID"
	}
	uri = crypto.TotpURI(secret, issuer, account)
	return secret, uri, nil
}

// Confirm verifies the first code against the pending secret, activates TOTP, and
// returns freshly generated single-use recovery codes (shown to the user once).
func (s *TotpService) Confirm(ctx context.Context, userID, code, ipAddress, userAgent string) ([]string, error) {
	if err := s.ensureEnabled(); err != nil {
		return nil, err
	}

	tx := s.db.Begin()
	defer func() { tx.Rollback() }()

	var user model.User
	if err := tx.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	if user.TotpEnabled {
		return nil, &common.TotpAlreadyEnabledError{}
	}
	if user.TotpSecret == nil || *user.TotpSecret == "" {
		return nil, &common.TotpNotEnabledError{}
	}

	if !crypto.VerifyTotp(string(*user.TotpSecret), code, time.Now()) {
		return nil, &common.MfaInvalidError{}
	}

	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).
		Update("totp_enabled", true).Error; err != nil {
		return nil, err
	}

	plainCodes, err := s.regenerateRecoveryCodes(ctx, tx, userID)
	if err != nil {
		return nil, err
	}

	s.auditLogService.Create(ctx, model.AuditLogEventTotpEnabled, ipAddress, userAgent, userID, model.AuditLogData{}, tx)

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	return plainCodes, nil
}

// Disable turns off TOTP and removes the secret and recovery codes.
func (s *TotpService) Disable(ctx context.Context, userID, ipAddress, userAgent string) error {
	tx := s.db.Begin()
	defer func() { tx.Rollback() }()

	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).
		Updates(map[string]any{"totp_enabled": false, "totp_secret": nil}).Error; err != nil {
		return err
	}
	if err := tx.WithContext(ctx).Where("user_id = ?", userID).Delete(&model.TotpRecoveryCode{}).Error; err != nil {
		return err
	}

	s.auditLogService.Create(ctx, model.AuditLogEventTotpDisabled, ipAddress, userAgent, userID, model.AuditLogData{}, tx)

	return tx.Commit().Error
}

// VerifySecondFactor checks a code against the user's TOTP secret, or, failing that,
// against the user's unused recovery codes (consuming one on match). Used during login.
func (s *TotpService) VerifySecondFactor(ctx context.Context, userID, code string, tx *gorm.DB) (bool, error) {
	var user model.User
	if err := tx.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return false, err
	}
	if !user.TotpEnabled || user.TotpSecret == nil {
		return false, nil
	}

	if ok, step := crypto.VerifyTotpWithStep(string(*user.TotpSecret), code, time.Now()); ok {
		// Reject replay: the matched time-step must be strictly newer than the last used one.
		if int64(step) <= user.TotpLastUsedStep { //nolint:gosec // step is a bounded unix time-step
			return false, nil
		}
		if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).
			Update("totp_last_used_step", int64(step)).Error; err != nil { //nolint:gosec // bounded time-step
			return false, err
		}
		return true, nil
	}

	// Fall back to a single-use recovery code.
	codeHash := crypto.HashToken(code)
	var recovery model.TotpRecoveryCode
	err := tx.WithContext(ctx).
		Where("user_id = ? AND code_hash = ? AND used_at IS NULL", userID, codeHash).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&recovery).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	now := datatype.DateTime(time.Now())
	if err := tx.WithContext(ctx).Model(&model.TotpRecoveryCode{}).
		Where("id = ?", recovery.ID).Update("used_at", &now).Error; err != nil {
		return false, err
	}
	return true, nil
}

func (s *TotpService) regenerateRecoveryCodes(ctx context.Context, tx *gorm.DB, userID string) ([]string, error) {
	if err := tx.WithContext(ctx).Where("user_id = ?", userID).Delete(&model.TotpRecoveryCode{}).Error; err != nil {
		return nil, err
	}

	plain := make([]string, 0, totpRecoveryCodeCount)
	for i := 0; i < totpRecoveryCodeCount; i++ {
		part1, err := utils.GenerateRandomUnambiguousString(5)
		if err != nil {
			return nil, err
		}
		part2, err := utils.GenerateRandomUnambiguousString(5)
		if err != nil {
			return nil, err
		}
		raw := part1 + "-" + part2
		plain = append(plain, raw)

		rc := &model.TotpRecoveryCode{
			UserID:   userID,
			CodeHash: crypto.HashToken(raw),
		}
		if err := tx.WithContext(ctx).Create(rc).Error; err != nil {
			return nil, err
		}
	}
	return plain, nil
}
