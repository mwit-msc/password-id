package service

// pocket-id-password fork: username/password authentication, account lockout,
// self-service change, and email-based reset / invite-to-set-password.
//
// Passwords are stored as Argon2id hashes (never encrypted). Login converges on the
// same jwtService.GenerateAccessToken used by passkey and one-time-code auth, so OIDC
// token issuance, groups, and custom claims are untouched.

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
	"github.com/pocket-id/pocket-id/backend/internal/utils/crypto"
	"github.com/pocket-id/pocket-id/backend/internal/utils/email"
	"go.opentelemetry.io/otel/trace"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	mfaChallengeTTL     = 5 * time.Minute
	mfaMaxAttempts      = 5
	resetTokenTTL       = 15 * time.Minute
	inviteTokenTTL      = 7 * 24 * time.Hour
	resetTokenRawLength = 32
)

type PasswordService struct {
	db               *gorm.DB
	jwtService       *JwtService
	auditLogService  *AuditLogService
	emailService     *EmailService
	appConfigService *AppConfigService
	totpService      *TotpService
	breachService    *BreachService

	// dummyHash is computed once from the live Argon2 params so that DummyVerify (used to
	// equalize timing for non-existent / passwordless users) costs the same as a real verify.
	dummyHash string
}

func NewPasswordService(db *gorm.DB, jwtService *JwtService, auditLogService *AuditLogService, emailService *EmailService, appConfigService *AppConfigService, totpService *TotpService, breachService *BreachService) *PasswordService {
	s := &PasswordService{
		db:               db,
		jwtService:       jwtService,
		auditLogService:  auditLogService,
		emailService:     emailService,
		appConfigService: appConfigService,
		totpService:      totpService,
		breachService:    breachService,
	}

	// Precompute a dummy hash with the configured cost for constant-time enumeration defense.
	if random, err := utils.GenerateRandomAlphanumericString(24); err == nil {
		if dh, err := crypto.HashPassword(random, s.argon2Params()); err == nil {
			s.dummyHash = dh
		}
	}

	return s
}

// dummyVerify runs an Argon2 verification against the precomputed dummy hash to keep
// timing constant when there is no real password to check. The result is discarded.
func (s *PasswordService) dummyVerify(password string) {
	if s.dummyHash != "" {
		_, _ = crypto.VerifyPassword(password, s.dummyHash)
		return
	}
	crypto.DummyVerify(password)
}

func (s *PasswordService) ensureEnabled() error {
	if !s.appConfigService.GetDbConfig().PasswordAuthEnabled.IsTrue() {
		return &common.PasswordAuthDisabledError{}
	}
	return nil
}

func (s *PasswordService) argon2Params() crypto.Argon2idParams {
	p := crypto.DefaultArgon2idParams()
	if v := common.EnvConfig.PasswordArgon2Memory; v > 0 {
		p.Memory = uint32(v) //nolint:gosec // bounded config value
	}
	if v := common.EnvConfig.PasswordArgon2Iterations; v > 0 {
		p.Iterations = uint32(v) //nolint:gosec // bounded config value
	}
	if v := common.EnvConfig.PasswordArgon2Parallelism; v > 0 {
		p.Parallelism = uint8(v) //nolint:gosec // bounded config value
	}
	return p
}

// ValidatePassword enforces the configured password policy.
func (s *PasswordService) ValidatePassword(ctx context.Context, password string) error {
	minLen := common.EnvConfig.PasswordMinLength
	if minLen <= 0 {
		minLen = 10
	}
	if len(password) < minLen {
		return &common.PasswordPolicyError{Reason: "password is too short"}
	}

	if s.appConfigService.GetDbConfig().BreachCheckEnabled.IsTrue() {
		breached, err := s.breachService.IsPasswordBreached(ctx, password)
		if err != nil {
			// Fail-open: log but do not block the user on an HIBP outage.
			slog.WarnContext(ctx, "breach check failed, allowing password", slog.Any("error", err))
		} else if breached {
			return &common.PasswordPolicyError{Reason: "this password has appeared in a known data breach; please choose another"}
		}
	}
	return nil
}

// PasswordPolicy returns the current policy for client-side hints.
func (s *PasswordService) PasswordPolicy() (minLength int) {
	minLength = common.EnvConfig.PasswordMinLength
	if minLength <= 0 {
		minLength = 10
	}
	return minLength
}

// LoginResult describes the outcome of a password login attempt.
type LoginResult struct {
	User         model.User
	AccessToken  string // set when login is complete
	MfaChallenge string // set when a second factor is required
}

// Login verifies username/email + password. On success it either issues an access token
// or, if the user has TOTP enabled, creates an MFA challenge requiring a second factor.
func (s *PasswordService) Login(ctx context.Context, identifier, password, ipAddress, userAgent string) (LoginResult, error) {
	if err := s.ensureEnabled(); err != nil {
		return LoginResult{}, err
	}

	identifier = strings.TrimSpace(identifier)

	tx := s.db.Begin()
	defer func() { tx.Rollback() }()

	var user model.User
	err := tx.WithContext(ctx).
		Where("username = ? OR email = ?", identifier, identifier).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Equalize timing against the user-exists path to prevent enumeration.
			s.dummyVerify(password)
			return LoginResult{}, &common.InvalidCredentialsError{}
		}
		return LoginResult{}, err
	}

	if user.PasswordHash == nil || *user.PasswordHash == "" || user.Disabled {
		s.dummyVerify(password)
		return LoginResult{}, &common.InvalidCredentialsError{}
	}

	// Lockout check. Return the generic error (and burn equivalent time) rather than a
	// distinct status, so lockout state can't be used to enumerate valid accounts.
	now := time.Now()
	if user.LockedUntil != nil && user.LockedUntil.ToTime().After(now) {
		s.dummyVerify(password)
		return LoginResult{}, &common.InvalidCredentialsError{}
	}

	ok, err := crypto.VerifyPassword(password, *user.PasswordHash)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok {
		s.registerFailedAttempt(ctx, tx, &user, ipAddress, userAgent)
		if err := tx.Commit().Error; err != nil {
			return LoginResult{}, err
		}
		return LoginResult{}, &common.InvalidCredentialsError{}
	}

	// Success: clear failure counters.
	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", user.ID).
		Updates(map[string]any{"failed_login_count": 0, "locked_until": nil}).Error; err != nil {
		return LoginResult{}, err
	}

	if user.TotpEnabled {
		// The challenge is identified to the client by a high-entropy random token stored
		// only as a hash — the primary key is never exposed as a bearer credential.
		rawToken, err := utils.GenerateRandomAlphanumericString(32)
		if err != nil {
			return LoginResult{}, err
		}
		challenge := &model.MfaChallenge{
			UserID:    user.ID,
			TokenHash: crypto.HashToken(rawToken),
			ExpiresAt: datatype.DateTime(now.Add(mfaChallengeTTL)),
		}
		if err := tx.WithContext(ctx).Create(challenge).Error; err != nil {
			return LoginResult{}, err
		}
		if err := tx.Commit().Error; err != nil {
			return LoginResult{}, err
		}
		return LoginResult{User: user, MfaChallenge: rawToken}, nil
	}

	token, err := s.jwtService.GenerateAccessToken(user, AuthenticationMethodPassword)
	if err != nil {
		return LoginResult{}, err
	}
	s.auditLogService.Create(ctx, model.AuditLogEventPasswordSignIn, ipAddress, userAgent, user.ID, model.AuditLogData{}, tx)
	if err := tx.Commit().Error; err != nil {
		return LoginResult{}, err
	}
	return LoginResult{User: user, AccessToken: token}, nil
}

func (s *PasswordService) registerFailedAttempt(ctx context.Context, tx *gorm.DB, user *model.User, ipAddress, userAgent string) {
	maxAttempts := common.EnvConfig.PasswordLockoutMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	lockMinutes := common.EnvConfig.PasswordLockoutDurationMinutes
	if lockMinutes <= 0 {
		lockMinutes = 15
	}

	newCount := user.FailedLoginCount + 1
	updates := map[string]any{"failed_login_count": newCount}
	if newCount >= maxAttempts {
		lockedUntil := datatype.DateTime(time.Now().Add(time.Duration(lockMinutes) * time.Minute))
		updates["locked_until"] = &lockedUntil
		updates["failed_login_count"] = 0
		s.auditLogService.Create(ctx, model.AuditLogEventAccountLocked, ipAddress, userAgent, user.ID, model.AuditLogData{}, tx)
	}
	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
		slog.ErrorContext(ctx, "failed to record login failure", slog.Any("error", err))
	}
}

// VerifyMfa completes a login that required a second factor. challengeToken is the raw
// token issued to the client (looked up by hash); code is a TOTP or recovery code.
func (s *PasswordService) VerifyMfa(ctx context.Context, challengeToken, code, ipAddress, userAgent string) (model.User, string, error) {
	if err := s.ensureEnabled(); err != nil {
		return model.User{}, "", err
	}

	tx := s.db.Begin()
	defer func() { tx.Rollback() }()

	var challenge model.MfaChallenge
	err := tx.WithContext(ctx).
		Where("token_hash = ? AND expires_at > ?", crypto.HashToken(challengeToken), datatype.DateTime(time.Now())).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&challenge).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.User{}, "", &common.MfaInvalidError{}
		}
		return model.User{}, "", err
	}

	if challenge.AttemptCount >= mfaMaxAttempts {
		_ = tx.WithContext(ctx).Delete(&challenge).Error
		_ = tx.Commit().Error
		return model.User{}, "", &common.MfaInvalidError{}
	}

	ok, err := s.totpService.VerifySecondFactor(ctx, challenge.UserID, strings.TrimSpace(code), tx)
	if err != nil {
		return model.User{}, "", err
	}
	if !ok {
		if err := tx.WithContext(ctx).Model(&model.MfaChallenge{}).Where("id = ?", challenge.ID).
			Update("attempt_count", challenge.AttemptCount+1).Error; err != nil {
			return model.User{}, "", err
		}
		if err := tx.Commit().Error; err != nil {
			return model.User{}, "", err
		}
		return model.User{}, "", &common.MfaInvalidError{}
	}

	var user model.User
	if err := tx.WithContext(ctx).Where("id = ?", challenge.UserID).First(&user).Error; err != nil {
		return model.User{}, "", err
	}

	// Re-check authorization state: the account may have been disabled or locked during
	// the MFA window. Do not issue a token for a user who can no longer log in.
	if user.Disabled || (user.LockedUntil != nil && user.LockedUntil.ToTime().After(time.Now())) {
		_ = tx.WithContext(ctx).Delete(&challenge).Error
		_ = tx.Commit().Error
		return model.User{}, "", &common.InvalidCredentialsError{}
	}

	token, err := s.jwtService.GenerateAccessToken(user, AuthenticationMethodPassword)
	if err != nil {
		return model.User{}, "", err
	}

	if err := tx.WithContext(ctx).Delete(&challenge).Error; err != nil {
		return model.User{}, "", err
	}
	s.auditLogService.Create(ctx, model.AuditLogEventMfaSignIn, ipAddress, userAgent, user.ID, model.AuditLogData{}, tx)

	if err := tx.Commit().Error; err != nil {
		return model.User{}, "", err
	}
	return user, token, nil
}

// ChangePassword updates the password for a logged-in user, verifying the current one
// when the user already has a password set.
func (s *PasswordService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword, ipAddress, userAgent string) error {
	if err := s.ensureEnabled(); err != nil {
		return err
	}
	if err := s.ValidatePassword(ctx, newPassword); err != nil {
		return err
	}

	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return err
	}

	if user.PasswordHash != nil && *user.PasswordHash != "" {
		ok, err := crypto.VerifyPassword(currentPassword, *user.PasswordHash)
		if err != nil {
			return err
		}
		if !ok {
			return &common.InvalidCredentialsError{}
		}
	}

	return s.setPasswordInternal(ctx, s.db, userID, newPassword, model.AuditLogEventPasswordChanged, ipAddress, userAgent)
}

// AdminSetPassword sets (or overwrites) a user's password as an administrator.
func (s *PasswordService) AdminSetPassword(ctx context.Context, userID, newPassword, ipAddress, userAgent string) error {
	if err := s.ensureEnabled(); err != nil {
		return err
	}
	if err := s.ValidatePassword(ctx, newPassword); err != nil {
		return err
	}
	return s.setPasswordInternal(ctx, s.db, userID, newPassword, model.AuditLogEventPasswordSet, ipAddress, userAgent)
}

func (s *PasswordService) setPasswordInternal(ctx context.Context, db *gorm.DB, userID, newPassword string, event model.AuditLogEvent, ipAddress, userAgent string) error {
	hash, err := crypto.HashPassword(newPassword, s.argon2Params())
	if err != nil {
		return err
	}

	tx := db.Begin()
	defer func() { tx.Rollback() }()

	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", userID).
		Updates(map[string]any{"password_hash": hash, "failed_login_count": 0, "locked_until": nil}).Error; err != nil {
		return err
	}
	s.auditLogService.Create(ctx, event, ipAddress, userAgent, userID, model.AuditLogData{}, tx)
	return tx.Commit().Error
}

// RequestReset creates a reset token and emails a reset link. To avoid user enumeration
// it always returns nil, regardless of whether the email matched a user.
func (s *PasswordService) RequestReset(ctx context.Context, emailAddr string) error {
	if err := s.ensureEnabled(); err != nil {
		return err
	}

	var user model.User
	err := s.db.WithContext(ctx).Where("email = ?", strings.TrimSpace(emailAddr)).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else if err != nil {
		return err
	}

	if err := s.createTokenAndEmail(ctx, user, model.PasswordResetPurposeReset, resetTokenTTL); err != nil {
		slog.ErrorContext(ctx, "failed to create password reset", slog.Any("error", err))
	}
	return nil
}

// SendInvite (admin) creates a long-lived invite token and emails a set-password link.
func (s *PasswordService) SendInvite(ctx context.Context, userID string) error {
	if err := s.ensureEnabled(); err != nil {
		return err
	}
	var user model.User
	if err := s.db.WithContext(ctx).Where("id = ?", userID).First(&user).Error; err != nil {
		return err
	}
	if user.Email == nil || *user.Email == "" {
		return &common.UserEmailNotSetError{}
	}
	return s.createTokenAndEmail(ctx, user, model.PasswordResetPurposeInvite, inviteTokenTTL)
}

func (s *PasswordService) createTokenAndEmail(ctx context.Context, user model.User, purpose model.PasswordResetTokenPurpose, ttl time.Duration) error {
	if user.Email == nil || *user.Email == "" {
		return &common.UserEmailNotSetError{}
	}

	rawToken, err := utils.GenerateRandomAlphanumericString(resetTokenRawLength)
	if err != nil {
		return err
	}

	resetToken := &model.PasswordResetToken{
		UserID:    user.ID,
		TokenHash: crypto.HashToken(rawToken),
		Purpose:   purpose,
		ExpiresAt: datatype.DateTime(time.Now().Add(ttl)),
	}
	if err := s.db.WithContext(ctx).Create(resetToken).Error; err != nil {
		return err
	}

	// #nosec G118 - background context for the goroutine, span propagated
	//nolint:contextcheck
	go func() {
		span := trace.SpanFromContext(ctx)
		innerCtx := trace.ContextWithSpan(context.Background(), span)

		link := common.EnvConfig.AppURL + "/set-password?token=" + url.QueryEscape(rawToken)
		var sendErr error
		if purpose == model.PasswordResetPurposeInvite {
			sendErr = SendEmail(innerCtx, s.emailService, email.Address{Name: user.FullName(), Email: *user.Email},
				PasswordInviteTemplate, &PasswordInviteTemplateData{
					UserFullName: user.FullName(),
					InviteLink:   link,
				})
		} else {
			sendErr = SendEmail(innerCtx, s.emailService, email.Address{Name: user.FullName(), Email: *user.Email},
				PasswordResetTemplate, &PasswordResetTemplateData{
					UserFullName:     user.FullName(),
					ResetLink:        link,
					ExpirationString: utils.DurationToString(ttl),
				})
		}
		if sendErr != nil {
			slog.ErrorContext(innerCtx, "failed to send password email", slog.Any("error", sendErr), slog.String("address", *user.Email))
		}
	}()

	return nil
}

// ConsumeReset validates a reset/invite token and sets the new password, single-use.
func (s *PasswordService) ConsumeReset(ctx context.Context, rawToken, newPassword, ipAddress, userAgent string) error {
	if err := s.ensureEnabled(); err != nil {
		return err
	}
	if err := s.ValidatePassword(ctx, newPassword); err != nil {
		return err
	}

	tx := s.db.Begin()
	defer func() { tx.Rollback() }()

	var resetToken model.PasswordResetToken
	err := tx.WithContext(ctx).
		Where("token_hash = ? AND expires_at > ?", crypto.HashToken(rawToken), datatype.DateTime(time.Now())).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		First(&resetToken).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &common.TokenInvalidOrExpiredError{}
		}
		return err
	}

	hash, err := crypto.HashPassword(newPassword, s.argon2Params())
	if err != nil {
		return err
	}

	if err := tx.WithContext(ctx).Model(&model.User{}).Where("id = ?", resetToken.UserID).
		Updates(map[string]any{"password_hash": hash, "failed_login_count": 0, "locked_until": nil}).Error; err != nil {
		return err
	}
	if err := tx.WithContext(ctx).Delete(&resetToken).Error; err != nil {
		return err
	}
	// Invalidate any other outstanding reset/invite tokens for this user.
	if err := tx.WithContext(ctx).Where("user_id = ?", resetToken.UserID).Delete(&model.PasswordResetToken{}).Error; err != nil {
		return err
	}
	s.auditLogService.Create(ctx, model.AuditLogEventPasswordReset, ipAddress, userAgent, resetToken.UserID, model.AuditLogData{}, tx)

	return tx.Commit().Error
}
