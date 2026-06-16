package service

// pocket-id-password fork: external OIDC providers (social login / account linking).
//
// Pocket-ID is an OIDC provider; this service lets it also act as a relying party against
// upstream IdPs such as Google. Flow:
//   1. BeginAuth persists a short-lived CSRF/PKCE session and returns the provider authorize URL.
//   2. The provider redirects back to the callback with code+state.
//   3. CompleteAuth verifies state, exchanges the code, reads userinfo, then links/creates the
//      local user and converges on jwtService.GenerateAccessToken (same path as passkey/password).
//
// Auto-signup and auto-link are gated by a per-provider email-domain whitelist so that not every
// Google account in the world can mint an account on this instance.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	"github.com/pocket-id/pocket-id/backend/internal/utils"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

const (
	externalAuthSessionTTL = 10 * time.Minute
	externalStateLength    = 32
)

type ExternalIdpService struct {
	db               *gorm.DB
	jwtService       *JwtService
	auditLogService  *AuditLogService
	appConfigService *AppConfigService
	userService      *UserService
	httpClient       *http.Client

	discoveryMu    sync.RWMutex
	discoveryCache map[string]oidcDiscovery
}

func NewExternalIdpService(db *gorm.DB, jwtService *JwtService, auditLogService *AuditLogService, appConfigService *AppConfigService, userService *UserService, httpClient *http.Client) *ExternalIdpService {
	return &ExternalIdpService{
		db:               db,
		jwtService:       jwtService,
		auditLogService:  auditLogService,
		appConfigService: appConfigService,
		userService:      userService,
		httpClient:       httpClient,
		discoveryCache:   make(map[string]oidcDiscovery),
	}
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type externalUserInfo struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// CompleteAuthResult is the outcome of a successful provider callback.
type CompleteAuthResult struct {
	Mode        string // "login" | "link"
	User        model.User
	AccessToken string
	RedirectURI string
}

// ---------------------------------------------------------------------------
// Provider CRUD
// ---------------------------------------------------------------------------

func (s *ExternalIdpService) ListProviders(ctx context.Context, onlyEnabled bool) ([]model.ExternalIdpProvider, error) {
	var providers []model.ExternalIdpProvider
	q := s.db.WithContext(ctx).Order("name ASC")
	if onlyEnabled {
		q = q.Where("enabled = ?", true)
	}
	if err := q.Find(&providers).Error; err != nil {
		return nil, err
	}
	return providers, nil
}

// ListPublicProviders returns the enabled providers that may be used to start a login.
func (s *ExternalIdpService) ListPublicProviders(ctx context.Context) ([]dto.ExternalIdpProviderPublicDto, error) {
	providers, err := s.ListProviders(ctx, true)
	if err != nil {
		return nil, err
	}
	out := make([]dto.ExternalIdpProviderPublicDto, 0, len(providers))
	for _, p := range providers {
		if !p.AllowLogin && !p.AllowSignup {
			continue
		}
		out = append(out, dto.ExternalIdpProviderPublicDto{Slug: p.Slug, Name: p.Name})
	}
	return out, nil
}

func (s *ExternalIdpService) getProviderBySlug(ctx context.Context, slug string) (model.ExternalIdpProvider, error) {
	var provider model.ExternalIdpProvider
	err := s.db.WithContext(ctx).Where("slug = ?", slug).First(&provider).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return model.ExternalIdpProvider{}, &common.ExternalIdpProviderNotFoundError{}
	}
	return provider, err
}

func (s *ExternalIdpService) GetProviderBySlug(ctx context.Context, slug string) (model.ExternalIdpProvider, error) {
	return s.getProviderBySlug(ctx, slug)
}

func (s *ExternalIdpService) CreateProvider(ctx context.Context, input dto.ExternalIdpProviderCreateDto) (model.ExternalIdpProvider, error) {
	provider := model.ExternalIdpProvider{
		Slug:           strings.ToLower(strings.TrimSpace(input.Slug)),
		Name:           input.Name,
		ClientID:       input.ClientID,
		ClientSecret:   datatype.EncryptedString(input.ClientSecret),
		IssuerURL:      strings.TrimRight(strings.TrimSpace(input.IssuerURL), "/"),
		Scopes:         normalizeScopes(input.Scopes),
		Enabled:        input.Enabled,
		AllowLogin:     input.AllowLogin,
		AllowSignup:    input.AllowSignup,
		AllowedDomains: input.AllowedDomains,
	}
	err := s.db.WithContext(ctx).Create(&provider).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return model.ExternalIdpProvider{}, &common.AlreadyInUseError{Property: "slug"}
	}
	if err != nil {
		return model.ExternalIdpProvider{}, err
	}
	return provider, nil
}

func (s *ExternalIdpService) UpdateProvider(ctx context.Context, id string, input dto.ExternalIdpProviderUpdateDto) (model.ExternalIdpProvider, error) {
	var provider model.ExternalIdpProvider
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&provider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return model.ExternalIdpProvider{}, &common.ExternalIdpProviderNotFoundError{}
		}
		return model.ExternalIdpProvider{}, err
	}
	if provider.ManagedByEnv {
		return model.ExternalIdpProvider{}, &common.ExternalIdpManagedByEnvError{}
	}

	provider.Name = input.Name
	provider.ClientID = input.ClientID
	provider.IssuerURL = strings.TrimRight(strings.TrimSpace(input.IssuerURL), "/")
	provider.Scopes = normalizeScopes(input.Scopes)
	provider.Enabled = input.Enabled
	provider.AllowLogin = input.AllowLogin
	provider.AllowSignup = input.AllowSignup
	provider.AllowedDomains = input.AllowedDomains
	if input.ClientSecret != nil {
		provider.ClientSecret = datatype.EncryptedString(*input.ClientSecret)
	}
	now := datatype.DateTime(time.Now())
	provider.UpdatedAt = &now

	if err := s.db.WithContext(ctx).Save(&provider).Error; err != nil {
		return model.ExternalIdpProvider{}, err
	}
	return provider, nil
}

func (s *ExternalIdpService) DeleteProvider(ctx context.Context, id string) error {
	var provider model.ExternalIdpProvider
	if err := s.db.WithContext(ctx).Where("id = ?", id).First(&provider).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &common.ExternalIdpProviderNotFoundError{}
		}
		return err
	}
	if provider.ManagedByEnv {
		return &common.ExternalIdpManagedByEnvError{}
	}
	return s.db.WithContext(ctx).Delete(&provider).Error
}

// ---------------------------------------------------------------------------
// Linked identities
// ---------------------------------------------------------------------------

func (s *ExternalIdpService) GetUserIdentities(ctx context.Context, userID string) ([]dto.UserExternalIdentityDto, error) {
	var identities []model.UserExternalIdentity
	err := s.db.WithContext(ctx).Preload("Provider").Where("user_id = ?", userID).Find(&identities).Error
	if err != nil {
		return nil, err
	}
	out := make([]dto.UserExternalIdentityDto, 0, len(identities))
	for _, id := range identities {
		out = append(out, dto.UserExternalIdentityDto{
			ID:           id.ID,
			ProviderSlug: id.Provider.Slug,
			ProviderName: id.Provider.Name,
			Email:        id.Email,
			CreatedAt:    id.CreatedAt,
		})
	}
	return out, nil
}

func (s *ExternalIdpService) Unlink(ctx context.Context, userID, identityID, ipAddress, userAgent string) error {
	res := s.db.WithContext(ctx).
		Where("id = ? AND user_id = ?", identityID, userID).
		Delete(&model.UserExternalIdentity{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return &common.ExternalIdpProviderNotFoundError{}
	}
	s.auditLogService.Create(ctx, model.AuditLogEventExternalAccountUnlinked, ipAddress, userAgent, userID, model.AuditLogData{}, nil)
	return nil
}

// ---------------------------------------------------------------------------
// Auth flow
// ---------------------------------------------------------------------------

// BeginAuth creates the auth session and returns the provider's authorize URL.
func (s *ExternalIdpService) BeginAuth(ctx context.Context, slug, mode, redirectURI string, userID *string) (string, error) {
	provider, err := s.getProviderBySlug(ctx, slug)
	if err != nil {
		return "", err
	}
	if !provider.Enabled {
		return "", &common.ExternalIdpDisabledError{}
	}

	disc, err := s.discover(ctx, provider.IssuerURL)
	if err != nil {
		return "", err
	}

	state, err := utils.GenerateRandomAlphanumericString(externalStateLength)
	if err != nil {
		return "", err
	}
	nonce, err := utils.GenerateRandomAlphanumericString(externalStateLength)
	if err != nil {
		return "", err
	}
	verifier := oauth2.GenerateVerifier()

	// Best-effort cleanup of expired sessions.
	s.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&model.ExternalIdpAuthSession{})

	session := model.ExternalIdpAuthSession{
		State:        state,
		ProviderID:   provider.ID,
		CodeVerifier: verifier,
		Nonce:        nonce,
		RedirectURI:  redirectURI,
		Mode:         mode,
		UserID:       userID,
		ExpiresAt:    datatype.DateTime(time.Now().Add(externalAuthSessionTTL)),
	}
	if err := s.db.WithContext(ctx).Create(&session).Error; err != nil {
		return "", err
	}

	conf := s.oauthConfig(provider, disc)
	authURL := conf.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.AccessTypeOffline,
	)
	return authURL, nil
}

// CompleteAuth verifies the callback, exchanges the code, and links/creates the user.
func (s *ExternalIdpService) CompleteAuth(ctx context.Context, slug, state, code, ipAddress, userAgent string) (*CompleteAuthResult, error) {
	var session model.ExternalIdpAuthSession
	err := s.db.WithContext(ctx).Where("state = ?", state).First(&session).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, &common.ExternalIdpStateInvalidError{}
	}
	if err != nil {
		return nil, err
	}
	// State is single-use: delete it before doing anything else.
	s.db.WithContext(ctx).Delete(&session)

	if time.Now().After(session.ExpiresAt.ToTime()) {
		return nil, &common.ExternalIdpStateInvalidError{}
	}

	provider, err := s.getProviderBySlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	if provider.ID != session.ProviderID {
		return nil, &common.ExternalIdpStateInvalidError{}
	}
	if !provider.Enabled {
		return nil, &common.ExternalIdpDisabledError{}
	}

	disc, err := s.discover(ctx, provider.IssuerURL)
	if err != nil {
		return nil, err
	}

	conf := s.oauthConfig(provider, disc)
	exchangeCtx := context.WithValue(ctx, oauth2.HTTPClient, s.httpClient)
	token, err := conf.Exchange(exchangeCtx, code, oauth2.VerifierOption(session.CodeVerifier))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	info, err := s.fetchUserInfo(ctx, disc.UserinfoEndpoint, token)
	if err != nil {
		return nil, err
	}
	if info.Subject == "" {
		return nil, fmt.Errorf("external provider did not return a subject")
	}

	// Link mode: bind this identity to the already signed-in user.
	if session.Mode == "link" && session.UserID != nil {
		if err := s.linkIdentity(ctx, *session.UserID, provider, info, ipAddress, userAgent); err != nil {
			return nil, err
		}
		return &CompleteAuthResult{Mode: "link", RedirectURI: session.RedirectURI}, nil
	}

	// Login mode: find linked identity, else match/create by email.
	user, err := s.resolveLoginUser(ctx, provider, info, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}
	if user.Disabled {
		return nil, &common.ExternalIdpNoAccountError{}
	}

	accessToken, err := s.jwtService.GenerateAccessToken(user, AuthenticationMethodExternal)
	if err != nil {
		return nil, err
	}
	s.auditLogService.Create(ctx, model.AuditLogEventExternalSignIn, ipAddress, userAgent, user.ID, model.AuditLogData{"provider": provider.Slug}, nil)

	return &CompleteAuthResult{Mode: "login", User: user, AccessToken: accessToken, RedirectURI: session.RedirectURI}, nil
}

// resolveLoginUser maps the provider identity to a local user, auto-linking/creating as allowed.
func (s *ExternalIdpService) resolveLoginUser(ctx context.Context, provider model.ExternalIdpProvider, info externalUserInfo, ipAddress, userAgent string) (model.User, error) {
	// 1. Already linked?
	var identity model.UserExternalIdentity
	err := s.db.WithContext(ctx).
		Where("provider_id = ? AND subject = ?", provider.ID, info.Subject).
		First(&identity).Error
	if err == nil {
		if !provider.AllowLogin {
			return model.User{}, &common.ExternalIdpDisabledError{}
		}
		return s.userService.GetUser(ctx, identity.UserID)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, err
	}

	// Not linked yet: we need a trusted, whitelisted email to proceed.
	email := strings.ToLower(strings.TrimSpace(info.Email))
	if email == "" || !info.EmailVerified {
		return model.User{}, &common.ExternalIdpEmailNotAllowedError{}
	}
	if !provider.EmailAllowed(email) {
		return model.User{}, &common.ExternalIdpEmailNotAllowedError{}
	}

	// 2. Match an existing user by verified email -> auto-link.
	var existing model.User
	err = s.db.WithContext(ctx).Where("LOWER(email) = ?", email).First(&existing).Error
	if err == nil {
		if !provider.AllowLogin {
			return model.User{}, &common.ExternalIdpNoAccountError{}
		}
		if err := s.createIdentity(ctx, existing.ID, provider, info, ipAddress, userAgent); err != nil {
			return model.User{}, err
		}
		return existing, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return model.User{}, err
	}

	// 3. No user: auto-provision if allowed.
	if !provider.AllowSignup {
		return model.User{}, &common.ExternalIdpNoAccountError{}
	}
	created, err := s.provisionUser(ctx, info, ipAddress, userAgent)
	if err != nil {
		return model.User{}, err
	}
	if err := s.createIdentity(ctx, created.ID, provider, info, ipAddress, userAgent); err != nil {
		return model.User{}, err
	}
	return created, nil
}

func (s *ExternalIdpService) linkIdentity(ctx context.Context, userID string, provider model.ExternalIdpProvider, info externalUserInfo, ipAddress, userAgent string) error {
	// Ensure this provider identity isn't already linked to a different account.
	var existing model.UserExternalIdentity
	err := s.db.WithContext(ctx).
		Where("provider_id = ? AND subject = ?", provider.ID, info.Subject).
		First(&existing).Error
	if err == nil {
		if existing.UserID == userID {
			return nil // already linked to this user
		}
		return &common.ExternalIdpAlreadyLinkedError{}
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return s.createIdentity(ctx, userID, provider, info, ipAddress, userAgent)
}

func (s *ExternalIdpService) createIdentity(ctx context.Context, userID string, provider model.ExternalIdpProvider, info externalUserInfo, ipAddress, userAgent string) error {
	identity := model.UserExternalIdentity{
		UserID:     userID,
		ProviderID: provider.ID,
		Subject:    info.Subject,
		Email:      strings.ToLower(strings.TrimSpace(info.Email)),
	}
	if err := s.db.WithContext(ctx).Create(&identity).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return &common.ExternalIdpAlreadyLinkedError{}
		}
		return err
	}
	s.auditLogService.Create(ctx, model.AuditLogEventExternalAccountLinked, ipAddress, userAgent, userID, model.AuditLogData{"provider": provider.Slug}, nil)
	return nil
}

func (s *ExternalIdpService) provisionUser(ctx context.Context, info externalUserInfo, ipAddress, userAgent string) (model.User, error) {
	email := strings.ToLower(strings.TrimSpace(info.Email))
	username, err := s.uniqueUsername(ctx, info, email)
	if err != nil {
		return model.User{}, err
	}

	input := dto.UserCreateDto{
		Username:      username,
		Email:         &email,
		EmailVerified: true, // the provider asserted the email is verified
		FirstName:     strings.TrimSpace(info.GivenName),
		LastName:      strings.TrimSpace(info.FamilyName),
		DisplayName:   strings.TrimSpace(info.Name),
	}
	if input.FirstName == "" && input.DisplayName != "" {
		input.FirstName = input.DisplayName
	}
	if input.FirstName == "" {
		input.FirstName = username
	}

	user, err := s.userService.CreateUser(ctx, input)
	if err != nil {
		return model.User{}, err
	}
	s.auditLogService.Create(ctx, model.AuditLogEventAccountCreated, ipAddress, userAgent, user.ID, model.AuditLogData{}, nil)
	return user, nil
}

// uniqueUsername derives a valid, unused username from the provider claims.
func (s *ExternalIdpService) uniqueUsername(ctx context.Context, info externalUserInfo, email string) (string, error) {
	base := sanitizeUsername(emailLocalPart(email))
	if base == "" {
		base = sanitizeUsername(info.Name)
	}
	if base == "" {
		base = "user"
	}

	candidate := base
	for i := 0; i < 50; i++ {
		var count int64
		if err := s.db.WithContext(ctx).Model(&model.User{}).Where("username = ?", candidate).Count(&count).Error; err != nil {
			return "", err
		}
		if count == 0 {
			return candidate, nil
		}
		suffix, err := utils.GenerateRandomAlphanumericString(4)
		if err != nil {
			return "", err
		}
		candidate = base + strings.ToLower(suffix)
	}
	return "", fmt.Errorf("could not allocate a unique username")
}

// ---------------------------------------------------------------------------
// Env seeding
// ---------------------------------------------------------------------------

// SeedFromEnv upserts providers defined via environment variables. Such providers are
// marked ManagedByEnv (read-only in the UI). Supported:
//
//	Google preset:
//	  OIDC_GOOGLE_CLIENT_ID, OIDC_GOOGLE_CLIENT_SECRET,
//	  OIDC_GOOGLE_ALLOWED_DOMAINS (optional), OIDC_GOOGLE_ALLOW_SIGNUP (optional, default true)
//	Generic provider:
//	  OIDC_PROVIDER_SLUG, OIDC_PROVIDER_NAME, OIDC_PROVIDER_ISSUER_URL,
//	  OIDC_PROVIDER_CLIENT_ID, OIDC_PROVIDER_CLIENT_SECRET,
//	  OIDC_PROVIDER_SCOPES (optional), OIDC_PROVIDER_ALLOWED_DOMAINS (optional),
//	  OIDC_PROVIDER_ALLOW_SIGNUP (optional, default false)
func (s *ExternalIdpService) SeedFromEnv(ctx context.Context) error {
	if cid := strings.TrimSpace(getEnv("OIDC_GOOGLE_CLIENT_ID")); cid != "" {
		err := s.upsertEnvProvider(ctx, envProvider{
			Slug:           "google",
			Name:           "Google",
			IssuerURL:      "https://accounts.google.com",
			ClientID:       cid,
			ClientSecret:   getEnv("OIDC_GOOGLE_CLIENT_SECRET"),
			Scopes:         "openid profile email",
			AllowedDomains: getEnv("OIDC_GOOGLE_ALLOWED_DOMAINS"),
			AllowSignup:    envBool("OIDC_GOOGLE_ALLOW_SIGNUP", true),
		})
		if err != nil {
			return err
		}
	}

	if slug := strings.TrimSpace(getEnv("OIDC_PROVIDER_SLUG")); slug != "" {
		err := s.upsertEnvProvider(ctx, envProvider{
			Slug:           strings.ToLower(slug),
			Name:           orDefault(getEnv("OIDC_PROVIDER_NAME"), slug),
			IssuerURL:      getEnv("OIDC_PROVIDER_ISSUER_URL"),
			ClientID:       getEnv("OIDC_PROVIDER_CLIENT_ID"),
			ClientSecret:   getEnv("OIDC_PROVIDER_CLIENT_SECRET"),
			Scopes:         orDefault(getEnv("OIDC_PROVIDER_SCOPES"), "openid profile email"),
			AllowedDomains: getEnv("OIDC_PROVIDER_ALLOWED_DOMAINS"),
			AllowSignup:    envBool("OIDC_PROVIDER_ALLOW_SIGNUP", false),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

type envProvider struct {
	Slug           string
	Name           string
	IssuerURL      string
	ClientID       string
	ClientSecret   string
	Scopes         string
	AllowedDomains string
	AllowSignup    bool
}

func (s *ExternalIdpService) upsertEnvProvider(ctx context.Context, ep envProvider) error {
	var existing model.ExternalIdpProvider
	err := s.db.WithContext(ctx).Where("slug = ?", ep.Slug).First(&existing).Error
	now := datatype.DateTime(time.Now())

	if errors.Is(err, gorm.ErrRecordNotFound) {
		provider := model.ExternalIdpProvider{
			Slug:           ep.Slug,
			Name:           ep.Name,
			ClientID:       ep.ClientID,
			ClientSecret:   datatype.EncryptedString(ep.ClientSecret),
			IssuerURL:      strings.TrimRight(ep.IssuerURL, "/"),
			Scopes:         normalizeScopes(ep.Scopes),
			Enabled:        true,
			AllowLogin:     true,
			AllowSignup:    ep.AllowSignup,
			AllowedDomains: ep.AllowedDomains,
			ManagedByEnv:   true,
		}
		return s.db.WithContext(ctx).Create(&provider).Error
	}
	if err != nil {
		return err
	}

	existing.Name = ep.Name
	existing.ClientID = ep.ClientID
	existing.ClientSecret = datatype.EncryptedString(ep.ClientSecret)
	existing.IssuerURL = strings.TrimRight(ep.IssuerURL, "/")
	existing.Scopes = normalizeScopes(ep.Scopes)
	existing.Enabled = true
	existing.AllowLogin = true
	existing.AllowSignup = ep.AllowSignup
	existing.AllowedDomains = ep.AllowedDomains
	existing.ManagedByEnv = true
	existing.UpdatedAt = &now
	return s.db.WithContext(ctx).Save(&existing).Error
}

// ---------------------------------------------------------------------------
// OAuth / OIDC helpers
// ---------------------------------------------------------------------------

func (s *ExternalIdpService) oauthConfig(provider model.ExternalIdpProvider, disc oidcDiscovery) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret.String(),
		RedirectURL:  s.callbackURL(provider.Slug),
		Scopes:       provider.ScopeList(),
		Endpoint: oauth2.Endpoint{
			AuthURL:  disc.AuthorizationEndpoint,
			TokenURL: disc.TokenEndpoint,
		},
	}
}

func (s *ExternalIdpService) callbackURL(slug string) string {
	return strings.TrimRight(common.EnvConfig.AppURL, "/") + "/api/external-idp/callback/" + slug
}

func (s *ExternalIdpService) discover(ctx context.Context, issuer string) (oidcDiscovery, error) {
	s.discoveryMu.RLock()
	if d, ok := s.discoveryCache[issuer]; ok {
		s.discoveryMu.RUnlock()
		return d, nil
	}
	s.discoveryMu.RUnlock()

	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return oidcDiscovery{}, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}
	var disc oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&disc); err != nil {
		return oidcDiscovery{}, fmt.Errorf("failed to parse OIDC discovery document: %w", err)
	}
	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery document is missing required endpoints")
	}

	s.discoveryMu.Lock()
	s.discoveryCache[issuer] = disc
	s.discoveryMu.Unlock()
	return disc, nil
}

func (s *ExternalIdpService) fetchUserInfo(ctx context.Context, endpoint string, token *oauth2.Token) (externalUserInfo, error) {
	if endpoint == "" {
		return externalUserInfo{}, fmt.Errorf("provider has no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return externalUserInfo{}, err
	}
	token.SetAuthHeader(req)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return externalUserInfo{}, fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return externalUserInfo{}, fmt.Errorf("userinfo endpoint returned status %d", resp.StatusCode)
	}
	var info externalUserInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return externalUserInfo{}, fmt.Errorf("failed to parse userinfo: %w", err)
	}
	return info, nil
}

func normalizeScopes(scopes string) string {
	fields := strings.Fields(scopes)
	if len(fields) == 0 {
		return "openid profile email"
	}
	hasOpenID := false
	for _, f := range fields {
		if f == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		fields = append([]string{"openid"}, fields...)
	}
	return strings.Join(fields, " ")
}

func getEnv(key string) string { return strings.TrimSpace(os.Getenv(key)) }

func envBool(key string, def bool) bool {
	v := getEnv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func emailLocalPart(email string) string {
	if at := strings.LastIndex(email, "@"); at > 0 {
		return email[:at]
	}
	return email
}

// sanitizeUsername coerces an arbitrary string into the username charset
// (^[a-zA-Z0-9]([a-zA-Z0-9_.@-]*[a-zA-Z0-9])?$), lower-cased.
func sanitizeUsername(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('.')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "._-")
	}
	return out
}
