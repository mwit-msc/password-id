package controller

// pocket-id-password fork: HTTP surface for external OIDC providers (social login + linking)
// and the admin CRUD for configuring them.

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/middleware"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	"github.com/pocket-id/pocket-id/backend/internal/service"
	"github.com/pocket-id/pocket-id/backend/internal/utils/cookie"
	"golang.org/x/time/rate"
)

func NewExternalIdpController(group *gin.RouterGroup, authMiddleware *middleware.AuthMiddleware, rateLimitMiddleware *middleware.RateLimitMiddleware, externalIdpService *service.ExternalIdpService, appConfigService *service.AppConfigService) {
	ec := &ExternalIdpController{externalIdpService: externalIdpService, appConfigService: appConfigService}

	// Public / login
	group.GET("/external-idp/providers", ec.listPublicProvidersHandler)
	group.GET("/external-idp/login/:slug", rateLimitMiddleware.Add(rate.Every(time.Second), 10), ec.beginLoginHandler)
	group.GET("/external-idp/callback/:slug", rateLimitMiddleware.Add(rate.Every(time.Second), 10), ec.callbackHandler)

	// Authenticated user
	group.GET("/external-idp/link/:slug", authMiddleware.WithAdminNotRequired().Add(), ec.beginLinkHandler)
	group.GET("/external-idp/identities", authMiddleware.WithAdminNotRequired().Add(), ec.listIdentitiesHandler)
	group.DELETE("/external-idp/identities/:id", authMiddleware.WithAdminNotRequired().Add(), ec.unlinkHandler)

	// Admin
	group.GET("/external-idp/admin/providers", authMiddleware.Add(), ec.adminListHandler)
	group.POST("/external-idp/admin/providers", authMiddleware.Add(), ec.adminCreateHandler)
	group.PUT("/external-idp/admin/providers/:id", authMiddleware.Add(), ec.adminUpdateHandler)
	group.DELETE("/external-idp/admin/providers/:id", authMiddleware.Add(), ec.adminDeleteHandler)
}

type ExternalIdpController struct {
	externalIdpService *service.ExternalIdpService
	appConfigService   *service.AppConfigService
}

func (ec *ExternalIdpController) accessCookieMaxAge() int {
	return int(ec.appConfigService.GetDbConfig().SessionDuration.AsDurationMinutes().Seconds())
}

// safeInternalPath ensures a redirect target is a local path, preventing open redirects.
func safeInternalPath(raw, fallback string) string {
	if raw == "" {
		return fallback
	}
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return fallback
	}
	return raw
}

func (ec *ExternalIdpController) listPublicProvidersHandler(c *gin.Context) {
	providers, err := ec.externalIdpService.ListPublicProviders(c.Request.Context())
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, providers)
}

func (ec *ExternalIdpController) beginLoginHandler(c *gin.Context) {
	slug := c.Param("slug")
	redirect := safeInternalPath(c.Query("redirect"), "/settings")
	authURL, err := ec.externalIdpService.BeginAuth(c.Request.Context(), slug, "login", redirect, nil)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

func (ec *ExternalIdpController) beginLinkHandler(c *gin.Context) {
	slug := c.Param("slug")
	userID := c.GetString("userID")
	redirect := safeInternalPath(c.Query("redirect"), "/settings/account")
	authURL, err := ec.externalIdpService.BeginAuth(c.Request.Context(), slug, "link", redirect, &userID)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

// callbackHandler always redirects the browser back into the SPA (it is reached via a
// full-page navigation from the provider, so JSON errors would be useless here).
func (ec *ExternalIdpController) callbackHandler(c *gin.Context) {
	slug := c.Param("slug")
	state := c.Query("state")
	code := c.Query("code")

	if providerErr := c.Query("error"); providerErr != "" {
		c.Redirect(http.StatusFound, "/login?externalError="+url.QueryEscape(providerErr))
		return
	}
	if state == "" || code == "" {
		c.Redirect(http.StatusFound, "/login?externalError=invalid_request")
		return
	}

	result, err := ec.externalIdpService.CompleteAuth(c.Request.Context(), slug, state, code, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		c.Redirect(http.StatusFound, "/login?externalError="+url.QueryEscape(externalErrorCode(err)))
		return
	}

	if result.Mode == "link" {
		c.Redirect(http.StatusFound, safeInternalPath(result.RedirectURI, "/settings/account")+"?linked="+url.QueryEscape(slug))
		return
	}

	cookie.AddAccessTokenCookie(c, ec.accessCookieMaxAge(), result.AccessToken)
	c.Redirect(http.StatusFound, safeInternalPath(result.RedirectURI, "/settings"))
}

func (ec *ExternalIdpController) listIdentitiesHandler(c *gin.Context) {
	identities, err := ec.externalIdpService.GetUserIdentities(c.Request.Context(), c.GetString("userID"))
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, identities)
}

func (ec *ExternalIdpController) unlinkHandler(c *gin.Context) {
	err := ec.externalIdpService.Unlink(c.Request.Context(), c.GetString("userID"), c.Param("id"), c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

// --- Admin ---

func (ec *ExternalIdpController) adminListHandler(c *gin.Context) {
	providers, err := ec.externalIdpService.ListProviders(c.Request.Context(), false)
	if err != nil {
		_ = c.Error(err)
		return
	}
	out := make([]dto.ExternalIdpProviderDto, 0, len(providers))
	for _, p := range providers {
		out = append(out, mapProviderDto(p))
	}
	c.JSON(http.StatusOK, out)
}

func (ec *ExternalIdpController) adminCreateHandler(c *gin.Context) {
	var input dto.ExternalIdpProviderCreateDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}
	provider, err := ec.externalIdpService.CreateProvider(c.Request.Context(), input)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusCreated, mapProviderDto(provider))
}

func (ec *ExternalIdpController) adminUpdateHandler(c *gin.Context) {
	var input dto.ExternalIdpProviderUpdateDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}
	provider, err := ec.externalIdpService.UpdateProvider(c.Request.Context(), c.Param("id"), input)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, mapProviderDto(provider))
}

func (ec *ExternalIdpController) adminDeleteHandler(c *gin.Context) {
	if err := ec.externalIdpService.DeleteProvider(c.Request.Context(), c.Param("id")); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func mapProviderDto(p model.ExternalIdpProvider) dto.ExternalIdpProviderDto {
	return dto.ExternalIdpProviderDto{
		ID:              p.ID,
		Slug:            p.Slug,
		Name:            p.Name,
		ClientID:        p.ClientID,
		ClientSecretSet: p.ClientSecret.String() != "",
		IssuerURL:       p.IssuerURL,
		Scopes:          p.Scopes,
		Enabled:         p.Enabled,
		AllowLogin:      p.AllowLogin,
		AllowSignup:     p.AllowSignup,
		AllowedDomains:  p.AllowedDomains,
		ManagedByEnv:    p.ManagedByEnv,
		CreatedAt:       p.CreatedAt,
		UpdatedAt:       p.UpdatedAt,
	}
}

// externalErrorCode maps service errors to short codes the login page can translate.
func externalErrorCode(err error) string {
	switch {
	case isErr(err, "no account"):
		return "no_account"
	case isErr(err, "not allowed"):
		return "email_not_allowed"
	case isErr(err, "disabled"):
		return "provider_disabled"
	case isErr(err, "invalid or has expired"):
		return "expired"
	default:
		return "failed"
	}
}

func isErr(err error, substr string) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), substr)
}
