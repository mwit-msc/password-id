package controller

// pocket-id-password fork: TOTP enrollment / confirmation / disable for the logged-in user.

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/middleware"
	"github.com/pocket-id/pocket-id/backend/internal/service"
	"golang.org/x/time/rate"
)

func NewTotpController(group *gin.RouterGroup, authMiddleware *middleware.AuthMiddleware, rateLimitMiddleware *middleware.RateLimitMiddleware, totpService *service.TotpService) {
	tc := &TotpController{totpService: totpService}

	user := authMiddleware.WithAdminNotRequired().Add()
	group.POST("/users/me/totp/enroll", user, rateLimitMiddleware.Add(rate.Every(10*time.Second), 5), tc.enrollHandler)
	group.POST("/users/me/totp/confirm", user, rateLimitMiddleware.Add(rate.Every(10*time.Second), 5), tc.confirmHandler)
	group.POST("/users/me/totp/disable", user, rateLimitMiddleware.Add(rate.Every(10*time.Second), 5), tc.disableHandler)
}

type TotpController struct {
	totpService *service.TotpService
}

func (tc *TotpController) enrollHandler(c *gin.Context) {
	userID := c.GetString("userID")
	secret, uri, err := tc.totpService.Enroll(c.Request.Context(), userID)
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.TotpEnrollResponseDto{Secret: secret, URI: uri})
}

func (tc *TotpController) confirmHandler(c *gin.Context) {
	var input dto.TotpConfirmDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}
	userID := c.GetString("userID")
	codes, err := tc.totpService.Confirm(c.Request.Context(), userID, input.Code, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		_ = c.Error(err)
		return
	}
	c.JSON(http.StatusOK, dto.TotpConfirmResponseDto{RecoveryCodes: codes})
}

func (tc *TotpController) disableHandler(c *gin.Context) {
	userID := c.GetString("userID")
	if err := tc.totpService.Disable(c.Request.Context(), userID, c.ClientIP(), c.Request.UserAgent()); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}
