package controller

// pocket-id-password fork: HTTP surface for password login (+ TOTP second factor),
// self-service change, and email reset / admin invite.

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pocket-id/pocket-id/backend/internal/common"
	"github.com/pocket-id/pocket-id/backend/internal/dto"
	"github.com/pocket-id/pocket-id/backend/internal/middleware"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	"github.com/pocket-id/pocket-id/backend/internal/service"
	"github.com/pocket-id/pocket-id/backend/internal/utils/cookie"
	"golang.org/x/time/rate"
)

func NewPasswordController(group *gin.RouterGroup, authMiddleware *middleware.AuthMiddleware, rateLimitMiddleware *middleware.RateLimitMiddleware, passwordService *service.PasswordService, appConfigService *service.AppConfigService) {
	pc := &PasswordController{passwordService: passwordService, appConfigService: appConfigService}

	group.POST("/password/login", rateLimitMiddleware.Add(rate.Every(10*time.Second), 5), pc.loginHandler)
	group.POST("/password/login/totp", rateLimitMiddleware.Add(rate.Every(10*time.Second), 5), pc.loginTotpHandler)
	group.GET("/password/policy", pc.policyHandler)
	group.POST("/password/reset-request", rateLimitMiddleware.Add(rate.Every(10*time.Minute), 3), pc.resetRequestHandler)
	group.POST("/password/reset", rateLimitMiddleware.Add(rate.Every(10*time.Second), 5), pc.resetHandler)

	group.POST("/password/change", authMiddleware.WithAdminNotRequired().Add(), rateLimitMiddleware.Add(rate.Every(10*time.Second), 5), pc.changeHandler)

	group.POST("/password/admin/:id/set", authMiddleware.Add(), pc.adminSetHandler)
	group.POST("/password/admin/:id/invite", authMiddleware.Add(), pc.adminInviteHandler)
}

type PasswordController struct {
	passwordService  *service.PasswordService
	appConfigService *service.AppConfigService
}

func mapUserDto(user model.User) (*dto.UserDto, error) {
	var userDto dto.UserDto
	if err := dto.MapStruct(user, &userDto); err != nil {
		return nil, err
	}
	return &userDto, nil
}

func (pc *PasswordController) accessCookieMaxAge() int {
	return int(pc.appConfigService.GetDbConfig().SessionDuration.AsDurationMinutes().Seconds())
}

func (pc *PasswordController) loginHandler(c *gin.Context) {
	var input dto.PasswordLoginDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}

	result, err := pc.passwordService.Login(c.Request.Context(), input.Identifier, input.Password, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		_ = c.Error(err)
		return
	}

	if result.MfaChallenge != "" {
		cookie.AddMfaChallengeCookie(c, int((5 * time.Minute).Seconds()), result.MfaChallenge)
		c.JSON(http.StatusOK, dto.PasswordLoginResponseDto{MfaRequired: true})
		return
	}

	userDto, err := mapUserDto(result.User)
	if err != nil {
		_ = c.Error(err)
		return
	}
	cookie.AddAccessTokenCookie(c, pc.accessCookieMaxAge(), result.AccessToken)
	c.JSON(http.StatusOK, dto.PasswordLoginResponseDto{Complete: true, User: userDto})
}

func (pc *PasswordController) loginTotpHandler(c *gin.Context) {
	challengeID, err := c.Cookie(cookie.MfaChallengeCookieName)
	if err != nil || challengeID == "" {
		_ = c.Error(&common.MfaInvalidError{})
		return
	}

	var input dto.PasswordMfaDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}

	user, token, err := pc.passwordService.VerifyMfa(c.Request.Context(), challengeID, input.Code, c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		_ = c.Error(err)
		return
	}

	userDto, err := mapUserDto(user)
	if err != nil {
		_ = c.Error(err)
		return
	}

	// Clear the challenge cookie and set the real session.
	cookie.AddMfaChallengeCookie(c, -1, "")
	cookie.AddAccessTokenCookie(c, pc.accessCookieMaxAge(), token)
	c.JSON(http.StatusOK, dto.PasswordLoginResponseDto{Complete: true, User: userDto})
}

func (pc *PasswordController) policyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, dto.PasswordPolicyDto{MinLength: pc.passwordService.PasswordPolicy()})
}

func (pc *PasswordController) changeHandler(c *gin.Context) {
	var input dto.ChangePasswordDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}
	userID := c.GetString("userID")
	if err := pc.passwordService.ChangePassword(c.Request.Context(), userID, input.CurrentPassword, input.NewPassword, c.ClientIP(), c.Request.UserAgent()); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (pc *PasswordController) resetRequestHandler(c *gin.Context) {
	var input dto.PasswordResetRequestDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}
	// Always returns success to avoid user enumeration.
	if err := pc.passwordService.RequestReset(c.Request.Context(), input.Email); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (pc *PasswordController) resetHandler(c *gin.Context) {
	var input dto.PasswordResetDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}
	if err := pc.passwordService.ConsumeReset(c.Request.Context(), input.Token, input.NewPassword, c.ClientIP(), c.Request.UserAgent()); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (pc *PasswordController) adminSetHandler(c *gin.Context) {
	var input dto.AdminSetPasswordDto
	if err := c.ShouldBindJSON(&input); err != nil {
		_ = c.Error(err)
		return
	}
	userID := c.Param("id")
	if err := pc.passwordService.AdminSetPassword(c.Request.Context(), userID, input.Password, c.ClientIP(), c.Request.UserAgent()); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (pc *PasswordController) adminInviteHandler(c *gin.Context) {
	userID := c.Param("id")
	if err := pc.passwordService.SendInvite(c.Request.Context(), userID); err != nil {
		_ = c.Error(err)
		return
	}
	c.Status(http.StatusNoContent)
}
