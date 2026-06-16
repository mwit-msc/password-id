package cookie

import (
	"time"

	"github.com/gin-gonic/gin"
)

func AddAccessTokenCookie(c *gin.Context, maxAgeInSeconds int, token string) {
	c.SetCookie(AccessTokenCookieName, token, maxAgeInSeconds, "/", "", true, true)
}

func AddSessionIdCookie(c *gin.Context, maxAgeInSeconds int, sessionID string) {
	c.SetCookie(SessionIdCookieName, sessionID, maxAgeInSeconds, "/", "", true, true)
}

func AddDeviceTokenCookie(c *gin.Context, deviceToken string) {
	c.SetCookie(DeviceTokenCookieName, deviceToken, int(15*time.Minute.Seconds()), "/api/one-time-access-token", "", true, true)
}

// AddMfaChallengeCookie sets the short-lived "password verified, second factor pending" cookie.
// pocket-id-password fork.
func AddMfaChallengeCookie(c *gin.Context, maxAgeInSeconds int, challengeID string) {
	c.SetCookie(MfaChallengeCookieName, challengeID, maxAgeInSeconds, "/api/password", "", true, true)
}
