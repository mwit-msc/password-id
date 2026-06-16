package cookie

import (
	"strings"

	"github.com/pocket-id/pocket-id/backend/internal/common"
)

var AccessTokenCookieName = "__Host-access_token"
var SessionIdCookieName = "__Host-session"
var DeviceTokenCookieName = "__Secure-device_token" //nolint:gosec
// pocket-id-password fork: __Secure- (not __Host-) because this cookie is path-scoped to
// /api/password; the __Host- prefix forbids a Path attribute.
var MfaChallengeCookieName = "__Secure-mfa_challenge"

func init() {
	if strings.HasPrefix(common.EnvConfig.AppURL, "http://") {
		AccessTokenCookieName = "access_token"
		SessionIdCookieName = "session"
		DeviceTokenCookieName = "device_token"
		MfaChallengeCookieName = "mfa_challenge"
	}
}
