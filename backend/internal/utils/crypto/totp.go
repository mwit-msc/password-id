package crypto

// pocket-id-password fork: RFC 6238 TOTP (Time-based One-Time Password), stdlib-only.
// Avoids a third-party dependency. SHA-1, 6 digits, 30s period (the values every
// authenticator app defaults to). Verified against RFC 6238 Appendix B test vectors.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by RFC 6238 / authenticator-app compatibility
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30 * time.Second
	// totpSkewSteps allows codes from N periods before/after now (clock drift tolerance).
	totpSkewSteps = 1
	totpSecretLen = 20 // 160 bits, RFC 4226 recommended
)

// GenerateTotpSecret returns a new random base32-encoded (no padding) TOTP secret.
func GenerateTotpSecret() (string, error) {
	secret := make([]byte, totpSecretLen)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// TotpURI builds an otpauth:// provisioning URI for QR-code enrollment.
func TotpURI(secret, issuer, accountName string) string {
	label := url.PathEscape(issuer + ":" + accountName)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// generateCode computes the TOTP code for a given counter (time step).
func generateCode(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("invalid TOTP secret: %w", err)
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	sum := mac.Sum(nil)

	// Dynamic truncation (RFC 4226 §5.3)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, value%mod), nil
}

// GenerateCodeAt returns the TOTP code valid at the given time. Primarily useful for
// tooling and tests; normal verification should use VerifyTotp (which tolerates skew).
func GenerateCodeAt(secret string, at time.Time) (string, error) {
	counter := uint64(at.Unix() / int64(totpPeriod.Seconds())) //nolint:gosec // unix time is positive
	return generateCode(secret, counter)
}

// VerifyTotp checks a user-supplied code against the secret at the given time,
// tolerating ±totpSkewSteps of clock drift. Comparison is constant-time.
func VerifyTotp(secret, code string, at time.Time) bool {
	ok, _ := VerifyTotpWithStep(secret, code, at)
	return ok
}

// VerifyTotpWithStep is like VerifyTotp but also returns the matched time-step (counter).
// Callers enforce single-use by rejecting a code whose step is not strictly greater than
// the last accepted step (RFC 6238 §5.2).
func VerifyTotpWithStep(secret, code string, at time.Time) (ok bool, step uint64) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false, 0
	}
	counter := uint64(at.Unix() / int64(totpPeriod.Seconds())) //nolint:gosec // unix time is positive
	for i := -totpSkewSteps; i <= totpSkewSteps; i++ {
		candidate := counter + uint64(int64(i))
		expected, err := generateCode(secret, candidate)
		if err != nil {
			return false, 0
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return true, candidate
		}
	}
	return false, 0
}
