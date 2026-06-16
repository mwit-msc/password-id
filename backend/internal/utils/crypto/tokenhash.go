package crypto

// pocket-id-password fork: hashing + constant-time comparison for at-rest secret tokens
// (password-reset tokens, TOTP recovery codes). Raw tokens are high-entropy random strings,
// so a fast SHA-256 (not a password KDF) is the correct choice for lookup-by-hash.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// HashToken returns the hex-encoded SHA-256 of a token, suitable for storage and unique-index lookup.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqualHash compares two hex hash strings in constant time.
func ConstantTimeEqualHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
