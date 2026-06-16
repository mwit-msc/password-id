package crypto

// pocket-id-password fork: Argon2id password hashing.
// Passwords are HASHED (never encrypted) using Argon2id with memory-hard parameters.
// Hashes are stored as PHC-encoded strings, e.g.:
//   $argon2id$v=19$m=65536,t=3,p=2$<b64salt>$<b64hash>

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2idParams controls the cost of password hashing. Defaults follow the
// OWASP Password Storage Cheat Sheet baseline (m=64MiB, t=3, p=2).
type Argon2idParams struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2idParams returns sane, memory-hard defaults.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Memory:      64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

var (
	// ErrInvalidPasswordHash is returned when a stored hash cannot be parsed.
	ErrInvalidPasswordHash = errors.New("invalid password hash")
	// ErrIncompatibleArgon2Version is returned for an unexpected argon2 version.
	ErrIncompatibleArgon2Version = errors.New("incompatible argon2 version")
)

// HashPassword hashes a plaintext password using Argon2id and returns a PHC-encoded string.
func HashPassword(password string, params Argon2idParams) (string, error) {
	salt := make([]byte, params.SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt, b64Hash)
	return encoded, nil
}

// VerifyPassword compares a plaintext password against a PHC-encoded Argon2id hash
// in constant time. Returns true on match.
func VerifyPassword(password, encodedHash string) (bool, error) {
	params, salt, hash, err := decodeArgon2idHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	if len(hash) != len(otherHash) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// dummyHash is a precomputed-shape Argon2id hash used to keep verification timing
// constant for non-existent users (mitigates user enumeration via timing).
const dummyHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"

// DummyVerify performs an Argon2id computation against a fixed hash to equalize timing
// when no user/hash is present. The boolean result is always false; callers ignore it.
func DummyVerify(password string) {
	//nolint:errcheck
	_, _ = VerifyPassword(password, dummyHash)
}

func decodeArgon2idHash(encodedHash string) (params Argon2idParams, salt, hash []byte, err error) {
	parts := strings.Split(encodedHash, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", "<salt>", "<hash>"]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return params, nil, nil, ErrInvalidPasswordHash
	}

	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return params, nil, nil, ErrInvalidPasswordHash
	}
	if version != argon2.Version {
		return params, nil, nil, ErrIncompatibleArgon2Version
	}

	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return params, nil, nil, ErrInvalidPasswordHash
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return params, nil, nil, ErrInvalidPasswordHash
	}
	params.SaltLength = uint32(len(salt)) //nolint:gosec // salt length is small and bounded

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params, nil, nil, ErrInvalidPasswordHash
	}
	params.KeyLength = uint32(len(hash)) //nolint:gosec // key length is small and bounded

	return params, salt, hash, nil
}
