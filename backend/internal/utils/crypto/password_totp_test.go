package crypto

import (
	"testing"
	"time"
)

func TestArgon2idHashVerify(t *testing.T) {
	params := DefaultArgon2idParams()
	hash, err := HashPassword("correct horse battery staple", params)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatal("expected password to verify")
	}

	ok, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword(wrong): %v", err)
	}
	if ok {
		t.Fatal("expected wrong password to fail")
	}
}

func TestArgon2idUniqueSalt(t *testing.T) {
	params := DefaultArgon2idParams()
	h1, _ := HashPassword("same", params)
	h2, _ := HashPassword("same", params)
	if h1 == h2 {
		t.Fatal("expected different hashes due to random salt")
	}
}

func TestVerifyPasswordInvalidHash(t *testing.T) {
	if _, err := VerifyPassword("x", "not-a-hash"); err == nil {
		t.Fatal("expected error for malformed hash")
	}
}

func TestDummyVerifyDoesNotPanic(t *testing.T) {
	DummyVerify("anything") // must not panic; result discarded
}

// TestTotpRFC6238 validates against RFC 6238 Appendix B test vectors (SHA-1),
// truncated to our 6-digit configuration.
func TestTotpRFC6238(t *testing.T) {
	// RFC 6238 SHA-1 seed "12345678901234567890" base32-encoded (no padding).
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" //nolint:gosec // RFC 6238 test vector, not a credential

	cases := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}

	for _, tc := range cases {
		at := time.Unix(tc.unix, 0).UTC()
		if !VerifyTotp(secret, tc.code, at) {
			t.Errorf("RFC6238 vector failed: t=%d expected code %s to verify", tc.unix, tc.code)
		}
		if VerifyTotp(secret, "000000", at) && tc.code != "000000" {
			t.Errorf("RFC6238 t=%d: wrong code unexpectedly verified", tc.unix)
		}
	}
}

func TestTotpSkewWindow(t *testing.T) {
	secret, err := GenerateTotpSecret()
	if err != nil {
		t.Fatalf("GenerateTotpSecret: %v", err)
	}
	now := time.Unix(1700000000, 0)
	code, err := generateCode(secret, uint64(now.Unix()/30)) //nolint:gosec // unix time is positive
	if err != nil {
		t.Fatalf("generateCode: %v", err)
	}
	// Code from the current step must verify within +/-1 step around it.
	if !VerifyTotp(secret, code, now.Add(30*time.Second)) {
		t.Error("expected code to verify one step later (skew tolerance)")
	}
	if VerifyTotp(secret, code, now.Add(5*time.Minute)) {
		t.Error("expected code to fail far outside skew window")
	}
}

func TestTokenHashStableAndComparable(t *testing.T) {
	a := HashToken("some-token")
	b := HashToken("some-token")
	if a != b {
		t.Fatal("HashToken not deterministic")
	}
	if !ConstantTimeEqualHash(a, b) {
		t.Fatal("expected equal hashes to compare equal")
	}
	if ConstantTimeEqualHash(a, HashToken("other")) {
		t.Fatal("expected different tokens to differ")
	}
}
