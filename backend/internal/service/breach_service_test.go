// pocket-id-password fork: optional HaveIBeenPwned k-anonymity breach check.

package service

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 required by HIBP k-anonymity protocol.
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hibpHash returns the uppercase SHA-1 hex of s, split into (prefix5, suffix35).
func hibpHash(s string) (prefix, suffix string) {
	h := sha1.New() //nolint:gosec
	h.Write([]byte(s))
	full := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	return full[:5], full[5:]
}

// TestIsPasswordBreached_Breached verifies that a password whose SHA-1 suffix
// appears in the fake HIBP response with a non-zero count is flagged as breached.
func TestIsPasswordBreached_Breached(t *testing.T) {
	const testPassword = "password123"
	wantPrefix, wantSuffix := hibpHash(testPassword)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the correct 5-char prefix was sent in the path.
		gotPrefix := strings.TrimPrefix(r.URL.Path, "/range/")
		assert.Equal(t, wantPrefix, gotPrefix, "HIBP prefix in request path should match SHA-1[:5]")

		// Return the target suffix with count 42 plus some unrelated padding lines.
		body := fmt.Sprintf(
			"0000000000000000000000000000000000000:0\r\n"+
				"%s:42\r\n"+
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n",
			wantSuffix,
		)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	svc := NewBreachService()
	svc.baseURL = server.URL

	breached, err := svc.IsPasswordBreached(context.Background(), testPassword)
	require.NoError(t, err)
	assert.True(t, breached, "password123 should be detected as breached")
}

// TestIsPasswordBreached_NotBreached verifies that a password whose SHA-1 suffix
// is absent from the HIBP response is correctly reported as not breached.
func TestIsPasswordBreached_NotBreached(t *testing.T) {
	const testPassword = "veryUniquePasswordThatIsNotBreached!@#2026"
	wantPrefix, _ := hibpHash(testPassword)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrefix := strings.TrimPrefix(r.URL.Path, "/range/")
		assert.Equal(t, wantPrefix, gotPrefix, "HIBP prefix in request path should match SHA-1[:5]")

		// Response contains only padding lines (count 0), none matching the suffix.
		body := "0000000000000000000000000000000000000:0\r\n" +
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	svc := NewBreachService()
	svc.baseURL = server.URL

	breached, err := svc.IsPasswordBreached(context.Background(), testPassword)
	require.NoError(t, err)
	assert.False(t, breached, "unique password should not be flagged as breached")
}

// TestIsPasswordBreached_ServerError verifies fail-open behaviour: when the HIBP
// API returns a 500 the method returns (false, non-nil error).
func TestIsPasswordBreached_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	svc := NewBreachService()
	svc.baseURL = server.URL

	breached, err := svc.IsPasswordBreached(context.Background(), "anypassword")
	require.Error(t, err, "a 500 response should produce a non-nil error")
	assert.False(t, breached, "fail-open: breached must be false when an error occurs")
	assert.Contains(t, err.Error(), "500", "error message should reference the unexpected status code")
}
