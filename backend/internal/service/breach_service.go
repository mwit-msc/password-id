// pocket-id-password fork: optional HaveIBeenPwned k-anonymity breach check.

package service

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 is required by the HIBP k-anonymity API protocol; this is NOT password storage.
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BreachService checks passwords against the HaveIBeenPwned k-anonymity range API.
// It is fail-open: on any network or parse error it returns (false, err) so that
// the caller can decide whether to block or simply log the failure.
type BreachService struct {
	httpClient *http.Client
	baseURL    string
}

// NewBreachService returns a BreachService pointed at the live HIBP API with a
// conservative 5-second timeout.
func NewBreachService() *BreachService {
	return &BreachService{
		baseURL: "https://api.pwnedpasswords.com",
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// IsPasswordBreached returns true when the HIBP range API reports the password
// has appeared in at least one known data breach with a non-zero count.
//
// The method uses the k-anonymity model: only the first 5 hex characters of the
// SHA-1 hash are transmitted to HIBP; the full hash never leaves the caller.
//
// Fail-open behaviour: on any error (network, non-200 status, parse failure)
// the method returns (false, err). Callers should log the error and decide
// whether to proceed or surface it to the user.
func (s *BreachService) IsPasswordBreached(ctx context.Context, password string) (bool, error) {
	// Compute SHA-1 of the password (uppercase hex). SHA-1 is the hash mandated
	// by the HIBP k-anonymity protocol; it is not used for storage or verification.
	h := sha1.New() //nolint:gosec
	h.Write([]byte(password))
	fullHash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	// The k-anonymity prefix is the first 5 hex characters; the suffix is the rest.
	prefix := fullHash[:5]
	suffix := fullHash[5:]

	url := fmt.Sprintf("%s/range/%s", s.baseURL, prefix)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("breach check: build request: %w", err)
	}

	// Add-Padding ensures the response always contains a fixed number of lines so
	// that the response size does not leak information about the prefix.
	req.Header.Set("Add-Padding", "true")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("breach check: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("breach check: unexpected status %d from HIBP API", resp.StatusCode)
	}

	// Each line in the response body has the form:  SUFFIX:COUNT\r\n
	// Padding lines have a count of 0 and must be ignored per HIBP spec.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		lineSuffix := parts[0]
		countStr := strings.TrimSpace(parts[1])

		count, err := strconv.ParseInt(countStr, 10, 64)
		if err != nil {
			// Malformed line – skip rather than abort so a single bad line does not
			// cause an unnecessary fail-open.
			continue
		}

		if strings.EqualFold(lineSuffix, suffix) && count > 0 {
			return true, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("breach check: reading response body: %w", err)
	}

	return false, nil
}
