package model

// pocket-id-password fork: external OIDC providers (social login / account linking).
// Pocket-ID is itself an OIDC provider; these models let it also act as a relying
// party against upstream IdPs such as Google.

import (
	"strings"

	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
)

// ExternalIdpProvider is a configured upstream OIDC provider.
type ExternalIdpProvider struct {
	Base

	Slug         string `gorm:"uniqueIndex"` // stable identifier used in callback URLs, e.g. "google"
	Name         string // display name shown on the login button
	ClientID     string
	ClientSecret datatype.EncryptedString // encrypted at rest
	IssuerURL    string                   // base issuer for OIDC discovery (.well-known/openid-configuration)
	Scopes       string                   // space-separated, default "openid profile email"
	Enabled      bool
	AllowLogin   bool // linked / matched users may sign in
	AllowSignup  bool // unknown users are auto-provisioned (subject to AllowedDomains)
	// AllowedDomains is a newline/comma-separated email-domain whitelist. When non-empty,
	// only users whose verified email is in one of these domains may log in or sign up.
	AllowedDomains string
	ManagedByEnv   bool // seeded from env vars => read-only in the admin UI

	UpdatedAt *datatype.DateTime
}

// AllowedDomainList returns the parsed, lower-cased whitelist domains (empty slice = allow any).
func (p ExternalIdpProvider) AllowedDomainList() []string {
	raw := strings.FieldsFunc(p.AllowedDomains, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == ';'
	})
	out := make([]string, 0, len(raw))
	for _, d := range raw {
		d = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(d, "@")))
		if d != "" {
			out = append(out, d)
		}
	}
	return out
}

// EmailAllowed reports whether the given email passes the domain whitelist.
func (p ExternalIdpProvider) EmailAllowed(email string) bool {
	domains := p.AllowedDomainList()
	if len(domains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	emailDomain := strings.ToLower(email[at+1:])
	for _, d := range domains {
		if emailDomain == d {
			return true
		}
	}
	return false
}

func (p ExternalIdpProvider) ScopeList() []string {
	scopes := strings.Fields(p.Scopes)
	if len(scopes) == 0 {
		return []string{"openid", "profile", "email"}
	}
	return scopes
}

// UserExternalIdentity links a local user to a subject at an external provider.
type UserExternalIdentity struct {
	Base

	UserID     string
	ProviderID string
	Subject    string // the "sub" claim at the provider
	Email      string

	UpdatedAt *datatype.DateTime

	User     User                `gorm:"foreignKey:UserID"`
	Provider ExternalIdpProvider `gorm:"foreignKey:ProviderID"`
}

// ExternalIdpAuthSession is the short-lived CSRF/PKCE state for an in-flight external login.
type ExternalIdpAuthSession struct {
	Base

	State        string `gorm:"uniqueIndex"`
	ProviderID   string
	CodeVerifier string
	Nonce        string
	RedirectURI  string  // where to send the browser after success
	Mode         string  // "login" | "link"
	UserID       *string // set for "link" mode (the signed-in user)
	ExpiresAt    datatype.DateTime
}
