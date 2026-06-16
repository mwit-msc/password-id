package common

// pocket-id-password fork: error types for the external OIDC (social login) layer.

import "net/http"

// ExternalIdpProviderNotFoundError is returned when no enabled provider matches the slug.
type ExternalIdpProviderNotFoundError struct{}

func (e ExternalIdpProviderNotFoundError) Error() string       { return "external provider not found" }
func (e ExternalIdpProviderNotFoundError) HttpStatusCode() int { return http.StatusNotFound }

// ExternalIdpDisabledError is returned when the provider exists but is disabled.
type ExternalIdpDisabledError struct{}

func (e ExternalIdpDisabledError) Error() string       { return "external provider is disabled" }
func (e ExternalIdpDisabledError) HttpStatusCode() int { return http.StatusForbidden }

// ExternalIdpStateInvalidError is returned for an unknown/expired/replayed auth state.
type ExternalIdpStateInvalidError struct{}

func (e ExternalIdpStateInvalidError) Error() string {
	return "login session is invalid or has expired"
}
func (e ExternalIdpStateInvalidError) HttpStatusCode() int { return http.StatusBadRequest }

// ExternalIdpEmailNotAllowedError is returned when the provider email fails the whitelist
// or is unverified, so the account cannot be auto-linked or created.
type ExternalIdpEmailNotAllowedError struct{}

func (e ExternalIdpEmailNotAllowedError) Error() string {
	return "this email address is not allowed to sign in with this provider"
}
func (e ExternalIdpEmailNotAllowedError) HttpStatusCode() int { return http.StatusForbidden }

// ExternalIdpNoAccountError is returned when login succeeds at the provider but no local
// account is linked and auto-signup is not permitted.
type ExternalIdpNoAccountError struct{}

func (e ExternalIdpNoAccountError) Error() string {
	return "no account is linked to this provider identity"
}
func (e ExternalIdpNoAccountError) HttpStatusCode() int { return http.StatusForbidden }

// ExternalIdpManagedByEnvError is returned when editing/deleting a provider seeded from env vars.
type ExternalIdpManagedByEnvError struct{}

func (e ExternalIdpManagedByEnvError) Error() string {
	return "this provider is managed by environment variables and cannot be changed in the UI"
}
func (e ExternalIdpManagedByEnvError) HttpStatusCode() int { return http.StatusBadRequest }

// ExternalIdpAlreadyLinkedError is returned when linking an identity already bound elsewhere.
type ExternalIdpAlreadyLinkedError struct{}

func (e ExternalIdpAlreadyLinkedError) Error() string {
	return "this provider identity is already linked to another account"
}
func (e ExternalIdpAlreadyLinkedError) HttpStatusCode() int { return http.StatusConflict }
