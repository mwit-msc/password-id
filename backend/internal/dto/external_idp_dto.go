package dto

// pocket-id-password fork: DTOs for external OIDC providers (social login / linking).

import datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"

// ExternalIdpProviderPublicDto is the minimal info the login page needs to render a button.
type ExternalIdpProviderPublicDto struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// ExternalIdpProviderDto is the admin-facing view. The client secret is never returned;
// only whether one is set.
type ExternalIdpProviderDto struct {
	ID              string             `json:"id"`
	Slug            string             `json:"slug"`
	Name            string             `json:"name"`
	ClientID        string             `json:"clientId"`
	ClientSecretSet bool               `json:"clientSecretSet"`
	IssuerURL       string             `json:"issuerUrl"`
	Scopes          string             `json:"scopes"`
	Enabled         bool               `json:"enabled"`
	AllowLogin      bool               `json:"allowLogin"`
	AllowSignup     bool               `json:"allowSignup"`
	AllowedDomains  string             `json:"allowedDomains"`
	ManagedByEnv    bool               `json:"managedByEnv"`
	CreatedAt       datatype.DateTime  `json:"createdAt"`
	UpdatedAt       *datatype.DateTime `json:"updatedAt"`
}

// ExternalIdpProviderCreateDto / UpdateDto carry admin edits.
type ExternalIdpProviderCreateDto struct {
	Slug           string `json:"slug" binding:"required,client_id,min=1,max=40"`
	Name           string `json:"name" binding:"required,min=1,max=60"`
	ClientID       string `json:"clientId" binding:"required"`
	ClientSecret   string `json:"clientSecret"`
	IssuerURL      string `json:"issuerUrl" binding:"required,url"`
	Scopes         string `json:"scopes"`
	Enabled        bool   `json:"enabled"`
	AllowLogin     bool   `json:"allowLogin"`
	AllowSignup    bool   `json:"allowSignup"`
	AllowedDomains string `json:"allowedDomains"`
}

type ExternalIdpProviderUpdateDto struct {
	Name           string  `json:"name" binding:"required,min=1,max=60"`
	ClientID       string  `json:"clientId" binding:"required"`
	ClientSecret   *string `json:"clientSecret"` // nil = leave unchanged, "" = clear
	IssuerURL      string  `json:"issuerUrl" binding:"required,url"`
	Scopes         string  `json:"scopes"`
	Enabled        bool    `json:"enabled"`
	AllowLogin     bool    `json:"allowLogin"`
	AllowSignup    bool    `json:"allowSignup"`
	AllowedDomains string  `json:"allowedDomains"`
}

// UserExternalIdentityDto is shown in the user's "linked accounts" list.
type UserExternalIdentityDto struct {
	ID           string            `json:"id"`
	ProviderSlug string            `json:"providerSlug"`
	ProviderName string            `json:"providerName"`
	Email        string            `json:"email"`
	CreatedAt    datatype.DateTime `json:"createdAt"`
}
