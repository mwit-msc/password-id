export type ExternalIdpProviderPublic = {
	slug: string;
	name: string;
};

export type ExternalIdpProvider = {
	id: string;
	slug: string;
	name: string;
	clientId: string;
	clientSecretSet: boolean;
	issuerUrl: string;
	scopes: string;
	enabled: boolean;
	allowLogin: boolean;
	allowSignup: boolean;
	allowedDomains: string;
	managedByEnv: boolean;
	createdAt: string;
	updatedAt?: string;
};

export type ExternalIdpProviderInput = {
	slug?: string;
	name: string;
	clientId: string;
	clientSecret?: string;
	issuerUrl: string;
	scopes: string;
	enabled: boolean;
	allowLogin: boolean;
	allowSignup: boolean;
	allowedDomains: string;
};

export type UserExternalIdentity = {
	id: string;
	providerSlug: string;
	providerName: string;
	email: string;
	createdAt: string;
};
