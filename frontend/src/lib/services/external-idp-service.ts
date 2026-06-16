import type {
	ExternalIdpProvider,
	ExternalIdpProviderInput,
	ExternalIdpProviderPublic,
	UserExternalIdentity
} from '$lib/types/external-idp.type';
import APIService from './api-service';

export default class ExternalIdpService extends APIService {
	// Public list used on the login page.
	listPublic = async () => {
		const res = await this.api.get('/external-idp/providers');
		return res.data as ExternalIdpProviderPublic[];
	};

	// Full-page navigations (these return 302 redirects to the provider).
	loginUrl = (slug: string, redirect?: string) =>
		`/api/external-idp/login/${encodeURIComponent(slug)}` +
		(redirect ? `?redirect=${encodeURIComponent(redirect)}` : '');

	linkUrl = (slug: string, redirect?: string) =>
		`/api/external-idp/link/${encodeURIComponent(slug)}` +
		(redirect ? `?redirect=${encodeURIComponent(redirect)}` : '');

	listIdentities = async () => {
		const res = await this.api.get('/external-idp/identities');
		return res.data as UserExternalIdentity[];
	};

	unlink = async (identityId: string) => {
		await this.api.delete(`/external-idp/identities/${identityId}`);
	};

	// Admin
	listAll = async () => {
		const res = await this.api.get('/external-idp/admin/providers');
		return res.data as ExternalIdpProvider[];
	};

	create = async (input: ExternalIdpProviderInput) => {
		const res = await this.api.post('/external-idp/admin/providers', input);
		return res.data as ExternalIdpProvider;
	};

	update = async (id: string, input: ExternalIdpProviderInput) => {
		const res = await this.api.put(`/external-idp/admin/providers/${id}`, input);
		return res.data as ExternalIdpProvider;
	};

	remove = async (id: string) => {
		await this.api.delete(`/external-idp/admin/providers/${id}`);
	};
}
