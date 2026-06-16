import ExternalIdpService from '$lib/services/external-idp-service';
import type { PageLoad } from './$types';

export const load: PageLoad = async () => {
	const externalIdpService = new ExternalIdpService();
	const providers = await externalIdpService.listAll().catch(() => []);
	return { providers };
};
