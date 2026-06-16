import PasswordService from '$lib/services/password-service';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ url }) => {
	const passwordService = new PasswordService();
	const policy = await passwordService.policy().catch(() => ({ minLength: 8 }));

	return {
		token: url.searchParams.get('token') || '',
		minLength: policy.minLength
	};
};
