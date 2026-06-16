import type { User } from '$lib/types/user.type';
import APIService from './api-service';

export type PasswordLoginResponse = {
	complete: boolean;
	mfaRequired: boolean;
	user?: User;
};

export type PasswordPolicy = {
	minLength: number;
};

export default class PasswordService extends APIService {
	login = async (identifier: string, password: string) => {
		const res = await this.api.post('/password/login', { identifier, password });
		return res.data as PasswordLoginResponse;
	};

	loginTotp = async (code: string) => {
		const res = await this.api.post('/password/login/totp', { code });
		return res.data as PasswordLoginResponse;
	};

	policy = async () => {
		const res = await this.api.get('/password/policy');
		return res.data as PasswordPolicy;
	};

	requestReset = async (email: string) => {
		await this.api.post('/password/reset-request', { email });
	};

	reset = async (token: string, newPassword: string) => {
		await this.api.post('/password/reset', { token, newPassword });
	};

	change = async (currentPassword: string, newPassword: string) => {
		await this.api.post('/password/change', { currentPassword, newPassword });
	};

	adminSet = async (userId: string, password: string) => {
		await this.api.post(`/password/admin/${userId}/set`, { password });
	};

	adminInvite = async (userId: string) => {
		await this.api.post(`/password/admin/${userId}/invite`);
	};
}
