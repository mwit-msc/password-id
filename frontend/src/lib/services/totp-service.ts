import APIService from './api-service';

export type TotpEnrollResponse = {
	secret: string;
	uri: string;
};

export type TotpConfirmResponse = {
	recoveryCodes: string[];
};

export default class TotpService extends APIService {
	enroll = async () => {
		const res = await this.api.post('/users/me/totp/enroll');
		return res.data as TotpEnrollResponse;
	};

	confirm = async (code: string) => {
		const res = await this.api.post('/users/me/totp/confirm', { code });
		return res.data as TotpConfirmResponse;
	};

	disable = async () => {
		await this.api.post('/users/me/totp/disable');
	};
}
