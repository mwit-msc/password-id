// pocket-id-password fork: E2E for username/password login.
//
// Requires the full e2e stack (the test harness's docker-compose + global setup), like
// every other spec here. Run with: `pnpm --filter pocket-id-tests test` (or
// `pnpm exec playwright test specs/password-auth.spec.ts`).
//
// Each test starts authenticated as the seeded admin (default storageState) so it can
// enable password auth and set a password via the API, then clears cookies to perform the
// actual login through the UI as an anonymous visitor.

import test, { expect } from '@playwright/test';
import { users } from '../data';
import { cleanupBackend } from '../utils/cleanup.util';

const PASSWORD = 'Sup3rSecretPassw0rd';

test.beforeEach(async () => await cleanupBackend());

/** Enable the password-auth feature flags via the admin config API. */
async function enablePasswordAuth(
	page: import('@playwright/test').Page,
	opts?: { totp?: boolean }
) {
	const res = await page.request.get('/api/application-configuration/all');
	expect(res.ok()).toBeTruthy();
	const current: Array<{ key: string; value: string }> = await res.json();

	const body: Record<string, string> = {};
	for (const v of current) body[v.key] = v.value ?? '';
	body.passwordAuthEnabled = 'true';
	body.totpEnabled = opts?.totp ? 'true' : 'false';
	body.breachCheckEnabled = 'false';

	const put = await page.request.put('/api/application-configuration', { data: body });
	expect(put.ok()).toBeTruthy();
}

/** Set a password for a user as admin. */
async function setPassword(
	page: import('@playwright/test').Page,
	userId: string,
	password: string
) {
	const res = await page.request.post(`/api/password/admin/${userId}/set`, {
		data: { password }
	});
	expect(res.status()).toBe(204);
}

test('Sign in with username and password', async ({ page }) => {
	await enablePasswordAuth(page);
	await setPassword(page, users.tim.id, PASSWORD);

	// Become anonymous, then log in through the UI.
	await page.context().clearCookies();
	await page.goto('/login/password');

	await page
		.getByLabel(/username|email/i)
		.first()
		.fill(users.tim.username);
	await page
		.getByLabel(/password/i)
		.first()
		.fill(PASSWORD);
	await page.getByRole('button', { name: /sign in|log in|continue/i }).click();

	await page.waitForURL('/settings/account');
});

test('Sign in with email and password', async ({ page }) => {
	await enablePasswordAuth(page);
	await setPassword(page, users.tim.id, PASSWORD);

	await page.context().clearCookies();
	await page.goto('/login/password');

	await page
		.getByLabel(/username|email/i)
		.first()
		.fill(users.tim.email);
	await page
		.getByLabel(/password/i)
		.first()
		.fill(PASSWORD);
	await page.getByRole('button', { name: /sign in|log in|continue/i }).click();

	await page.waitForURL('/settings/account');
});

test('Sign in fails with wrong password', async ({ page }) => {
	await enablePasswordAuth(page);
	await setPassword(page, users.tim.id, PASSWORD);

	await page.context().clearCookies();
	await page.goto('/login/password');

	await page
		.getByLabel(/username|email/i)
		.first()
		.fill(users.tim.username);
	await page
		.getByLabel(/password/i)
		.first()
		.fill('definitely-wrong');
	await page.getByRole('button', { name: /sign in|log in|continue/i }).click();

	// Generic credentials error (no user enumeration); stays on the login page.
	await expect(page.getByTestId('login-error')).toBeVisible();
	await expect(page).toHaveURL(/\/login\/password/);
});

test('Password reset request always succeeds (no user enumeration)', async ({ page }) => {
	await enablePasswordAuth(page);
	await page.context().clearCookies();

	// Unknown email must still return success-shaped (204) — never reveal existence.
	const res = await page.request.post('/api/password/reset-request', {
		data: { email: 'does-not-exist@test.com' }
	});
	expect(res.status()).toBe(204);
});
