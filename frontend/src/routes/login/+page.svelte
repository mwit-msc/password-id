<script lang="ts">
	import { page } from '$app/state';
	import SignInWrapper from '$lib/components/login-wrapper.svelte';
	import { m } from '$lib/paraglide/messages';
	import appConfigStore from '$lib/stores/application-configuration-store';
	import { deferToast } from '$lib/utils/toast.util';
	import { onMount } from 'svelte';
	import ExternalProviders from './components/external-providers.svelte';
	import PasskeyLogin from './components/passkey-login.svelte';
	import PasswordLogin from './components/password-login.svelte';

	let { data } = $props();

	const passwordAvailable = $derived($appConfigStore.passwordAuthEnabled);
	// Primary method comes from config, but only matters when password auth is enabled.
	const primaryIsPassword = $derived(
		passwordAvailable && $appConfigStore.loginPrimaryMethod === 'password'
	);

	let showPassword = $state(false);
	$effect(() => {
		showPassword = primaryIsPassword;
	});

	onMount(() => {
		const err = page.url.searchParams.get('externalError');
		if (err) {
			deferToast((t) => t.error(externalErrorMessage(err)));
		}
	});

	function externalErrorMessage(code: string): string {
		switch (code) {
			case 'no_account':
				return m.external_no_account();
			case 'email_not_allowed':
				return m.external_email_not_allowed();
			case 'provider_disabled':
				return m.external_provider_disabled();
			case 'expired':
				return m.external_sign_in_expired();
			default:
				return m.external_sign_in_failed();
		}
	}
</script>

<svelte:head>
	<title>{m.sign_in()}</title>
</svelte:head>

<SignInWrapper showAlternativeSignInMethodButton>
	{#if showPassword}
		<PasswordLogin redirect={data.redirect} />
	{:else}
		<PasskeyLogin redirect={data.redirect} />
	{/if}

	<ExternalProviders redirect={data.redirect} />

	{#if passwordAvailable}
		<button
			type="button"
			class="text-muted-foreground mt-5 text-xs transition-colors hover:underline"
			onclick={() => (showPassword = !showPassword)}
		>
			{showPassword ? m.sign_in_with_a_passkey() : m.sign_in_with_password()}
		</button>
	{/if}
</SignInWrapper>
