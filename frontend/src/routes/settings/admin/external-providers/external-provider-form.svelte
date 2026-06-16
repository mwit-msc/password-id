<script lang="ts">
	import SwitchWithLabel from '$lib/components/form/switch-with-label.svelte';
	import { Button } from '$lib/components/ui/button';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import { m } from '$lib/paraglide/messages';
	import type { ExternalIdpProvider, ExternalIdpProviderInput } from '$lib/types/external-idp.type';

	let {
		mode,
		provider,
		callback
	}: {
		mode: 'create' | 'edit';
		provider?: ExternalIdpProvider;
		callback: (input: ExternalIdpProviderInput) => Promise<boolean>;
	} = $props();

	let slug = $state(provider?.slug ?? '');
	let name = $state(provider?.name ?? '');
	let issuerUrl = $state(provider?.issuerUrl ?? '');
	let clientId = $state(provider?.clientId ?? '');
	let clientSecret = $state('');
	let scopes = $state(provider?.scopes ?? 'openid profile email');
	let allowedDomains = $state(provider?.allowedDomains ?? '');
	let enabled = $state(provider?.enabled ?? true);
	let allowLogin = $state(provider?.allowLogin ?? true);
	let allowSignup = $state(provider?.allowSignup ?? false);
	let isLoading = $state(false);

	const callbackUrl = $derived(
		slug
			? `${typeof window !== 'undefined' ? window.location.origin : ''}/api/external-idp/callback/${slug}`
			: ''
	);

	async function onSubmit(e: Event) {
		e.preventDefault();
		isLoading = true;
		const input: ExternalIdpProviderInput = {
			name,
			issuerUrl,
			clientId,
			scopes,
			allowedDomains,
			enabled,
			allowLogin,
			allowSignup
		};
		if (mode === 'create') {
			input.slug = slug;
			input.clientSecret = clientSecret;
		} else if (clientSecret) {
			// Only send the secret when the admin entered a new one.
			input.clientSecret = clientSecret;
		}
		const ok = await callback(input);
		isLoading = false;
		if (ok && mode === 'create') {
			slug = name = issuerUrl = clientId = clientSecret = allowedDomains = '';
			scopes = 'openid profile email';
		}
	}
</script>

<form onsubmit={onSubmit} class="flex flex-col gap-4">
	{#if mode === 'create'}
		<div class="flex flex-col gap-1.5">
			<Label for="slug">{m.provider_slug()}</Label>
			<Input id="slug" bind:value={slug} placeholder="google" />
			<p class="text-muted-foreground text-[0.8rem]">{m.provider_slug_description()}</p>
		</div>
	{/if}

	<div class="flex flex-col gap-1.5">
		<Label for="name">{m.provider_display_name()}</Label>
		<Input id="name" bind:value={name} placeholder="Google" />
	</div>

	<div class="flex flex-col gap-1.5">
		<Label for="issuer">{m.issuer_url()}</Label>
		<Input id="issuer" bind:value={issuerUrl} placeholder="https://accounts.google.com" />
	</div>

	<div class="grid grid-cols-1 gap-4 md:grid-cols-2">
		<div class="flex flex-col gap-1.5">
			<Label for="client-id">{m.client_id()}</Label>
			<Input id="client-id" bind:value={clientId} />
		</div>
		<div class="flex flex-col gap-1.5">
			<Label for="client-secret">{m.client_secret()}</Label>
			<Input id="client-secret" type="password" bind:value={clientSecret} />
			{#if mode === 'edit'}
				<p class="text-muted-foreground text-[0.8rem]">{m.client_secret_leave_blank()}</p>
			{/if}
		</div>
	</div>

	<div class="flex flex-col gap-1.5">
		<Label for="scopes">{m.scopes()}</Label>
		<Input id="scopes" bind:value={scopes} placeholder="openid profile email" />
	</div>

	<div class="flex flex-col gap-1.5">
		<Label for="allowed-domains">{m.allowed_email_domains()}</Label>
		<Input id="allowed-domains" bind:value={allowedDomains} placeholder="example.com, mwit.link" />
		<p class="text-muted-foreground text-[0.8rem]">{m.allowed_email_domains_description()}</p>
	</div>

	{#if callbackUrl}
		<div class="bg-muted/40 rounded-lg border p-3 text-sm">
			<p class="text-muted-foreground">{m.the_callback_url_to_configure_at_the_provider()}</p>
			<code class="break-all">{callbackUrl}</code>
		</div>
	{/if}

	<SwitchWithLabel id="enabled" label={m.provider_enabled()} bind:checked={enabled} />
	<SwitchWithLabel
		id="allow-login"
		label={m.allow_login_with_this_provider()}
		description={m.allow_login_with_this_provider_description()}
		bind:checked={allowLogin}
	/>
	<SwitchWithLabel
		id="allow-signup"
		label={m.allow_signup_with_this_provider()}
		description={m.allow_signup_with_this_provider_description()}
		bind:checked={allowSignup}
	/>

	<div class="flex justify-end">
		<Button type="submit" {isLoading}>{m.save()}</Button>
	</div>
</form>
