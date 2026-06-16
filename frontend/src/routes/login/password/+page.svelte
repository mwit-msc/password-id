<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import FormInput from '$lib/components/form/form-input.svelte';
	import SignInWrapper from '$lib/components/login-wrapper.svelte';
	import { Button } from '$lib/components/ui/button';
	import { m } from '$lib/paraglide/messages';
	import PasswordService from '$lib/services/password-service';
	import appConfigStore from '$lib/stores/application-configuration-store';
	import userStore from '$lib/stores/user-store';
	import { getAxiosErrorMessage } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { fade } from 'svelte/transition';
	import { z } from 'zod/v4';
	import LoginLogoErrorSuccessIndicator from '../components/login-logo-error-success-indicator.svelte';

	let { data } = $props();

	const passwordService = new PasswordService();

	const formSchema = z.object({
		identifier: z.string().min(1),
		password: z.string().min(1)
	});
	const { inputs, ...form } = createForm(formSchema, { identifier: '', password: '' });

	let isLoading = $state(false);
	let error: string | undefined = $state(undefined);

	async function onSubmit() {
		const values = form.validate();
		if (!values) return;

		error = undefined;
		isLoading = true;
		try {
			const res = await passwordService.login(values.identifier, values.password);
			if (res.mfaRequired) {
				goto('/login/password/totp' + page.url.search);
				return;
			}
			if (res.complete && res.user) {
				await userStore.setUser(res.user);
				goto(data.redirect || '/settings');
				return;
			}
		} catch (e) {
			error = getAxiosErrorMessage(e);
		}
		isLoading = false;
	}
</script>

<svelte:head>
	<title>{m.sign_in()}</title>
</svelte:head>

<SignInWrapper>
	<div class="flex justify-center">
		<LoginLogoErrorSuccessIndicator error={!!error} />
	</div>
	<h1 class="font-gloock mt-5 text-3xl font-bold sm:text-4xl">
		{m.sign_in_to_appname({ appName: $appConfigStore.appName })}
	</h1>
	{#if error}
		<p class="text-muted-foreground mt-2" in:fade>
			{error}. {m.please_try_again()}
		</p>
	{:else}
		<p class="text-muted-foreground mt-2" in:fade>
			{m.sign_in_with_your_username_and_password()}
		</p>
	{/if}
	<form onsubmit={preventDefault(onSubmit)} class="mt-7 w-full max-w-[450px] space-y-4">
		<FormInput
			label={m.username_or_email()}
			bind:input={$inputs.identifier}
			placeholder={m.username_or_email()}
		/>
		<FormInput label={m.password()} type="password" bind:input={$inputs.password} />
		<div class="flex justify-end">
			<a
				class="text-muted-foreground text-xs transition-colors hover:underline"
				href="/reset-password"
			>
				{m.forgot_your_password()}
			</a>
		</div>
		<div class="flex justify-between gap-2">
			<Button variant="secondary" class="flex-1" href={'/login' + page.url.search}>
				{m.go_back()}
			</Button>
			<Button class="flex-1" type="submit" {isLoading}>
				{error ? m.try_again() : m.sign_in()}
			</Button>
		</div>
	</form>
</SignInWrapper>
