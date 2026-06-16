<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import FormInput from '$lib/components/form/form-input.svelte';
	import SignInWrapper from '$lib/components/login-wrapper.svelte';
	import { Button } from '$lib/components/ui/button';
	import { m } from '$lib/paraglide/messages';
	import PasswordService from '$lib/services/password-service';
	import userStore from '$lib/stores/user-store';
	import { getAxiosErrorMessage } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { fade } from 'svelte/transition';
	import { z } from 'zod/v4';
	import LoginLogoErrorSuccessIndicator from '../../components/login-logo-error-success-indicator.svelte';

	let { data } = $props();

	const passwordService = new PasswordService();

	const formSchema = z.object({
		code: z.string().min(1)
	});
	const { inputs, ...form } = createForm(formSchema, { code: '' });

	let isLoading = $state(false);
	let error: string | undefined = $state(undefined);

	async function onSubmit() {
		const values = form.validate();
		if (!values) return;

		error = undefined;
		isLoading = true;
		try {
			const res = await passwordService.loginTotp(values.code);
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
	<title>{m.two_factor_authentication()}</title>
</svelte:head>

<SignInWrapper>
	<div class="flex justify-center">
		<LoginLogoErrorSuccessIndicator error={!!error} />
	</div>
	<h1 class="font-gloock mt-5 text-3xl font-bold sm:text-4xl">
		{m.two_factor_authentication()}
	</h1>
	{#if error}
		<p class="text-muted-foreground mt-2" in:fade>
			{error}. {m.please_try_again()}
		</p>
	{:else}
		<p class="text-muted-foreground mt-2" in:fade>
			{m.enter_the_code_from_your_authenticator_app()}
		</p>
	{/if}
	<form onsubmit={preventDefault(onSubmit)} class="mt-7 w-full max-w-[450px] space-y-4">
		<FormInput label={m.authentication_code()} bind:input={$inputs.code} placeholder="123456" />
		<p class="text-muted-foreground text-start text-xs">
			{m.you_can_also_use_one_of_your_recovery_codes()}
		</p>
		<div class="flex justify-between gap-2">
			<Button variant="secondary" class="flex-1" href={'/login/password' + page.url.search}>
				{m.go_back()}
			</Button>
			<Button class="flex-1" type="submit" {isLoading}>
				{error ? m.try_again() : m.sign_in()}
			</Button>
		</div>
	</form>
</SignInWrapper>
