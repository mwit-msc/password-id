<script lang="ts">
	import { goto } from '$app/navigation';
	import FormInput from '$lib/components/form/form-input.svelte';
	import SignInWrapper from '$lib/components/login-wrapper.svelte';
	import { Button } from '$lib/components/ui/button';
	import { m } from '$lib/paraglide/messages';
	import PasswordService from '$lib/services/password-service';
	import { getAxiosErrorMessage } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { fade } from 'svelte/transition';
	import { z } from 'zod/v4';
	import LoginLogoErrorSuccessIndicator from '../login/components/login-logo-error-success-indicator.svelte';

	let { data } = $props();

	const passwordService = new PasswordService();

	const formSchema = z
		.object({
			newPassword: z
				.string()
				.min(data.minLength, m.password_must_be_at_least_n_characters({ n: data.minLength })),
			confirmPassword: z.string().min(1)
		})
		.refine((d) => d.newPassword === d.confirmPassword, {
			message: m.passwords_do_not_match(),
			path: ['confirmPassword']
		});
	const { inputs, ...form } = createForm(formSchema, { newPassword: '', confirmPassword: '' });

	let isLoading = $state(false);
	let error: string | undefined = $state(undefined);

	async function onSubmit() {
		const values = form.validate();
		if (!values) return;

		error = undefined;
		isLoading = true;
		try {
			await passwordService.reset(data.token, values.newPassword);
			goto('/login/password');
			return;
		} catch (e) {
			error = getAxiosErrorMessage(e);
		}
		isLoading = false;
	}
</script>

<svelte:head>
	<title>{m.set_password()}</title>
</svelte:head>

<SignInWrapper>
	<div class="flex justify-center">
		<LoginLogoErrorSuccessIndicator error={!!error} />
	</div>
	<h1 class="font-gloock mt-5 text-3xl font-bold sm:text-4xl">{m.set_password()}</h1>
	{#if !data.token}
		<p class="text-muted-foreground mt-2" in:fade>
			{m.this_password_reset_link_is_invalid_or_has_expired()}
		</p>
		<div class="mt-10 flex justify-center">
			<Button class="flex-1" href="/login/password">{m.go_back()}</Button>
		</div>
	{:else}
		{#if error}
			<p class="text-muted-foreground mt-2" in:fade>
				{error}. {m.please_try_again()}
			</p>
		{:else}
			<p class="text-muted-foreground mt-2" in:fade>
				{m.choose_a_new_password_for_your_account()}
			</p>
		{/if}
		<form onsubmit={preventDefault(onSubmit)} class="mt-7 w-full max-w-[450px] space-y-4">
			<FormInput label={m.new_password()} type="password" bind:input={$inputs.newPassword} />
			<FormInput
				label={m.confirm_password()}
				type="password"
				bind:input={$inputs.confirmPassword}
			/>
			<div class="flex justify-end">
				<Button class="flex-1" type="submit" {isLoading}>{m.save()}</Button>
			</div>
		</form>
	{/if}
</SignInWrapper>
