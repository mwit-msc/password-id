<script lang="ts">
	import SignInWrapper from '$lib/components/login-wrapper.svelte';
	import { Button } from '$lib/components/ui/button';
	import Input from '$lib/components/ui/input/input.svelte';
	import { m } from '$lib/paraglide/messages';
	import PasswordService from '$lib/services/password-service';
	import { getAxiosErrorMessage } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { fade } from 'svelte/transition';
	import LoginLogoErrorSuccessIndicator from '../login/components/login-logo-error-success-indicator.svelte';

	const passwordService = new PasswordService();

	let email = $state('');
	let isLoading = $state(false);
	let error: string | undefined = $state(undefined);
	let success = $state(false);

	async function requestReset() {
		isLoading = true;
		try {
			await passwordService.requestReset(email);
			success = true;
		} catch (e) {
			error = getAxiosErrorMessage(e);
		}
		isLoading = false;
	}
</script>

<svelte:head>
	<title>{m.reset_password()}</title>
</svelte:head>

<SignInWrapper>
	<div class="flex justify-center">
		<LoginLogoErrorSuccessIndicator {success} error={!!error} />
	</div>
	<h1 class="font-gloock mt-5 text-3xl font-bold sm:text-4xl">{m.reset_password()}</h1>
	{#if error}
		<p class="text-muted-foreground mt-2" in:fade>
			{error}. {m.please_try_again()}
		</p>
		<div class="mt-10 flex justify-between gap-2">
			<Button variant="secondary" class="flex-1" href="/login/password">{m.go_back()}</Button>
			<Button class="flex-1" onclick={() => (error = undefined)}>{m.try_again()}</Button>
		</div>
	{:else if success}
		<p class="text-muted-foreground mt-2" in:fade>
			{m.if_that_email_exists_a_password_reset_link_has_been_sent()}
		</p>
		<div class="mt-8 flex justify-center">
			<Button variant="secondary" class="flex-1" href="/login/password">{m.go_back()}</Button>
		</div>
	{:else}
		<form onsubmit={preventDefault(requestReset)} class="w-full max-w-[450px]">
			<p class="text-muted-foreground mt-2" in:fade>
				{m.enter_your_email_address_to_receive_a_password_reset_link()}
			</p>
			<Input
				id="Email"
				class="mt-7"
				placeholder={m.your_email()}
				aria-label={m.email()}
				bind:value={email}
				type="email"
			/>
			<div class="mt-8 flex justify-between gap-2">
				<Button variant="secondary" class="flex-1" href="/login/password">{m.go_back()}</Button>
				<Button class="flex-1" type="submit" {isLoading}>{m.submit()}</Button>
			</div>
		</form>
	{/if}
</SignInWrapper>
