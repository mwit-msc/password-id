<script lang="ts">
	import { page } from '$app/state';
	import SignInWrapper from '$lib/components/login-wrapper.svelte';
	import { Button } from '$lib/components/ui/button';
	import { m } from '$lib/paraglide/messages';
	import ExternalProviders from '../components/external-providers.svelte';
	import PasswordLogin from '../components/password-login.svelte';

	let { data } = $props();
</script>

<svelte:head>
	<title>{m.sign_in()}</title>
</svelte:head>

<SignInWrapper>
	<PasswordLogin redirect={data.redirect} />

	<ExternalProviders redirect={data.redirect} />

	<div class="mt-6 w-full max-w-[450px]">
		<Button variant="secondary" class="w-full" href={'/login' + page.url.search}>
			{m.go_back()}
		</Button>
	</div>
</SignInWrapper>
