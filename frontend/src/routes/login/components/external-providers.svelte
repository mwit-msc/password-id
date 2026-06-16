<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import { m } from '$lib/paraglide/messages';
	import ExternalIdpService from '$lib/services/external-idp-service';
	import type { ExternalIdpProviderPublic } from '$lib/types/external-idp.type';
	import { onMount } from 'svelte';

	let { redirect = '/settings' }: { redirect?: string } = $props();

	const externalIdpService = new ExternalIdpService();
	let providers: ExternalIdpProviderPublic[] = $state([]);

	onMount(async () => {
		try {
			providers = await externalIdpService.listPublic();
		} catch {
			providers = [];
		}
	});
</script>

{#if providers.length > 0}
	<div class="mt-6 flex w-full max-w-[450px] flex-col gap-3">
		<div class="flex items-center gap-3">
			<div class="bg-border h-px flex-1"></div>
			<span class="text-muted-foreground text-xs uppercase">{m.or()}</span>
			<div class="bg-border h-px flex-1"></div>
		</div>
		{#each providers as provider (provider.slug)}
			<Button
				variant="secondary"
				class="w-full"
				href={externalIdpService.loginUrl(provider.slug, redirect)}
			>
				{m.continue_with_provider({ name: provider.name })}
			</Button>
		{/each}
	</div>
{/if}
