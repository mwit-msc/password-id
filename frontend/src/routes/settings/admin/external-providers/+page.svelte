<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Item from '$lib/components/ui/item/index.js';
	import { m } from '$lib/paraglide/messages';
	import ExternalIdpService from '$lib/services/external-idp-service';
	import type { ExternalIdpProvider, ExternalIdpProviderInput } from '$lib/types/external-idp.type';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { Globe, LucideMinus } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';
	import { slide } from 'svelte/transition';
	import ExternalProviderForm from './external-provider-form.svelte';

	let { data } = $props();

	const externalIdpService = new ExternalIdpService();

	let providers = $derived(data.providers as ExternalIdpProvider[]);
	let expandAdd = $state(false);
	let editingId: string | null = $state(null);

	async function create(input: ExternalIdpProviderInput) {
		try {
			await externalIdpService.create(input);
			toast.success(m.provider_saved_successfully());
			expandAdd = false;
			await invalidateAll();
			return true;
		} catch (e) {
			axiosErrorToast(e);
			return false;
		}
	}

	function updateFor(id: string) {
		return async (input: ExternalIdpProviderInput) => {
			try {
				await externalIdpService.update(id, input);
				toast.success(m.provider_saved_successfully());
				editingId = null;
				await invalidateAll();
				return true;
			} catch (e) {
				axiosErrorToast(e);
				return false;
			}
		};
	}

	async function remove(provider: ExternalIdpProvider) {
		if (!confirm(m.are_you_sure_you_want_to_delete_this_provider())) return;
		try {
			await externalIdpService.remove(provider.id);
			toast.success(m.provider_deleted_successfully());
			await invalidateAll();
		} catch (e) {
			axiosErrorToast(e);
		}
	}
</script>

<svelte:head>
	<title>{m.external_providers()}</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<Card.Root>
		<Card.Header>
			<div class="flex items-center justify-between">
				<div>
					<Card.Title>
						<Globe class="text-primary/80 size-5" />
						{m.external_providers()}
					</Card.Title>
					<Card.Description>{m.external_providers_description()}</Card.Description>
				</div>
				{#if !expandAdd}
					<Button onclick={() => (expandAdd = true)}>{m.add_provider()}</Button>
				{:else}
					<Button class="h-8 p-3" variant="ghost" onclick={() => (expandAdd = false)}>
						<LucideMinus class="size-5" />
					</Button>
				{/if}
			</div>
		</Card.Header>
		{#if expandAdd}
			<div transition:slide>
				<Card.Content>
					<ExternalProviderForm mode="create" callback={create} />
				</Card.Content>
			</div>
		{/if}
	</Card.Root>

	{#each providers as provider (provider.id)}
		<Card.Root>
			<Card.Content class="pt-6">
				<Item.Root variant="outline">
					<Item.Content>
						<Item.Title class="flex items-center gap-2">
							{provider.name}
							<span class="text-muted-foreground text-xs">({provider.slug})</span>
							{#if !provider.enabled}
								<span class="bg-muted text-muted-foreground rounded px-2 py-0.5 text-xs">
									{m.disabled()}
								</span>
							{/if}
						</Item.Title>
						<Item.Description>
							{provider.issuerUrl}
							{#if provider.managedByEnv}
								· {m.managed_by_environment_variables()}
							{/if}
						</Item.Description>
					</Item.Content>
					<Item.Actions>
						{#if !provider.managedByEnv}
							<Button
								variant="outline"
								onclick={() => (editingId = editingId === provider.id ? null : provider.id)}
							>
								{m.edit()}
							</Button>
							<Button variant="outline" onclick={() => remove(provider)}>{m.delete()}</Button>
						{/if}
					</Item.Actions>
				</Item.Root>

				{#if editingId === provider.id}
					<div transition:slide class="mt-4">
						<ExternalProviderForm mode="edit" {provider} callback={updateFor(provider.id)} />
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	{/each}
</div>
