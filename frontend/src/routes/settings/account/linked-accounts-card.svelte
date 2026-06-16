<script lang="ts">
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import * as Item from '$lib/components/ui/item/index.js';
	import { m } from '$lib/paraglide/messages';
	import ExternalIdpService from '$lib/services/external-idp-service';
	import type {
		ExternalIdpProviderPublic,
		UserExternalIdentity
	} from '$lib/types/external-idp.type';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { Link2 } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';

	const externalIdpService = new ExternalIdpService();

	let providers: ExternalIdpProviderPublic[] = $state([]);
	let identities: UserExternalIdentity[] = $state([]);
	let loaded = $state(false);

	const linkedSlugs = $derived(new Set(identities.map((i) => i.providerSlug)));
	const unlinkedProviders = $derived(providers.filter((p) => !linkedSlugs.has(p.slug)));

	onMount(async () => {
		await refresh();
		loaded = true;
	});

	async function refresh() {
		try {
			[providers, identities] = await Promise.all([
				externalIdpService.listPublic(),
				externalIdpService.listIdentities()
			]);
		} catch {
			providers = [];
			identities = [];
		}
	}

	async function unlink(id: string) {
		try {
			await externalIdpService.unlink(id);
			toast.success(m.account_unlinked_successfully());
			await refresh();
		} catch (e) {
			axiosErrorToast(e);
		}
	}
</script>

{#if loaded && (identities.length > 0 || providers.length > 0)}
	<Card.Root>
		<Card.Header>
			<Card.Title>
				<Link2 class="text-primary/80 size-5" />
				{m.linked_accounts()}
			</Card.Title>
			<Card.Description>{m.link_external_accounts_to_sign_in_with_them()}</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col gap-3">
			{#each identities as identity (identity.id)}
				<Item.Root variant="outline">
					<Item.Content>
						<Item.Title>{identity.providerName}</Item.Title>
						{#if identity.email}
							<Item.Description>{identity.email}</Item.Description>
						{/if}
					</Item.Content>
					<Item.Actions>
						<Button variant="outline" onclick={() => unlink(identity.id)}>{m.unlink()}</Button>
					</Item.Actions>
				</Item.Root>
			{/each}

			{#each unlinkedProviders as provider (provider.slug)}
				<Item.Root variant="outline">
					<Item.Content>
						<Item.Title>{provider.name}</Item.Title>
					</Item.Content>
					<Item.Actions>
						<Button
							variant="secondary"
							href={externalIdpService.linkUrl(provider.slug, '/settings/account')}
						>
							{m.link()}
						</Button>
					</Item.Actions>
				</Item.Root>
			{/each}

			{#if identities.length === 0 && providers.length === 0}
				<p class="text-muted-foreground text-sm">{m.no_linked_accounts()}</p>
			{/if}
		</Card.Content>
	</Card.Root>
{/if}
