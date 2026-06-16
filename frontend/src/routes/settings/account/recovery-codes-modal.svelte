<script lang="ts">
	import CopyToClipboard from '$lib/components/copy-to-clipboard.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog';
	import { m } from '$lib/paraglide/messages';
	import { LucideCopy } from '@lucide/svelte';

	let {
		recoveryCodes = $bindable()
	}: {
		recoveryCodes: string[] | null;
	} = $props();

	function onOpenChange(open: boolean) {
		if (!open) {
			recoveryCodes = null;
		}
	}

	function copyAll() {
		if (recoveryCodes) {
			navigator.clipboard.writeText(recoveryCodes.join('\n'));
		}
	}
</script>

<Dialog.Root open={!!recoveryCodes} {onOpenChange}>
	<Dialog.Content class="max-w-md" onOpenAutoFocus={(e) => e.preventDefault()}>
		<Dialog.Header>
			<Dialog.Title>{m.recovery_codes()}</Dialog.Title>
			<Dialog.Description>
				{m.store_these_recovery_codes_in_a_safe_place_they_will_not_be_shown_again()}
			</Dialog.Description>
		</Dialog.Header>

		<div class="bg-muted grid grid-cols-2 gap-2 rounded-2xl p-4 font-mono text-sm">
			{#each recoveryCodes ?? [] as code (code)}
				<CopyToClipboard value={code}>
					<span>{code}</span>
				</CopyToClipboard>
			{/each}
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={copyAll}>
				<LucideCopy class="mr-2 size-4" />
				{m.copy_all()}
			</Button>
			<Button onclick={() => (recoveryCodes = null)}>{m.done()}</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
