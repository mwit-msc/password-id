<script lang="ts">
	import CopyToClipboard from '$lib/components/copy-to-clipboard.svelte';
	import FormInput from '$lib/components/form/form-input.svelte';
	import Qrcode from '$lib/components/qrcode/qrcode.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { m } from '$lib/paraglide/messages';
	import TotpService from '$lib/services/totp-service';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { LucideShieldCheck } from '@lucide/svelte';
	import { mode } from 'mode-watcher';
	import { toast } from 'svelte-sonner';
	import { z } from 'zod/v4';
	import RecoveryCodesModal from './recovery-codes-modal.svelte';

	let {
		enabled = $bindable()
	}: {
		enabled: boolean;
	} = $props();

	const totpService = new TotpService();

	let enrolling = $state(false);
	let isLoading = $state(false);
	let secret: string | null = $state(null);
	let uri: string | null = $state(null);
	let recoveryCodes: string[] | null = $state(null);

	const formSchema = z.object({
		code: z.string().min(1)
	});
	const { inputs, ...form } = createForm(formSchema, { code: '' });

	async function startEnroll() {
		isLoading = true;
		try {
			const res = await totpService.enroll();
			secret = res.secret;
			uri = res.uri;
			enrolling = true;
		} catch (e) {
			axiosErrorToast(e);
		}
		isLoading = false;
	}

	async function confirm() {
		const values = form.validate();
		if (!values) return;

		isLoading = true;
		try {
			const res = await totpService.confirm(values.code);
			recoveryCodes = res.recoveryCodes;
			enabled = true;
			enrolling = false;
			secret = null;
			uri = null;
			form.reset();
			toast.success(m.two_factor_authentication_enabled());
		} catch (e) {
			axiosErrorToast(e);
		}
		isLoading = false;
	}

	function cancelEnroll() {
		enrolling = false;
		secret = null;
		uri = null;
		form.reset();
	}

	async function disable() {
		isLoading = true;
		try {
			await totpService.disable();
			enabled = false;
			toast.success(m.two_factor_authentication_disabled());
		} catch (e) {
			axiosErrorToast(e);
		}
		isLoading = false;
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>
			<LucideShieldCheck class="text-primary/80 size-5" />
			{m.two_factor_authentication()}
		</Card.Title>
		<Card.Description>
			{m.add_an_extra_layer_of_security_using_an_authenticator_app()}
		</Card.Description>
	</Card.Header>
	<Card.Content>
		{#if enabled}
			<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
				<p class="text-muted-foreground text-sm">
					{m.two_factor_authentication_is_currently_enabled()}
				</p>
				<Button variant="destructive" {isLoading} onclick={disable}>{m.disable()}</Button>
			</div>
		{:else if enrolling}
			<div class="flex flex-col items-center gap-5">
				<p class="text-muted-foreground text-center text-sm">
					{m.scan_the_qr_code_with_your_authenticator_app()}
				</p>
				<Qrcode value={uri} size={180} color={mode.current === 'dark' ? '#FFFFFF' : '#000000'} />
				{#if secret}
					<CopyToClipboard value={secret}>
						<span class="bg-muted rounded-full px-3 py-1 font-mono text-sm">{secret}</span>
					</CopyToClipboard>
				{/if}
				<form onsubmit={preventDefault(confirm)} class="w-full max-w-[300px] space-y-4">
					<FormInput
						label={m.authentication_code()}
						bind:input={$inputs.code}
						placeholder="123456"
					/>
					<div class="flex justify-between gap-2">
						<Button variant="secondary" class="flex-1" type="button" onclick={cancelEnroll}>
							{m.cancel()}
						</Button>
						<Button class="flex-1" type="submit" {isLoading}>{m.enable()}</Button>
					</div>
				</form>
			</div>
		{:else}
			<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
				<p class="text-muted-foreground text-sm">
					{m.two_factor_authentication_is_not_enabled()}
				</p>
				<Button {isLoading} onclick={startEnroll}>{m.enable()}</Button>
			</div>
		{/if}
	</Card.Content>
</Card.Root>

<RecoveryCodesModal bind:recoveryCodes />
