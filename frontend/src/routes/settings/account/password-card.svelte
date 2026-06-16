<script lang="ts">
	import FormInput from '$lib/components/form/form-input.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Card from '$lib/components/ui/card';
	import { m } from '$lib/paraglide/messages';
	import PasswordService from '$lib/services/password-service';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { LucideLock } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';
	import { z } from 'zod/v4';

	const passwordService = new PasswordService();

	let minLength = $state(8);
	let isLoading = $state(false);

	let formSchema = $derived(
		z
			.object({
				currentPassword: z.string(),
				newPassword: z
					.string()
					.min(minLength, m.password_must_be_at_least_n_characters({ n: minLength })),
				confirmPassword: z.string().min(1)
			})
			.refine((d) => d.newPassword === d.confirmPassword, {
				message: m.passwords_do_not_match(),
				path: ['confirmPassword']
			})
	);

	let { inputs, ...form } = $derived(
		createForm(formSchema, { currentPassword: '', newPassword: '', confirmPassword: '' })
	);

	onMount(async () => {
		try {
			const policy = await passwordService.policy();
			minLength = policy.minLength;
		} catch {
			// Keep the default minimum length if the policy can not be loaded
		}
	});

	async function onSubmit() {
		const values = form.validate();
		if (!values) return;

		isLoading = true;
		try {
			await passwordService.change(values.currentPassword, values.newPassword);
			toast.success(m.password_updated_successfully());
			form.reset();
		} catch (e) {
			axiosErrorToast(e);
		}
		isLoading = false;
	}
</script>

<Card.Root>
	<Card.Header>
		<Card.Title>
			<LucideLock class="text-primary/80 size-5" />
			{m.password()}
		</Card.Title>
		<Card.Description>{m.change_the_password_used_to_sign_in_to_your_account()}</Card.Description>
	</Card.Header>
	<Card.Content>
		<form onsubmit={preventDefault(onSubmit)} class="space-y-5">
			<FormInput
				label={m.current_password()}
				type="password"
				bind:input={$inputs.currentPassword}
			/>
			<div class="grid grid-cols-1 gap-5 md:grid-cols-2">
				<FormInput label={m.new_password()} type="password" bind:input={$inputs.newPassword} />
				<FormInput
					label={m.confirm_password()}
					type="password"
					bind:input={$inputs.confirmPassword}
				/>
			</div>
			<div class="flex justify-end">
				<Button type="submit" {isLoading}>{m.save()}</Button>
			</div>
		</form>
	</Card.Content>
</Card.Root>
