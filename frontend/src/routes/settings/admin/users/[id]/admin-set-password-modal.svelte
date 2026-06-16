<script lang="ts">
	import FormInput from '$lib/components/form/form-input.svelte';
	import { Button } from '$lib/components/ui/button';
	import * as Dialog from '$lib/components/ui/dialog';
	import { m } from '$lib/paraglide/messages';
	import PasswordService from '$lib/services/password-service';
	import { axiosErrorToast } from '$lib/utils/error-util';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';
	import { z } from 'zod/v4';

	let {
		show = $bindable(),
		userId
	}: {
		show: boolean;
		userId: string;
	} = $props();

	const passwordService = new PasswordService();

	let minLength = $state(8);
	let isLoading = $state(false);

	let formSchema = $derived(
		z
			.object({
				password: z
					.string()
					.min(minLength, m.password_must_be_at_least_n_characters({ n: minLength })),
				confirmPassword: z.string().min(1)
			})
			.refine((d) => d.password === d.confirmPassword, {
				message: m.passwords_do_not_match(),
				path: ['confirmPassword']
			})
	);

	let { inputs, ...form } = $derived(createForm(formSchema, { password: '', confirmPassword: '' }));

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
			await passwordService.adminSet(userId, values.password);
			toast.success(m.password_updated_successfully());
			form.reset();
			show = false;
		} catch (e) {
			axiosErrorToast(e);
		}
		isLoading = false;
	}

	function onOpenChange(open: boolean) {
		if (!open) {
			form.reset();
			show = false;
		}
	}
</script>

<Dialog.Root open={show} {onOpenChange}>
	<Dialog.Content class="max-w-md">
		<Dialog.Header>
			<Dialog.Title>{m.set_password()}</Dialog.Title>
			<Dialog.Description>{m.set_a_new_password_for_this_user()}</Dialog.Description>
		</Dialog.Header>
		<form onsubmit={preventDefault(onSubmit)} class="space-y-5">
			<FormInput label={m.new_password()} type="password" bind:input={$inputs.password} />
			<FormInput
				label={m.confirm_password()}
				type="password"
				bind:input={$inputs.confirmPassword}
			/>
			<Dialog.Footer>
				<Button variant="secondary" type="button" onclick={() => onOpenChange(false)}>
					{m.cancel()}
				</Button>
				<Button type="submit" {isLoading}>{m.save()}</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
