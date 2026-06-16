<script lang="ts">
	import SwitchWithLabel from '$lib/components/form/switch-with-label.svelte';
	import { Button } from '$lib/components/ui/button';
	import { m } from '$lib/paraglide/messages';
	import appConfigStore from '$lib/stores/application-configuration-store';
	import type { AllAppConfig } from '$lib/types/application-configuration.type';
	import { preventDefault } from '$lib/utils/event-util';
	import { createForm } from '$lib/utils/form-util';
	import { toast } from 'svelte-sonner';
	import { z } from 'zod/v4';

	let {
		callback,
		appConfig
	}: {
		appConfig: AllAppConfig;
		callback: (appConfig: Partial<AllAppConfig>) => Promise<void>;
	} = $props();

	let isLoading = $state(false);

	const updatedAppConfig = {
		passwordAuthEnabled: appConfig.passwordAuthEnabled,
		totpEnabled: appConfig.totpEnabled,
		breachCheckEnabled: appConfig.breachCheckEnabled
	};

	const formSchema = z.object({
		passwordAuthEnabled: z.boolean(),
		totpEnabled: z.boolean(),
		breachCheckEnabled: z.boolean()
	});

	let { inputs, ...form } = $derived(createForm(formSchema, updatedAppConfig));

	async function onSubmit() {
		const data = form.validate();
		if (!data) return;
		isLoading = true;

		await callback(data).finally(() => (isLoading = false));
		toast.success(m.application_configuration_updated_successfully());
	}
</script>

<form onsubmit={preventDefault(onSubmit)}>
	<fieldset class="flex flex-col gap-5" disabled={$appConfigStore.uiConfigDisabled}>
		<SwitchWithLabel
			id="password-auth-enabled"
			label={m.enable_password_authentication()}
			description={m.allow_users_to_sign_in_with_a_username_and_password()}
			bind:checked={$inputs.passwordAuthEnabled.value}
		/>
		<SwitchWithLabel
			id="totp-enabled"
			label={m.enable_two_factor_authentication()}
			description={m.allow_users_to_secure_their_account_with_an_authenticator_app()}
			bind:checked={$inputs.totpEnabled.value}
		/>
		<SwitchWithLabel
			id="breach-check-enabled"
			label={m.enable_breach_check()}
			description={m.reject_passwords_that_have_been_found_in_known_data_breaches()}
			bind:checked={$inputs.breachCheckEnabled.value}
		/>

		<div class="mt-2 flex justify-end">
			<Button {isLoading} type="submit">{m.save()}</Button>
		</div>
	</fieldset>
</form>
