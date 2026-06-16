import { toast } from 'svelte-sonner';

/**
 * svelte-sonner's <Toaster> calls `toastState.reset()` inside its own `onMount`.
 * Svelte mounts child components before their parent, and the <Toaster> lives in the
 * root layout, so any toast queued during a page's `onMount` on the *initial* page load
 * is wiped by that reset before it ever renders.
 *
 * Deferring with a macrotask pushes the toast past the synchronous mount flush (the
 * Toaster's reset has already run by then), so toasts triggered by query params on a
 * fresh page load — e.g. `/login?externalError=...` or `/settings/account?linked=...` —
 * actually show up.
 */
export function deferToast(fn: (t: typeof toast) => void) {
	setTimeout(() => fn(toast), 0);
}
