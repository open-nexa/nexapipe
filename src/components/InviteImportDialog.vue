<script setup lang="ts">
/**
 * Quick-add for the desktop: paste a `nexapipe://` invite instead of copying a Node ID and a
 * domain list by hand. Android gets the same content by scanning it; a desktop has no camera
 * worth pointing at a terminal, so the link is what arrives here — in a chat message, a ticket,
 * or the server's `--generate-invite` output.
 *
 * The link is parsed in Rust (`parse_invite`), so what the preview shows is exactly what the
 * backend will use. Parsing is live and debounced: the user sees whether a code is any good
 * before pressing anything, and a bad one is never silently accepted.
 */
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import AppButton from './base/AppButton.vue';
import { errorDetail, errorKey } from '../api/errors';
import { parseInvite } from '../api/invite';
import { useToast } from '../composables/useToast';
import type { InvitePayload } from '../types';

const props = withDefaults(
  defineProps<{
    open: boolean;
    /** A link pasted into a node field, so the dialog opens already holding it. */
    initialValue?: string;
  }>(),
  { initialValue: '' },
);

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'import', payload: { invite: InvitePayload; applyRelay: boolean }): void;
}>();

const { t } = useI18n();
const toast = useToast();

const uri = ref('');
const parsing = ref(false);
const invite = ref<InvitePayload | null>(null);
const errorKey_ = ref('');
const errorText = ref('');
const showDetails = ref(false);
/**
 * Whether the invite's relay should be adopted as the global relay setting.
 *
 * Off by default: the relay is global, so importing one invite would otherwise silently
 * repoint every other node's home relay. The invite's relay is a hint about how *that*
 * endpoint is reachable, not a request to change this machine's configuration.
 */
const applyRelay = ref(false);

const panel = ref<HTMLElement | null>(null);
const input = ref<HTMLTextAreaElement | null>(null);
let previouslyFocused: HTMLElement | null = null;
let debounce: ReturnType<typeof setTimeout> | null = null;
/** Guards against a slow parse resolving after a newer one and overwriting it. */
let generation = 0;

const canImport = computed(() => invite.value !== null && !parsing.value);

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function reset(): void {
  uri.value = '';
  parsing.value = false;
  invite.value = null;
  errorKey_.value = '';
  errorText.value = '';
  showDetails.value = false;
}

async function runParse(value: string): Promise<void> {
  const trimmed = value.trim();
  if (!trimmed) {
    parsing.value = false;
    invite.value = null;
    errorKey_.value = '';
    errorText.value = '';
    return;
  }

  const mine = ++generation;
  parsing.value = true;
  try {
    const parsed = await parseInvite(trimmed);
    if (mine !== generation) return;
    invite.value = parsed;
    errorKey_.value = '';
    errorText.value = '';
  } catch (error) {
    if (mine !== generation) return;
    invite.value = null;
    errorKey_.value = errorKey(error, 'error.invite.parse_failed');
    errorText.value = errorDetail(error);
    // The diagnostic is the parser's reason and is English by contract; it goes to the console
    // like every other failure, and is only shown behind the disclosure below.
    console.error(`[invite] ${errorKey_.value}: ${errorText.value}`);
  } finally {
    if (mine === generation) parsing.value = false;
  }
}

watch(uri, (value) => {
  if (debounce) clearTimeout(debounce);
  invite.value = null;
  errorKey_.value = '';
  errorText.value = '';
  if (!value.trim()) {
    parsing.value = false;
    return;
  }
  parsing.value = true;
  debounce = setTimeout(() => void runParse(value), 250);
});

watch(
  () => props.open,
  async (isOpen) => {
    if (isOpen) {
      reset();
      previouslyFocused = document.activeElement as HTMLElement | null;
      // Set after `reset`, and watched, so a pasted link is parsed without another keystroke.
      if (props.initialValue) uri.value = props.initialValue;
      await nextTick();
      input.value?.focus();
    } else {
      if (debounce) clearTimeout(debounce);
      generation++;
      previouslyFocused?.focus?.();
      previouslyFocused = null;
    }
  },
);

onBeforeUnmount(() => {
  if (debounce) clearTimeout(debounce);
  previouslyFocused?.focus?.();
});

async function pasteFromClipboard(): Promise<void> {
  try {
    uri.value = await navigator.clipboard.readText();
  } catch {
    toast.fromKey('invite.pasteFailed');
  }
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    event.preventDefault();
    emit('close');
    return;
  }

  if (event.key !== 'Tab' || !panel.value) return;

  const items = Array.from(panel.value.querySelectorAll<HTMLElement>(FOCUSABLE));
  if (items.length === 0) return;
  const first = items[0]!;
  const last = items[items.length - 1]!;
  const active = document.activeElement as HTMLElement | null;

  if (event.shiftKey && (active === first || active === panel.value)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

function confirmImport(): void {
  if (!invite.value) return;
  emit('import', { invite: invite.value, applyRelay: applyRelay.value });
  emit('close');
}
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="overlay" @click.self="emit('close')" @keydown="onKeydown">
      <div
        ref="panel"
        class="panel"
        role="dialog"
        aria-modal="true"
        :aria-label="t('invite.title')"
        tabindex="-1"
        @keydown="onKeydown"
      >
        <header class="header">
          <h2 class="title">{{ t('invite.title') }}</h2>
        </header>

        <p class="description">{{ t('invite.description') }}</p>

        <div class="field">
          <textarea
            ref="input"
            v-model="uri"
            class="input"
            rows="3"
            spellcheck="false"
            :placeholder="t('invite.placeholder')"
            @keydown.enter.exact.prevent="confirmImport"
          />
          <div class="field-actions">
            <AppButton size="sm" tone="ghost" icon="clipboard" @click="pasteFromClipboard">
              {{ t('invite.paste') }}
            </AppButton>
          </div>
        </div>

        <p v-if="parsing" class="status">{{ t('invite.parsing') }}</p>

        <div v-else-if="errorKey_" class="result tone-error">
          <p class="result-message">{{ t(errorKey_) }}</p>
          <div v-if="errorText" class="details">
            <button type="button" class="details-toggle" @click="showDetails = !showDetails">
              {{ t('common.details') }}
            </button>
            <pre v-if="showDetails" class="details-body" data-selectable>{{ errorText }}</pre>
          </div>
        </div>

        <div v-else-if="invite" class="result tone-ok">
          <dl class="summary">
            <div class="row">
              <dt>{{ t('invite.target') }}</dt>
              <dd>
                <span class="badge">{{ invite.kind === 'ticket' ? t('invite.kindTicket') : t('invite.kindEndpoint') }}</span>
                <span class="mono break">{{ invite.target }}</span>
              </dd>
            </div>
            <div v-if="invite.name" class="row">
              <dt>{{ t('invite.name') }}</dt>
              <dd>{{ invite.name }}</dd>
            </div>
            <div class="row">
              <dt>{{ t('invite.domains') }}</dt>
              <dd>
                <span v-if="invite.domains.length === 0" class="muted">{{ t('invite.domainsNone') }}</span>
                <span v-else class="chips">
                  <span v-for="domain in invite.domains" :key="domain" class="chip">{{ domain }}</span>
                </span>
              </dd>
            </div>
            <div v-if="invite.relay" class="row">
              <dt>{{ t('invite.relay') }}</dt>
              <dd>
                <span class="mono break">{{ invite.relay }}</span>
                <span class="hint">{{ t('invite.relayHint') }}</span>
                <label class="apply-relay">
                  <input v-model="applyRelay" type="checkbox" />
                  <span>{{ t('invite.applyRelay') }}</span>
                </label>
              </dd>
            </div>
            <div v-if="invite.totp" class="row">
              <dt>{{ t('invite.twoFactor') }}</dt>
              <dd>
                <span>{{ t('invite.twoFactorClient', { id: invite.totp.clientId }) }}</span>
                <span class="hint">{{ t('invite.twoFactorHint') }}</span>
              </dd>
            </div>
          </dl>
        </div>

        <footer class="actions">
          <AppButton tone="ghost" @click="emit('close')">{{ t('common.cancel') }}</AppButton>
          <AppButton tone="primary" :disabled="!canImport" @click="confirmImport">
            {{ t('invite.add') }}
          </AppButton>
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.overlay {
  position: fixed;
  inset: 0;
  z-index: 300;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-6);
  background: var(--bg-overlay);
}

.panel {
  width: 100%;
  max-width: 520px;
  max-height: 100%;
  overflow: auto;
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  padding: var(--space-6);
  background: var(--bg-elevated);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-popup);
}

.panel:focus-visible {
  box-shadow: var(--shadow-popup), var(--focus-ring);
}

.header {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.title {
  font-size: var(--font-size-16);
  font-weight: var(--font-weight-semibold);
  color: var(--text-primary);
}

.description {
  font-size: var(--font-size-13);
  color: var(--text-secondary);
}

.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.input {
  width: 100%;
  padding: var(--space-3);
  background: var(--bg-input);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  font-family: var(--font-mono);
  font-size: var(--font-size-12);
  line-height: var(--line-height-mono);
  resize: vertical;
  overflow-wrap: anywhere;
}

.input::placeholder {
  color: var(--text-muted);
}

.input:focus-visible {
  box-shadow: var(--focus-ring);
}

.field-actions {
  display: flex;
  justify-content: flex-end;
}

.status {
  font-size: var(--font-size-12);
  color: var(--text-muted);
}

.result {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
  padding: var(--space-4);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-md);
  background: var(--bg-inset);
}

.result.tone-error {
  border-color: var(--error);
  background: var(--error-subtle);
}

.result.tone-ok {
  border-color: var(--success);
  background: var(--success-subtle);
}

.result-message {
  font-size: var(--font-size-13);
  color: var(--error-text);
  overflow-wrap: anywhere;
}

.summary {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.row {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.row dt {
  font-size: var(--font-size-12);
  color: var(--text-secondary);
}

.row dd {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--space-2);
  font-size: var(--font-size-13);
  color: var(--text-primary);
  overflow-wrap: anywhere;
}

.badge {
  padding: 0 var(--space-2);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-full);
  font-size: var(--font-size-11);
  color: var(--text-secondary);
  white-space: nowrap;
}

.mono {
  font-family: var(--font-mono);
  font-size: var(--font-size-12);
}

.break {
  overflow-wrap: anywhere;
}

.muted {
  color: var(--text-muted);
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-1);
}

.chip {
  padding: 0 var(--space-2);
  background: var(--bg-card);
  border: 1px solid var(--border-default);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--font-size-11);
  color: var(--text-secondary);
}

.hint {
  font-size: var(--font-size-11);
  color: var(--text-muted);
}

.apply-relay {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  margin-top: var(--space-2);
  font-size: var(--font-size-12);
  color: var(--text-secondary);
  cursor: pointer;
}

.apply-relay input {
  accent-color: var(--accent);
  cursor: pointer;
}

.details {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.details-toggle {
  align-self: flex-start;
  font-size: var(--font-size-12);
  color: var(--text-muted);
}

.details-toggle:hover {
  color: var(--text-secondary);
}

.details-body {
  max-height: 120px;
  overflow: auto;
  padding: var(--space-3);
  background: var(--bg-card);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-sm);
  font-family: var(--font-mono);
  font-size: var(--font-size-11);
  line-height: var(--line-height-mono);
  color: var(--text-secondary);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}

.actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-2);
}
</style>
