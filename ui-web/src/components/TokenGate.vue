<script setup lang="ts">
/**
 * The gate the operator walks through before the console does anything.
 *
 * The token is asked for rather than read from the instance: the token file's
 * permissions are what keep another user on a shared machine out of the
 * management surface, and a token in the page would hand it to anyone who can
 * fetch the page.
 */
import { ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useTokenStore } from '../stores/token';

const { t } = useI18n();
const tokens = useTokenStore();

const pasted = ref('');

function open(): void {
  if (pasted.value.trim()) {
    tokens.setToken(pasted.value);
  }
}
</script>

<template>
  <div class="gate">
    <form class="gate__card" @submit.prevent="open">
      <h1 class="gate__title">{{ t('token.title') }}</h1>
      <p class="gate__intro">{{ t('token.intro') }}</p>

      <label class="field">
        <span class="field__label">{{ t('token.label') }}</span>
        <input
          v-model="pasted"
          class="field__input"
          type="password"
          autocomplete="off"
          spellcheck="false"
          :placeholder="t('token.placeholder')"
        />
      </label>

      <button class="button" type="submit" :disabled="!pasted.trim()">
        {{ t('token.submit') }}
      </button>

      <p class="gate__hint">{{ t('token.hint') }}</p>
      <p class="gate__missing">{{ t('token.missing') }}</p>
    </form>
  </div>
</template>
