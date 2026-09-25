<script setup lang="ts">
/**
 * The root component (§3.2): providers in, shell out. No state, no business logic, no styles —
 * anything that grows here belongs in `app/providers` or `app/shell`.
 */
import AppProviders from './app/providers/AppProviders.vue';
import AppShell from './app/shell/AppShell.vue';
</script>

<template>
  <AppProviders>
    <AppShell />
  </AppProviders>
</template>
