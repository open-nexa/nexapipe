<script setup lang="ts">
/**
 * The card a section of the configuration screen is drawn on.
 *
 * Every section of the screen is the same card: a title, the rule under it, and whatever the
 * section puts at the right-hand end of the header. The card and the form primitives the
 * sections share are written down once, in `config-section.css`, so that a section cannot drift
 * away from the others — the network section, the relay section and the node list are three
 * pieces of one screen, and a field that looked like a different field in one of them would be a
 * bug rather than a variation.
 *
 * The title is passed in already translated: the shell draws, it does not decide what is said.
 */
defineProps<{
  /** The section's title. */
  title: string;
}>();
</script>

<template>
  <div class="config-section">
    <div class="card-header">
      <h2>{{ title }}</h2>
      <div class="card-header-decoration"></div>
      <slot name="actions"></slot>
    </div>
    <slot></slot>
  </div>
</template>

<style scoped src="./config-section.css"></style>
