<script setup lang="ts">
/**
 * One navigation entry: icon, optional label, active marker.
 *
 * When the rail is collapsed the label is only reachable through a tooltip — which is also shown
 * on keyboard focus, so the collapsed rail stays navigable without a mouse.
 */
import AppIcon from '../../components/base/AppIcon.vue';
import AppTooltip from '../../components/base/AppTooltip.vue';

defineProps<{
  icon: string;
  label: string;
  active: boolean;
  collapsed: boolean;
}>();

const emit = defineEmits<{
  (e: 'select'): void;
}>();
</script>

<template>
  <AppTooltip :label="label" :disabled="!collapsed" placement="right">
    <button
      type="button"
      class="side-bar-item"
      :class="{ active, collapsed }"
      :aria-current="active ? 'page' : undefined"
      :aria-label="collapsed ? label : undefined"
      :title="collapsed ? undefined : label"
      @click="emit('select')"
    >
      <span v-if="active" class="side-bar-item__indicator" aria-hidden="true" />
      <AppIcon :name="icon" :size="18" />
      <span v-if="!collapsed" class="side-bar-item__label">{{ label }}</span>
    </button>
  </AppTooltip>
</template>

<style scoped>
.side-bar-item {
  position: relative;
  display: flex;
  align-items: center;
  gap: var(--space-3);
  width: 100%;
  height: 38px;
  padding: 0 var(--space-3);
  border-radius: var(--radius-md);
  color: var(--nav-text);
  font-size: var(--font-size-13);
  font-weight: var(--font-weight-medium);
  transition:
    background-color var(--duration-fast) var(--ease-standard),
    color var(--duration-fast) var(--ease-standard);
}

.side-bar-item.collapsed {
  justify-content: center;
  padding: 0;
}

.side-bar-item:hover {
  background: var(--nav-bg-hover);
  color: var(--text-primary);
}

.side-bar-item.active {
  background: var(--nav-bg-active);
  color: var(--nav-text-active);
}

.side-bar-item:focus-visible {
  box-shadow: var(--focus-ring);
}

.side-bar-item__indicator {
  position: absolute;
  left: 0;
  top: 50%;
  width: 3px;
  height: 18px;
  border-radius: 0 var(--radius-xs) var(--radius-xs) 0;
  background: var(--nav-indicator);
  transform: translateY(-50%);
}

/* A label that still does not fit the 200px rail elides, and carries its full text in `title`
   (§5.5). The fixed row height is what keeps the rail scannable, so wrapping is not an option
   here; the tooltip covers the collapsed case. */
.side-bar-item__label {
  min-width: 0;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
</style>
