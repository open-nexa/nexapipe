<script setup lang="ts">
/**
 * Renders an icon from the registry. Replaces every `v-html` SVG string in the app (D6): the
 * markup comes from the template, colour from `currentColor`, and size from a prop.
 */
import { computed } from 'vue';
import { getIconShapes } from '../../icons/registry';

const props = withDefaults(
  defineProps<{
    name: string;
    /** Any CSS length, or a pixel number. */
    size?: number | string;
    strokeWidth?: number;
  }>(),
  {
    size: 16,
    strokeWidth: 2,
  },
);

const shapes = computed(() => getIconShapes(props.name));
const dimension = computed(() =>
  typeof props.size === 'number' ? `${props.size}px` : props.size,
);
</script>

<template>
  <svg
    class="app-icon"
    :style="{ width: dimension, height: dimension }"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    :stroke-width="strokeWidth"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <template v-for="(shape, index) in shapes" :key="index">
      <path v-if="shape.t === 'path'" :d="shape.d" />
      <circle v-else-if="shape.t === 'circle'" :cx="shape.cx" :cy="shape.cy" :r="shape.r" />
      <line
        v-else-if="shape.t === 'line'"
        :x1="shape.x1"
        :y1="shape.y1"
        :x2="shape.x2"
        :y2="shape.y2"
      />
      <polyline v-else-if="shape.t === 'polyline'" :points="shape.points" />
      <rect
        v-else
        :x="shape.x"
        :y="shape.y"
        :width="shape.width"
        :height="shape.height"
        :rx="shape.rx"
      />
    </template>
  </svg>
</template>

<style scoped>
.app-icon {
  display: block;
  flex-shrink: 0;
}
</style>
