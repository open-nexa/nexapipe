<script setup lang="ts">
import { watch } from "vue";

interface ToastItem {
  id: number;
  type: "success" | "error" | "warning" | "info";
  message: string;
  duration?: number;
}

const props = defineProps<{
  toasts: ToastItem[];
}>();

const emit = defineEmits<{
  (e: "remove", id: number): void;
}>();

function getIcon(type: string) {
  switch (type) {
    case "success":
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;
    case "error":
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;
    case "warning":
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`;
    case "info":
    default:
      return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
  }
}

function getClass(type: string) {
  switch (type) {
    case "success":
      return "toast-success";
    case "error":
      return "toast-error";
    case "warning":
      return "toast-warning";
    case "info":
    default:
      return "toast-info";
  }
}

watch(() => props.toasts, (newToasts) => {
  newToasts.forEach(toast => {
    const duration = toast.duration || 3000;
    setTimeout(() => {
      emit("remove", toast.id);
    }, duration);
  });
}, { deep: true });
</script>

<template>
  <div class="toast-container">
    <TransitionGroup name="toast">
      <div
        v-for="toast in toasts"
        :key="toast.id"
        class="toast-item"
        :class="getClass(toast.type)"
      >
        <div class="toast-icon" v-html="getIcon(toast.type)"></div>
        <span class="toast-message">{{ toast.message }}</span>
        <button class="toast-close" @click="emit('remove', toast.id)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<style scoped>
.toast-container {
  position: fixed;
  top: 20px;
  right: 20px;
  z-index: 1000;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.toast-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 18px;
  border-radius: var(--radius-md);
  min-width: 280px;
  max-width: 400px;
  box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(10px);
}

.toast-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
}

.toast-icon svg {
  width: 100%;
  height: 100%;
}

.toast-message {
  flex: 1;
  font-size: 14px;
  font-weight: 500;
  line-height: 1.5;
}

.toast-close {
  width: 24px;
  height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  border: none;
  border-radius: var(--radius-sm);
  cursor: pointer;
  opacity: 0.6;
  transition: all var(--transition-fast);
}

.toast-close:hover {
  opacity: 1;
  background: rgba(0, 0, 0, 0.1);
}

.toast-close svg {
  width: 16px;
  height: 16px;
}

.toast-success {
  background: var(--success-50);
  color: var(--success-700);
  border-left: 3px solid var(--success-500);
}

.toast-success .toast-icon {
  color: var(--success-500);
}

.toast-error {
  background: var(--error-50);
  color: var(--error-700);
  border-left: 3px solid var(--error-500);
}

.toast-error .toast-icon {
  color: var(--error-500);
}

.toast-warning {
  background: var(--warning-50);
  color: var(--warning-700);
  border-left: 3px solid var(--warning-500);
}

.toast-warning .toast-icon {
  color: var(--warning-500);
}

.toast-info {
  background: var(--primary-50);
  color: var(--primary-700);
  border-left: 3px solid var(--primary-500);
}

.toast-info .toast-icon {
  color: var(--primary-500);
}

.toast-enter-active,
.toast-leave-active {
  transition: all var(--transition-normal);
}

.toast-enter-from {
  opacity: 0;
  transform: translateX(100%);
}

.toast-leave-to {
  opacity: 0;
  transform: translateX(100%);
}

.toast-move {
  transition: transform var(--transition-normal);
}

@media (max-width: 600px) {
  .toast-container {
    right: 12px;
    left: 12px;
  }
  
  .toast-item {
    min-width: auto;
    max-width: none;
  }
}
</style>