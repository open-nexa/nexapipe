<script setup lang="ts">
defineProps<{
  visible: boolean;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  type?: "warning" | "danger" | "info";
}>();

const emit = defineEmits<{
  (e: "confirm"): void;
  (e: "cancel"): void;
}>();
</script>

<template>
  <Teleport to="body">
    <Transition name="dialog">
      <div v-if="visible" class="dialog-overlay" @click.self="emit('cancel')">
        <div class="dialog-container">
          <div class="dialog-icon" :class="type">
            <svg v-if="type === 'danger'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M18 6L6 18M6 6l12 12"/>
            </svg>
            <svg v-else-if="type === 'warning'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
            <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="16" x2="12" y2="12"/>
              <line x1="12" y1="8" x2="12.01" y2="8"/>
            </svg>
          </div>
          
          <h3 class="dialog-title">{{ title }}</h3>
          <p class="dialog-message">{{ message }}</p>
          
          <div class="dialog-actions">
            <button class="btn btn-secondary" @click="emit('cancel')">
              {{ cancelText || 'Cancel' }}
            </button>
            <button class="btn btn-danger" v-if="type === 'danger'" @click="emit('confirm')">
              {{ confirmText || 'Confirm' }}
            </button>
            <button class="btn btn-warning" v-else-if="type === 'warning'" @click="emit('confirm')">
              {{ confirmText || 'Confirm' }}
            </button>
            <button class="btn btn-primary" v-else @click="emit('confirm')">
              {{ confirmText || 'Confirm' }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 2000;
  backdrop-filter: blur(4px);
}

.dialog-container {
  background: var(--surface-1);
  border-radius: var(--radius-lg);
  padding: 32px;
  min-width: 360px;
  max-width: 90%;
  box-shadow: 0 25px 80px rgba(0, 0, 0, 0.25);
  border: 1px solid var(--border-light);
}

.dialog-icon {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 20px;
  transition: all var(--transition-normal);
}

.dialog-icon svg {
  width: 24px;
  height: 24px;
}

.dialog-icon.info {
  background: var(--primary-100);
  color: var(--primary-600);
}

.dialog-icon.warning {
  background: var(--warning-100);
  color: var(--warning-600);
}

.dialog-icon.danger {
  background: var(--error-100);
  color: var(--error-600);
}

.dialog-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text-primary);
  text-align: center;
  margin: 0 0 12px;
}

.dialog-message {
  font-size: 14px;
  color: var(--text-secondary);
  text-align: center;
  line-height: 1.6;
  margin: 0 0 24px;
}

.dialog-actions {
  display: flex;
  gap: 12px;
  justify-content: center;
}

.btn {
  padding: 10px 24px;
  border: none;
  border-radius: var(--radius-md);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all var(--transition-normal);
}

.btn-secondary {
  background: var(--surface-3);
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
}

.btn-secondary:hover {
  background: var(--surface-4);
  border-color: var(--primary-300);
}

.btn-primary {
  background: var(--gradient-primary);
  color: white;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 20px rgba(59, 130, 246, 0.4);
}

.btn-warning {
  background: var(--warning-500);
  color: white;
}

.btn-warning:hover {
  background: var(--warning-600);
}

.btn-danger {
  background: var(--error-500);
  color: white;
}

.btn-danger:hover {
  background: var(--error-600);
}

.dialog-enter-active,
.dialog-leave-active {
  transition: all var(--transition-normal);
}

.dialog-enter-from,
.dialog-leave-to {
  opacity: 0;
}

.dialog-enter-from .dialog-container,
.dialog-leave-to .dialog-container {
  transform: scale(0.9) translateY(20px);
}

@media (max-width: 480px) {
  .dialog-container {
    min-width: auto;
    padding: 24px;
  }
  
  .dialog-actions {
    flex-direction: column;
  }
  
  .btn {
    width: 100%;
  }
}
</style>