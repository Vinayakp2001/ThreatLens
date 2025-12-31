import { ref } from 'vue'
import { defineStore } from 'pinia'

export type ToastType = 'success' | 'error' | 'warning' | 'info'

export interface Toast {
  id: string
  type: ToastType
  title: string
  message?: string
  duration?: number
  persistent?: boolean
  action?: {
    label: string
    onClick: () => void
  }
}

export const useToastStore = defineStore('toast', () => {
  const toasts = ref<Toast[]>([])

  const addToast = (toast: Omit<Toast, 'id'>): string => {
    const id = Math.random().toString(36).substr(2, 9)
    const newToast: Toast = {
      id,
      duration: 5000,
      ...toast
    }

    toasts.value.push(newToast)

    // Auto-remove toast after duration (unless persistent)
    if (!newToast.persistent && newToast.duration) {
      setTimeout(() => {
        removeToast(id)
      }, newToast.duration)
    }

    return id
  }

  const removeToast = (id: string) => {
    const index = toasts.value.findIndex(toast => toast.id === id)
    if (index > -1) {
      toasts.value.splice(index, 1)
    }
  }

  const clearToasts = () => {
    toasts.value = []
  }

  return {
    toasts,
    addToast,
    removeToast,
    clearToasts
  }
})

// Utility composables for common toast patterns
export function useToast() {
  const store = useToastStore()

  const showSuccess = (title: string, message?: string) => {
    return store.addToast({ type: 'success', title, message })
  }

  const showError = (title: string, message?: string, action?: Toast['action']) => {
    return store.addToast({ 
      type: 'error', 
      title, 
      message, 
      action,
      persistent: true // Errors should be persistent by default
    })
  }

  const showWarning = (title: string, message?: string) => {
    return store.addToast({ type: 'warning', title, message })
  }

  const showInfo = (title: string, message?: string) => {
    return store.addToast({ type: 'info', title, message })
  }

  return {
    showSuccess,
    showError,
    showWarning,
    showInfo,
    removeToast: store.removeToast,
    clearToasts: store.clearToasts
  }
}