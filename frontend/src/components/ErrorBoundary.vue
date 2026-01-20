<template>
  <div v-if="error" class="error-boundary">
    <ErrorDisplay 
      :error="error" 
      :title="errorTitle"
      :on-retry="retryOperation"
      :show-retry="showRetry"
      :on-dismiss="clearError"
      class="m-4"
    />
    
    <!-- Fallback UI when data is unavailable -->
    <div v-if="showFallbackUI" class="p-6 text-center">
      <div class="text-gray-400 dark:text-gray-600 mb-4">
        <component :is="fallbackIcon" class="w-16 h-16 mx-auto" />
      </div>
      <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
        {{ fallbackTitle }}
      </h3>
      <p class="text-gray-600 dark:text-gray-400 mb-4">
        {{ fallbackMessage }}
      </p>
      <button
        v-if="showRetry"
        @click="retryOperation"
        class="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors"
      >
        <RefreshCw class="w-4 h-4 mr-2" />
        Try Again
      </button>
    </div>
  </div>
  
  <div v-else>
    <slot />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onErrorCaptured, watch } from 'vue'
import { RefreshCw, AlertTriangle, Wifi, Database, MessageCircle } from 'lucide-vue-next'
import ErrorDisplay from './ErrorDisplay.vue'
import { isAPIError, isNetworkError } from '@/lib/api'

interface Props {
  errorTitle?: string
  fallbackTitle?: string
  fallbackMessage?: string
  showRetry?: boolean
  showFallbackUI?: boolean
  onRetry?: () => void | Promise<void>
  onError?: (error: Error) => void
}

const props = withDefaults(defineProps<Props>(), {
  errorTitle: 'Component Error',
  fallbackTitle: 'Something went wrong',
  fallbackMessage: 'We encountered an error while loading this content. Please try again.',
  showRetry: true,
  showFallbackUI: false
})

const error = ref<Error | null>(null)

// Capture errors from child components
onErrorCaptured((err: Error) => {
  console.error('ErrorBoundary caught error:', err)
  error.value = err
  
  // Call the onError callback if provided
  if (props.onError) {
    props.onError(err)
  }
  
  // Prevent the error from propagating further
  return false
})

// Watch for external error clearing
watch(() => props.onRetry, () => {
  if (error.value && props.onRetry) {
    // Clear error when retry function changes (indicates parent wants to retry)
    error.value = null
  }
})

const fallbackIcon = computed(() => {
  if (!error.value) return AlertTriangle
  
  if (isNetworkError(error.value)) {
    return Wifi
  }
  
  if (isAPIError(error.value)) {
    return Database
  }
  
  if (error.value.message.toLowerCase().includes('chat')) {
    return MessageCircle
  }
  
  return AlertTriangle
})

const retryOperation = async () => {
  if (props.onRetry) {
    try {
      error.value = null
      await props.onRetry()
    } catch (err) {
      console.error('Retry operation failed:', err)
      error.value = err instanceof Error ? err : new Error('Retry failed')
    }
  } else {
    // Default retry: clear error and let component re-render
    error.value = null
  }
}

const clearError = () => {
  error.value = null
}

// Expose methods for parent components
defineExpose({
  setError: (err: Error) => {
    error.value = err
  },
  clearError,
  hasError: computed(() => !!error.value)
})
</script>

<style scoped>
.error-boundary {
  @apply min-h-0 flex flex-col;
}
</style>