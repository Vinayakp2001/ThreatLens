<template>
  <ErrorBoundary
    :error-title="errorTitle"
    :fallback-title="fallbackTitle"
    :fallback-message="fallbackMessage"
    :show-retry="true"
    :show-fallback-ui="true"
    :on-retry="handleRetry"
    :on-error="handleChatError"
  >
    <slot />
  </ErrorBoundary>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import ErrorBoundary from './ErrorBoundary.vue'
import { isAPIError, isNetworkError } from '@/lib/api'

interface Props {
  repoId?: string
  onRetry?: () => void | Promise<void>
  onError?: (error: Error) => void
}

const props = defineProps<Props>()

const errorTitle = computed(() => 'Chat System Error')

const fallbackTitle = computed(() => 'Chat Unavailable')

const fallbackMessage = computed(() => {
  if (props.repoId) {
    return 'The security chat system is temporarily unavailable. You can still browse the wiki sections while we work to restore chat functionality.'
  }
  return 'The chat system encountered an error. Please try refreshing the page or contact support if the problem persists.'
})

const handleChatError = (error: Error) => {
  console.error('Chat system error:', error)
  
  // Log specific error details for debugging
  if (isAPIError(error)) {
    console.error('API Error details:', {
      status: error.status,
      code: error.code,
      details: error.details
    })
  }
  
  if (isNetworkError(error)) {
    console.error('Network error - chat service may be unavailable')
  }
  
  // Call parent error handler if provided
  if (props.onError) {
    props.onError(error)
  }
}

const handleRetry = async () => {
  console.log('Retrying chat system initialization...')
  
  if (props.onRetry) {
    await props.onRetry()
  } else {
    // Default retry behavior - reload the page
    window.location.reload()
  }
}
</script>