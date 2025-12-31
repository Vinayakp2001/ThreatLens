<template>
  <div :class="cn('rounded-lg border p-4', colors.bg, colors.border, className)">
    <div class="flex items-start space-x-3">
      <div :class="cn('flex-shrink-0 mt-0.5', colors.icon)">
        <component :is="getErrorIcon(errorObj)" class="w-5 h-5" />
      </div>
      
      <div class="flex-1 min-w-0">
        <div class="flex items-start justify-between">
          <div class="flex-1">
            <h3 :class="cn('text-sm font-medium', colors.title)">
              {{ title }}
            </h3>
            <p :class="cn('mt-1 text-sm', colors.text)">
              {{ getUserFriendlyMessage(errorObj) }}
            </p>
          </div>
          
          <button
            v-if="onDismiss"
            @click="onDismiss"
            :class="cn('ml-3 flex-shrink-0 hover:opacity-70 transition-opacity', colors.icon)"
          >
            <X class="w-4 h-4" />
          </button>
        </div>

        <!-- Action Buttons -->
        <div class="mt-3 flex items-center space-x-3">
          <button
            v-if="showRetry && onRetry"
            @click="onRetry"
            :class="cn('inline-flex items-center space-x-1 text-sm hover:opacity-80 transition-opacity', colors.title)"
          >
            <RefreshCw class="w-4 h-4" />
            <span>Try Again</span>
          </button>
          
          <button
            @click="showDetails = !showDetails"
            :class="cn('inline-flex items-center space-x-1 text-sm hover:opacity-80 transition-opacity', colors.title)"
          >
            <ChevronDown v-if="showDetails" class="w-4 h-4" />
            <ChevronRight v-else class="w-4 h-4" />
            <span>{{ showDetails ? 'Hide' : 'Show' }} Details</span>
          </button>
        </div>

        <!-- Error Details -->
        <div 
          v-if="showDetails" 
          class="mt-4 p-3 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700"
        >
          <div class="space-y-3">
            <div>
              <h4 class="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                Error Details
              </h4>
              <div class="mt-1 text-xs font-mono text-gray-600 dark:text-gray-400 space-y-1">
                <div>
                  <span class="text-gray-500">Type:</span> {{ errorObj.name }}
                </div>
                <div>
                  <span class="text-gray-500">Message:</span> {{ errorObj.message }}
                </div>
                <div v-if="isAPIError(errorObj)">
                  <span class="text-gray-500">Status:</span> {{ errorObj.status }}
                </div>
                <div v-if="isAPIError(errorObj) && errorObj.code">
                  <span class="text-gray-500">Code:</span> {{ errorObj.code }}
                </div>
                <div>
                  <span class="text-gray-500">Time:</span> {{ new Date().toLocaleString() }}
                </div>
              </div>
            </div>

            <div v-if="errorObj.stack">
              <h4 class="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                Stack Trace
              </h4>
              <pre class="mt-1 text-xs bg-gray-100 dark:bg-gray-900 p-2 rounded overflow-auto max-h-32 text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{{ errorObj.stack }}</pre>
            </div>

            <div v-if="isAPIError(errorObj) && errorObj.details">
              <h4 class="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                Additional Details
              </h4>
              <pre class="mt-1 text-xs bg-gray-100 dark:bg-gray-900 p-2 rounded overflow-auto max-h-32 text-gray-700 dark:text-gray-300">{{ JSON.stringify(errorObj.details, null, 2) }}</pre>
            </div>

            <div class="pt-2 border-t border-gray-200 dark:border-gray-700">
              <button
                @click="copyErrorDetails"
                class="inline-flex items-center space-x-1 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
              >
                <Copy class="w-3 h-3" />
                <span>Copy Error Details</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { 
  AlertTriangle, 
  RefreshCw, 
  Copy, 
  ChevronDown, 
  ChevronRight, 
  X,
  Wifi,
  XCircle
} from 'lucide-vue-next'
import { isAPIError, isValidationError, isNetworkError } from '@/lib/api'
import { cn } from '@/lib/utils'

interface Props {
  error: Error | string
  title?: string
  onRetry?: () => void
  onDismiss?: () => void
  showRetry?: boolean
  className?: string
}

const props = withDefaults(defineProps<Props>(), {
  title: 'An error occurred',
  showRetry: true,
  className: ''
})

const showDetails = ref(false)

const errorObj = computed(() => 
  typeof props.error === 'string' ? new Error(props.error) : props.error
)

const getUserFriendlyMessage = (error: Error): string => {
  if (isNetworkError(error)) {
    return 'Unable to connect to the server. Please check your internet connection and try again.'
  }
  
  if (isValidationError(error)) {
    return `Please check your input: ${error.message}`
  }
  
  if (isAPIError(error)) {
    switch (error.status) {
      case 400:
        return 'The request was invalid. Please check your input and try again.'
      case 401:
        return 'Authentication required. Please log in and try again.'
      case 403:
        return 'You do not have permission to perform this action.'
      case 404:
        return 'The requested resource was not found.'
      case 409:
        return 'There was a conflict with the current state. Please refresh and try again.'
      case 413:
        return 'The file or request is too large. Please try with a smaller file.'
      case 422:
        return 'The data provided is invalid. Please check your input.'
      case 429:
        return 'Too many requests. Please wait a moment and try again.'
      case 500:
        return 'A server error occurred. Please try again later.'
      case 502:
      case 503:
        return 'The service is temporarily unavailable. Please try again later.'
      case 504:
        return 'The request timed out. Please try again.'
      default:
        return error.message || 'An unexpected error occurred.'
    }
  }
  
  return error.message || 'An unexpected error occurred.'
}

const getErrorIcon = (error: Error) => {
  if (isNetworkError(error)) {
    return Wifi
  }
  
  if (isValidationError(error)) {
    return AlertTriangle
  }
  
  return XCircle
}

const getErrorColor = (error: Error) => {
  if (isNetworkError(error)) {
    return {
      bg: 'bg-orange-50 dark:bg-orange-900/20',
      border: 'border-orange-200 dark:border-orange-800',
      icon: 'text-orange-500',
      title: 'text-orange-800 dark:text-orange-200',
      text: 'text-orange-700 dark:text-orange-300'
    }
  }
  
  if (isValidationError(error)) {
    return {
      bg: 'bg-yellow-50 dark:bg-yellow-900/20',
      border: 'border-yellow-200 dark:border-yellow-800',
      icon: 'text-yellow-500',
      title: 'text-yellow-800 dark:text-yellow-200',
      text: 'text-yellow-700 dark:text-yellow-300'
    }
  }
  
  return {
    bg: 'bg-red-50 dark:bg-red-900/20',
    border: 'border-red-200 dark:border-red-800',
    icon: 'text-red-500',
    title: 'text-red-800 dark:text-red-200',
    text: 'text-red-700 dark:text-red-300'
  }
}

const colors = computed(() => getErrorColor(errorObj.value))

const copyErrorDetails = () => {
  const details = {
    message: errorObj.value.message,
    name: errorObj.value.name,
    stack: errorObj.value.stack,
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent,
    url: window.location.href,
    ...(isAPIError(errorObj.value) && {
      status: errorObj.value.status,
      code: errorObj.value.code,
      details: errorObj.value.details
    })
  }
  
  navigator.clipboard.writeText(JSON.stringify(details, null, 2))
}
</script>