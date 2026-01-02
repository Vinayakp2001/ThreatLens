<template>
  <div :class="cn('space-y-3', className)">
    <!-- Loading State -->
    <div v-if="!status && !error" class="flex items-center space-x-2">
      <LoadingSpinner size="small" />
      <span class="text-sm text-gray-600 dark:text-gray-400">
        Loading status...
      </span>
    </div>

    <!-- Status Header -->
    <div v-if="status" class="flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <component :is="getStatusIcon(status.status)" />
        <div>
          <div :class="cn('font-medium capitalize', getStatusColor(status.status))">
            {{ status.status }}
          </div>
          <div class="text-sm text-gray-600 dark:text-gray-400">
            {{ getStatusMessage(status) }}
          </div>
        </div>
      </div>
      
      <!-- Duration -->
      <div v-if="status.started_at" class="text-xs text-gray-500 dark:text-gray-500">
        {{ formatDuration(status.started_at, status.completed_at) }}
      </div>
    </div>

    <!-- Progress Bar -->
    <div v-if="status && status.progress_percentage !== undefined" class="space-y-1">
      <div class="flex justify-between text-xs text-gray-600 dark:text-gray-400">
        <span>Progress</span>
        <span>{{ status.progress_percentage }}%</span>
      </div>
      <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
        <div 
          :class="cn('h-2 rounded-full transition-all duration-300', {
            'bg-red-500': status.status === 'error',
            'bg-green-500': status.status === 'completed',
            'bg-blue-500': status.status !== 'error' && status.status !== 'completed'
          })"
          :style="{ width: `${Math.max(0, Math.min(100, status.progress_percentage))}%` }"
        />
      </div>
    </div>

    <!-- Current Stage -->
    <div 
      v-if="status && status.current_stage && status.status === 'analyzing'" 
      class="text-sm text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 rounded-lg p-3"
    >
      <div class="font-medium mb-1">Current Stage:</div>
      <div>{{ status.current_stage }}</div>
    </div>

    <!-- Error Display -->
    <div 
      v-if="error" 
      class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3"
    >
      <div class="flex items-start space-x-2">
        <AlertTriangle class="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0" />
        <div class="flex-1">
          <div class="text-sm font-medium text-red-800 dark:text-red-200">
            Analysis Error
          </div>
          <div class="text-sm text-red-700 dark:text-red-300 mt-1">
            {{ error }}
          </div>
          <button
            @click="retryAnalysis"
            class="mt-2 text-sm text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-200 underline"
          >
            Retry Analysis
          </button>
        </div>
      </div>
    </div>

    <!-- Success Message -->
    <div 
      v-if="status && status.status === 'completed'" 
      class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3"
    >
      <div class="flex items-center space-x-2">
        <CheckCircle class="w-5 h-5 text-green-500" />
        <div class="text-sm font-medium text-green-800 dark:text-green-200">
          Analysis completed successfully!
        </div>
      </div>
      <div v-if="status.completed_at" class="text-xs text-green-700 dark:text-green-300 mt-1">
        Completed at {{ new Date(status.completed_at).toLocaleString() }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { CheckCircle, AlertTriangle, X } from 'lucide-vue-next'
import { api, formatAPIError } from '@/lib/api'
import type { AnalysisProgress, AnalysisStatus } from '@/lib/types'
import { cn } from '@/lib/utils'
import LoadingSpinner from './LoadingSpinner.vue'

interface Props {
  repoId: string
  analysisId?: string
  onStatusChange?: (status: AnalysisProgress) => void
  onComplete?: (status: AnalysisProgress) => void
  onError?: (error: string) => void
  pollInterval?: number
  className?: string
}

const props = withDefaults(defineProps<Props>(), {
  pollInterval: 2000,
  className: ''
})

const status = ref<AnalysisProgress | null>(null)
const error = ref<string | null>(null)
const isPolling = ref(false)
let pollIntervalId: NodeJS.Timeout | null = null

const fetchStatus = async () => {
  try {
    error.value = null
    let statusResponse: AnalysisProgress
    
    if (props.analysisId) {
      statusResponse = await api.getAnalysisProgress(props.analysisId)
    } else {
      statusResponse = await api.getAnalysisStatus(props.repoId)
    }
    
    status.value = statusResponse
    
    // Call status change callback
    if (props.onStatusChange) {
      props.onStatusChange(statusResponse)
    }
    
    // Handle completion
    if (statusResponse.status === 'completed') {
      stopPolling()
      if (props.onComplete) {
        props.onComplete(statusResponse)
      }
    }
    
    // Handle errors
    if (statusResponse.status === 'error') {
      stopPolling()
      const errorMessage = statusResponse.error_details || statusResponse.message || 'Analysis failed'
      error.value = errorMessage
      if (props.onError) {
        props.onError(errorMessage)
      }
    }
    
    return statusResponse
  } catch (err) {
    const errorMessage = formatAPIError(err)
    error.value = errorMessage
    stopPolling()
    if (props.onError) {
      props.onError(errorMessage)
    }
    throw err
  }
}

const startPolling = () => {
  if (isPolling.value) return
  
  isPolling.value = true
  fetchStatus()
  
  pollIntervalId = setInterval(async () => {
    try {
      const currentStatus = await fetchStatus()
      
      // Stop polling if analysis is complete or failed
      if (currentStatus.status === 'completed' || currentStatus.status === 'error') {
        stopPolling()
      }
    } catch (err) {
      console.error('Error polling analysis status:', err)
      stopPolling()
    }
  }, props.pollInterval)
}

const stopPolling = () => {
  isPolling.value = false
  if (pollIntervalId) {
    clearInterval(pollIntervalId)
    pollIntervalId = null
  }
}

const shouldPoll = computed(() => {
  return !status.value || status.value.status === 'queued' || status.value.status === 'analyzing'
})

// Watch for changes that should trigger polling
watch(shouldPoll, (newShouldPoll) => {
  if (newShouldPoll && !isPolling.value) {
    startPolling()
  } else if (!newShouldPoll && isPolling.value) {
    stopPolling()
  }
}, { immediate: true })

const getStatusIcon = (statusType: AnalysisStatus) => {
  switch (statusType) {
    case 'queued':
      return 'div'
    case 'analyzing':
      return 'div'
    case 'completed':
      return CheckCircle
    case 'error':
      return X
    default:
      return 'div'
  }
}

const getStatusColor = (statusType: AnalysisStatus) => {
  switch (statusType) {
    case 'queued':
      return 'text-blue-600 dark:text-blue-400'
    case 'analyzing':
      return 'text-yellow-600 dark:text-yellow-400'
    case 'completed':
      return 'text-green-600 dark:text-green-400'
    case 'error':
      return 'text-red-600 dark:text-red-400'
    default:
      return 'text-gray-600 dark:text-gray-400'
  }
}

const getStatusMessage = (status: AnalysisProgress) => {
  switch (status.status) {
    case 'queued':
      return 'Analysis queued for processing...'
    case 'analyzing':
      return status.current_stage || 'Analyzing repository...'
    case 'completed':
      return 'Analysis completed successfully'
    case 'error':
      return status.error_details || status.message || 'Analysis failed'
    default:
      return 'Unknown status'
  }
}

const formatDuration = (startTime?: string, endTime?: string) => {
  if (!startTime) return null
  
  const start = new Date(startTime)
  const end = endTime ? new Date(endTime) : new Date()
  const durationMs = end.getTime() - start.getTime()
  const durationSec = Math.floor(durationMs / 1000)
  
  if (durationSec < 60) {
    return `${durationSec}s`
  } else if (durationSec < 3600) {
    const minutes = Math.floor(durationSec / 60)
    const seconds = durationSec % 60
    return `${minutes}m ${seconds}s`
  } else {
    const hours = Math.floor(durationSec / 3600)
    const minutes = Math.floor((durationSec % 3600) / 60)
    return `${hours}h ${minutes}m`
  }
}

const retryAnalysis = async () => {
  try {
    error.value = null
    startPolling()
  } catch (err) {
    console.error('Error retrying analysis:', err)
  }
}

onMounted(() => {
  if (shouldPoll.value) {
    startPolling()
  }
})

onUnmounted(() => {
  stopPolling()
})
</script>