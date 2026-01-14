<template>
  <div data-testid="wiki-card" class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md transition-shadow duration-200">
    <!-- Card Header -->
    <div class="p-4 border-b border-gray-200 dark:border-gray-700">
      <div class="flex items-start justify-between">
        <div class="flex-1 min-w-0">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 truncate">
            {{ wiki.repository_name }}
          </h3>
          <p class="text-sm text-gray-500 dark:text-gray-400 truncate mt-1">
            {{ wiki.repository_url }}
          </p>
        </div>
        
        <!-- Status Badge -->
        <div class="ml-3 flex-shrink-0">
          <span :class="getStatusBadgeClass(wiki.analysis_status)" class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium">
            <component :is="getStatusIcon(wiki.analysis_status)" class="w-3 h-3 mr-1" />
            {{ getStatusText(wiki.analysis_status) }}
          </span>
        </div>
      </div>
    </div>
    
    <!-- Card Content -->
    <div class="p-4">
      <!-- Creation Date -->
      <div class="flex items-center text-sm text-gray-500 dark:text-gray-400 mb-4">
        <Calendar class="w-4 h-4 mr-2" />
        <span>Created {{ formatDate(wiki.created_at) }}</span>
      </div>
      
      <!-- Progress for analyzing status -->
      <div v-if="wiki.analysis_status === 'analyzing'" class="mb-4">
        <div class="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400 mb-2">
          <span>Analyzing repository...</span>
          <span>{{ analysisProgress }}%</span>
        </div>
        <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
          <div 
            class="bg-blue-600 h-2 rounded-full transition-all duration-300"
            :style="{ width: `${analysisProgress}%` }"
          ></div>
        </div>
      </div>
      
      <!-- Error message for failed status -->
      <div v-if="wiki.analysis_status === 'failed'" class="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
        <div class="flex items-center">
          <AlertTriangle class="w-4 h-4 text-red-500 mr-2" />
          <span class="text-sm text-red-700 dark:text-red-300">Analysis failed</span>
        </div>
      </div>
      
      <!-- Action Buttons -->
      <div class="flex items-center justify-between">
        <div class="flex space-x-2">
          <!-- View Button -->
          <button
            @click="handleView"
            :disabled="!canView"
            :class="cn(
              'inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors',
              canView
                ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 hover:bg-blue-200 dark:hover:bg-blue-900/40'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 cursor-not-allowed'
            )"
          >
            <Eye class="w-4 h-4 mr-2" />
            View
          </button>
          
          <!-- Retry Button (for failed analyses) -->
          <button
            v-if="wiki.analysis_status === 'failed'"
            @click="handleRetry"
            class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg bg-yellow-100 dark:bg-yellow-900/20 text-yellow-700 dark:text-yellow-300 hover:bg-yellow-200 dark:hover:bg-yellow-900/40 transition-colors"
          >
            <RotateCcw class="w-4 h-4 mr-2" />
            Retry
          </button>
        </div>
        
        <!-- Delete Button -->
        <button
          @click="handleDelete"
          class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
        >
          <Trash2 class="w-4 h-4 mr-2" />
          Delete
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { 
  Calendar, 
  Eye, 
  Trash2, 
  AlertTriangle, 
  CheckCircle, 
  Clock, 
  XCircle,
  RotateCcw,
  Loader
} from 'lucide-vue-next'
import { cn } from '@/lib/utils'
import type { UserWiki } from '@/lib/types'

interface Props {
  wiki: UserWiki
}

interface Emits {
  (e: 'view', repoId: string): void
  (e: 'delete', wikiId: string): void
  (e: 'retry', wiki: UserWiki): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

// Mock analysis progress for demonstration
const analysisProgress = ref(65)

const canView = computed(() => {
  return props.wiki.analysis_status === 'completed' && props.wiki.repo_id
})

const getStatusBadgeClass = (status: string) => {
  switch (status) {
    case 'completed':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    case 'analyzing':
      return 'bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200'
    case 'failed':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    case 'pending':
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const getStatusIcon = (status: string) => {
  switch (status) {
    case 'completed':
      return CheckCircle
    case 'analyzing':
      return Loader
    case 'failed':
      return XCircle
    case 'pending':
    default:
      return Clock
  }
}

const getStatusText = (status: string) => {
  switch (status) {
    case 'completed':
      return 'Completed'
    case 'analyzing':
      return 'Analyzing'
    case 'failed':
      return 'Failed'
    case 'pending':
    default:
      return 'Pending'
  }
}

const formatDate = (dateString: string) => {
  const date = new Date(dateString)
  const now = new Date()
  const diffTime = Math.abs(now.getTime() - date.getTime())
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  
  if (diffDays === 1) {
    return 'today'
  } else if (diffDays === 2) {
    return 'yesterday'
  } else if (diffDays <= 7) {
    return `${diffDays - 1} days ago`
  } else {
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    })
  }
}

const handleView = () => {
  if (canView.value) {
    emit('view', props.wiki.repo_id)
  }
}

const handleDelete = () => {
  emit('delete', props.wiki.id)
}

const handleRetry = () => {
  emit('retry', props.wiki)
}
</script>

<style scoped>
/* Additional styles if needed */
</style>