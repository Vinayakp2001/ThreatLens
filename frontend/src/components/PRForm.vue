<template>
  <div class="w-full max-w-2xl mx-auto">
    <form @submit="handleSubmit" class="space-y-6">
      <FormField
        label="Pull Request URL"
        type="url"
        v-model="prUrl"
        placeholder="https://github.com/username/repository/pull/123"
        :required="true"
        :disabled="isSubmitting"
        :validation-rules="validationRules"
        :validate-on-change="true"
        :validate-on-blur="true"
        auto-complete="url"
        class="mb-4"
      />

      <!-- Context Status Display -->
      <div v-if="contextStatus" class="p-4 rounded-lg border" :class="contextStatusClass">
        <div class="flex items-center space-x-2">
          <CheckCircle v-if="contextStatus.exists" class="w-5 h-5 text-green-600" />
          <AlertCircle v-else class="w-5 h-5 text-yellow-600" />
          <span class="font-medium">{{ contextStatus.message }}</span>
        </div>
        
        <!-- Smart Guidance Display -->
        <div v-if="contextStatus.guidance && contextStatus.guidance.show_guidance" class="mt-3">
          <div class="space-y-2">
            <p v-for="message in contextStatus.guidance.messages" :key="message" class="text-sm text-gray-600 dark:text-gray-400">
              {{ message }}
            </p>
          </div>
          
          <!-- Action Buttons -->
          <div v-if="contextStatus.guidance.actions && contextStatus.guidance.actions.length > 0" class="mt-4 space-y-2">
            <div class="text-sm font-medium text-gray-700 dark:text-gray-300">Recommended Actions:</div>
            <div class="space-y-2">
              <button
                v-for="action in contextStatus.guidance.actions"
                :key="action.action"
                @click="handleGuidanceAction(action)"
                class="w-full text-left p-3 rounded-lg border border-gray-200 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
              >
                <div class="flex items-center justify-between">
                  <div>
                    <div class="font-medium text-gray-900 dark:text-gray-100">{{ action.label }}</div>
                    <div class="text-sm text-gray-600 dark:text-gray-400">{{ action.description }}</div>
                  </div>
                  <div class="text-xs text-gray-500 dark:text-gray-400">{{ action.estimated_time }}</div>
                </div>
              </button>
            </div>
          </div>
        </div>
        
        <!-- Fallback guidance for simple context status -->
        <p v-else-if="!contextStatus.exists" class="text-sm mt-2 text-gray-600 dark:text-gray-400">
          For better analysis results, consider analyzing the full repository first.
        </p>
      </div>

      <button
        type="submit"
        :disabled="isSubmitting || !prUrl.trim()"
        :class="cn(
          'w-full py-3 px-6 rounded-lg font-medium transition-all duration-200',
          isSubmitting || !prUrl.trim()
            ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 dark:text-gray-400 cursor-not-allowed'
            : 'bg-purple-600 hover:bg-purple-700 text-white shadow-lg hover:shadow-xl transform hover:-translate-y-0.5'
        )"
      >
        <div v-if="isSubmitting" class="flex items-center justify-center space-x-2">
          <LoadingSpinner size="small" />
          <span>Analyzing Pull Request...</span>
        </div>
        <span v-else>Analyze Pull Request</span>
      </button>

      <!-- Error Display -->
      <ErrorDisplay
        v-if="error"
        :error="error"
        title="PR Analysis Failed"
        :on-retry="handleRetry"
        :on-dismiss="dismissError"
        :show-retry="true"
        class="mt-4"
      />
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import { CheckCircle, AlertCircle } from 'lucide-vue-next'
import { api } from '@/lib/api'
import type { AnalyzePRRequest, AnalyzePRResponse, RepoStatusResponse } from '@/lib/types'
import { useToast } from '@/composables/useToast'
import { cn } from '@/lib/utils'
import FormField from './FormField.vue'
import ErrorDisplay from './ErrorDisplay.vue'
import LoadingSpinner from './LoadingSpinner.vue'

interface Props {
  onAnalysisStarted?: (response: AnalyzePRResponse, prUrl: string) => void
}

const props = defineProps<Props>()

const prUrl = ref('')
const isSubmitting = ref(false)
const error = ref<Error | null>(null)
const contextStatus = ref<{ exists: boolean; message: string } | null>(null)

const { showSuccess, showError } = useToast()

// Validation rules for the PR URL field
const validationRules = [
  {
    test: (value: string) => value.trim().length > 0,
    message: 'Pull Request URL is required'
  },
  {
    test: (value: string) => {
      try {
        new URL(value)
        return true
      } catch {
        return false
      }
    },
    message: 'Please enter a valid URL'
  },
  {
    test: (value: string) => {
      const prPattern = /^https:\/\/github\.com\/[^\/]+\/[^\/]+\/pull\/\d+/
      return prPattern.test(value)
    },
    message: 'Please enter a valid GitHub Pull Request URL (e.g., https://github.com/user/repo/pull/123)'
  }
]

const contextStatusClass = computed(() => {
  if (!contextStatus.value) return ''
  
  return contextStatus.value.exists
    ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-800 dark:text-green-200'
    : 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-200'
})

// Extract repo info from PR URL
const extractRepoInfo = (url: string) => {
  const match = url.match(/^https:\/\/github\.com\/([^\/]+)\/([^\/]+)\/pull\/(\d+)/)
  if (match) {
    return {
      owner: match[1],
      repo: match[2],
      prNumber: match[3],
      repoId: `github_${match[1]}_${match[2]}`
    }
  }
  return null
}

// Check repository context when PR URL changes
watch(prUrl, async (newUrl) => {
  if (!newUrl.trim()) {
    contextStatus.value = null
    return
  }

  const repoInfo = extractRepoInfo(newUrl.trim())
  if (!repoInfo) {
    contextStatus.value = null
    return
  }

  try {
    // Use the new smart context checking endpoint
    const contextCheck = await api.checkPRContextRequirements({
      pr_url: newUrl.trim(),
      repo_id: repoInfo.repoId
    })
    
    if (contextCheck.error) {
      contextStatus.value = {
        exists: false,
        message: '⚠ Unable to check repository context'
      }
      return
    }
    
    const requirements = contextCheck.requirements
    const guidance = contextCheck.guidance
    
    contextStatus.value = {
      exists: requirements.context_available,
      message: requirements.context_available 
        ? `✓ Repository context available (Quality: ${Math.round(requirements.context_quality * 100)}%)`
        : '⚠ No repository context found',
      guidance: guidance,
      requirements: requirements
    }
  } catch (err) {
    // Fallback to original repo status check
    try {
      const status = await api.getRepositoryStatus(repoInfo.repoId)
      contextStatus.value = {
        exists: status.exists,
        message: status.exists 
          ? `✓ Repository context available (${status.document_count} security documents)`
          : '⚠ No repository context found'
      }
    } catch (fallbackErr) {
      contextStatus.value = {
        exists: false,
        message: '⚠ Unable to check repository context'
      }
    }
  }
}, { debounce: 500 })

const handleSubmit = async (e: Event) => {
  e.preventDefault()
  
  if (!prUrl.value.trim()) {
    return
  }

  isSubmitting.value = true
  error.value = null

  try {
    const repoInfo = extractRepoInfo(prUrl.value.trim())
    
    const request: AnalyzePRRequest = {
      pr_url: prUrl.value.trim(),
      repo_id: repoInfo?.repoId
    }

    // Start the PR analysis
    const response = await api.analyzePR(request)
    
    // Show success toast
    showSuccess(
      'PR Analysis Started',
      `Pull request analysis has been queued successfully!${response.has_repo_context ? ' Using repository context for enhanced analysis.' : ''}`
    )
    
    // Call the callback if provided
    if (props.onAnalysisStarted) {
      props.onAnalysisStarted(response, prUrl.value.trim())
    }

    // Clear the form on success
    prUrl.value = ''
    contextStatus.value = null
    
  } catch (err) {
    const errorObj = err instanceof Error ? err : new Error('An unexpected error occurred')
    error.value = errorObj
    showError(
      'PR Analysis Failed',
      errorObj.message,
      {
        label: 'Try Again',
        onClick: handleRetry
      }
    )
  } finally {
    isSubmitting.value = false
  }
}

const handleRetry = () => {
  error.value = null
  handleSubmit(new Event('submit'))
}

const dismissError = () => {
  error.value = null
}

const handleGuidanceAction = (action: any) => {
  if (action.action === 'analyze_repository') {
    // Navigate to repository analysis
    const repoInfo = extractRepoInfo(prUrl.value.trim())
    if (repoInfo) {
      // You could emit an event or use router to navigate to repo analysis
      showSuccess('Repository Analysis', 'Redirecting to full repository analysis...')
      // For now, just show a message - in a real app you'd navigate to repo analysis
      setTimeout(() => {
        window.location.href = `/?mode=repository&url=https://github.com/${repoInfo.owner}/${repoInfo.repo}`
      }, 1000)
    }
  } else if (action.action === 'proceed_without_context') {
    // Proceed with PR analysis anyway
    handleSubmit(new Event('submit'))
  } else if (action.action === 'refresh_analysis') {
    // Refresh repository analysis
    showSuccess('Refresh Analysis', 'Repository analysis refresh would be triggered here')
  }
}
</script>