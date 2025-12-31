<template>
  <div class="w-full max-w-2xl mx-auto">
    <form @submit="handleSubmit" class="space-y-6">
      <FormField
        label="Repository URL"
        type="url"
        v-model="repoUrl"
        placeholder="https://github.com/username/repository"
        :required="true"
        :disabled="isSubmitting"
        :validation-rules="validationRules"
        :validate-on-change="true"
        :validate-on-blur="true"
        auto-complete="url"
        class="mb-4"
      />

      <button
        type="submit"
        :disabled="isSubmitting || !repoUrl.trim()"
        :class="cn(
          'w-full py-3 px-6 rounded-lg font-medium transition-all duration-200',
          isSubmitting || !repoUrl.trim()
            ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 dark:text-gray-400 cursor-not-allowed'
            : 'bg-blue-600 hover:bg-blue-700 text-white shadow-lg hover:shadow-xl transform hover:-translate-y-0.5'
        )"
      >
        <div v-if="isSubmitting" class="flex items-center justify-center space-x-2">
          <LoadingSpinner size="small" />
          <span>Analyzing Repository...</span>
        </div>
        <span v-else>Analyze Repository</span>
      </button>

      <!-- Error Display -->
      <ErrorDisplay
        v-if="error"
        :error="error"
        title="Analysis Failed"
        :on-retry="handleRetry"
        :on-dismiss="dismissError"
        :show-retry="true"
        class="mt-4"
      />
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { api } from '@/lib/api'
import type { AnalyzeRepoRequest, AnalyzeRepoResponse } from '@/lib/types'
import { useToast } from '@/composables/useToast'
import { cn } from '@/lib/utils'
import FormField from './FormField.vue'
import ErrorDisplay from './ErrorDisplay.vue'
import LoadingSpinner from './LoadingSpinner.vue'

interface Props {
  onAnalysisStarted?: (response: AnalyzeRepoResponse, repoUrl: string) => void
}

const props = defineProps<Props>()

const repoUrl = ref('')
const isSubmitting = ref(false)
const error = ref<Error | null>(null)

const { showSuccess, showError } = useToast()

// Validation rules for the URL field
const validationRules = [
  {
    test: (value: string) => value.trim().length > 0,
    message: 'Repository URL is required'
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
      try {
        const url = new URL(value)
        return /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org|git\.)/.test(value)
      } catch {
        return false
      }
    },
    message: 'Please enter a valid Git repository URL (GitHub, GitLab, Bitbucket, etc.)'
  }
]

const handleSubmit = async (e: Event) => {
  e.preventDefault()
  
  if (!repoUrl.value.trim()) {
    return
  }

  isSubmitting.value = true
  error.value = null

  try {
    const request: AnalyzeRepoRequest = {
      repo_url: repoUrl.value.trim()
    }

    // First validate the repository
    const validation = await api.validateRepository(request)
    
    if (!validation.valid) {
      throw new Error(validation.message || 'Repository validation failed')
    }

    // Start the analysis
    const response = await api.analyzeRepository(request)
    
    // Show success toast
    showSuccess(
      'Analysis Started',
      'Repository analysis has been queued successfully!'
    )
    
    // Call the callback if provided
    if (props.onAnalysisStarted) {
      props.onAnalysisStarted(response, repoUrl.value.trim())
    }

    // Clear the form on success
    repoUrl.value = ''
    
  } catch (err) {
    const errorObj = err instanceof Error ? err : new Error('An unexpected error occurred')
    error.value = errorObj
    showError(
      'Analysis Failed',
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
</script>