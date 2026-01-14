<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <div class="container mx-auto px-4 py-12">
      <!-- Header -->
      <div class="text-center mb-12">
        <h1 class="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          ThreatLens
        </h1>
        <p class="text-xl text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
          GPU-powered security documentation generator. 
          Analyze repositories or pull requests to generate comprehensive security analysis and documentation.
        </p>
      </div>

      <!-- Main Content -->
      <div class="space-y-12">
        <!-- Analysis Mode Selection -->
        <section>
          <div class="text-center mb-8">
            <h2 class="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-6">
              Choose Analysis Mode
            </h2>
          </div>
          
          <AnalysisModeToggle v-model="analysisMode" />
          
          <!-- Repository Analysis Form -->
          <div v-if="analysisMode === 'repository'">
            <RepoForm @analysis-started="handleRepoAnalysisStarted" />
          </div>
          
          <!-- PR Analysis Form -->
          <div v-else>
            <PRForm @analysis-started="handlePRAnalysisStarted" />
          </div>
        </section>

        <!-- My Security Wikis Section (Phase 1 MVP) -->
        <section class="mt-16">
          <div class="text-center mb-8">
            <h2 class="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
              My Security Wikis
            </h2>
            <p class="text-gray-600 dark:text-gray-400">
              Your personal collection of security analyses
            </p>
          </div>
          
          <!-- Loading State -->
          <div v-if="wikisLoading" class="flex justify-center py-8">
            <LoadingSpinner size="medium" message="Loading your wikis..." />
          </div>
          
          <!-- Error State -->
          <div v-else-if="wikisError" class="max-w-md mx-auto">
            <ErrorDisplay
              :error="wikisError"
              title="Failed to load wikis"
              :on-retry="loadUserWikis"
              :show-retry="true"
            />
          </div>
          
          <!-- Empty State -->
          <div v-else-if="userWikis.length === 0" data-testid="empty-state" class="text-center py-12">
            <div class="w-16 h-16 bg-gray-100 dark:bg-gray-800 rounded-full flex items-center justify-center mx-auto mb-4">
              <FileText class="w-8 h-8 text-gray-400" />
            </div>
            <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
              No security wikis yet
            </h3>
            <p class="text-gray-600 dark:text-gray-400 mb-6">
              Analyze your first repository above to create your first security wiki
            </p>
          </div>
          
          <!-- Wiki Grid -->
          <div v-else class="grid md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
            <WikiCard
              v-for="wiki in userWikis"
              :key="wiki.id"
              :wiki="wiki"
              @view="handleWikiView"
              @delete="handleWikiDelete"
              @retry="handleWikiRetry"
            />
          </div>
          
          <!-- Show More Button (for future pagination) -->
          <div v-if="userWikis.length >= 6" class="text-center mt-8">
            <button
              @click="loadMoreWikis"
              :disabled="loadingMore"
              class="inline-flex items-center px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50"
            >
              <span v-if="!loadingMore">Show More</span>
              <span v-else class="flex items-center">
                <LoadingSpinner size="small" class="mr-2" />
                Loading...
              </span>
            </button>
          </div>
        </section>

        <!-- Features Overview -->
        <section class="mt-16">
          <div class="text-center mb-8">
            <h2 class="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
              What ThreatLens Does
            </h2>
          </div>
          <div class="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div class="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <div class="w-12 h-12 bg-blue-100 dark:bg-blue-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <CheckCircle class="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Code Analysis
              </h3>
              <p class="text-gray-600 dark:text-gray-400 text-sm">
                Automatically analyzes your codebase to identify components, data flows, and security patterns
              </p>
            </div>
            
            <div class="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <div class="w-12 h-12 bg-red-100 dark:bg-red-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <AlertTriangle class="w-6 h-6 text-red-600 dark:text-red-400" />
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Security Assessment
              </h3>
              <p class="text-gray-600 dark:text-gray-400 text-sm">
                Identifies potential security threats, vulnerabilities, and provides comprehensive security analysis
              </p>
            </div>
            
            <div class="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <div class="w-12 h-12 bg-green-100 dark:bg-green-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <FileText class="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Documentation
              </h3>
              <p class="text-gray-600 dark:text-gray-400 text-sm">
                Generates comprehensive security documentation with recommendations and mitigation strategies
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { CheckCircle, AlertTriangle, FileText } from 'lucide-vue-next'
import RepoForm from '@/components/RepoForm.vue'
import PRForm from '@/components/PRForm.vue'
import AnalysisModeToggle from '@/components/AnalysisModeToggle.vue'
import WikiCard from '@/components/WikiCard.vue'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import ErrorDisplay from '@/components/ErrorDisplay.vue'
import { api } from '@/lib/api'
import { useToast } from '@/composables/useToast'
import type { AnalyzeRepoResponse, AnalyzePRResponse, UserWiki } from '@/lib/types'

const router = useRouter()
const { showSuccess, showError } = useToast()

// Analysis mode
const analysisMode = ref<'repository' | 'pr'>('repository')

// User wikis state
const userWikis = ref<UserWiki[]>([])
const wikisLoading = ref(false)
const wikisError = ref<string | null>(null)
const loadingMore = ref(false)

// Generate or get user ID (Phase 1 MVP - browser-based)
const getUserId = (): string => {
  let userId = localStorage.getItem('threatlens_user_id')
  if (!userId) {
    // Generate simple user ID based on browser fingerprint
    const fingerprint = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      new Date().getTimezoneOffset()
    ].join('|')
    
    // Create hash-like ID
    let hash = 0
    for (let i = 0; i < fingerprint.length; i++) {
      const char = fingerprint.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
      hash = hash & hash // Convert to 32-bit integer
    }
    
    userId = `user_${Math.abs(hash).toString(16)}`
    localStorage.setItem('threatlens_user_id', userId)
  }
  return userId
}

const loadUserWikis = async () => {
  try {
    wikisLoading.value = true
    wikisError.value = null
    
    const userId = getUserId()
    const response = await api.getUserWikis(userId)
    userWikis.value = response.wikis || []
    
  } catch (error) {
    console.error('Error loading user wikis:', error)
    wikisError.value = error instanceof Error ? error.message : 'Failed to load wikis'
  } finally {
    wikisLoading.value = false
  }
}

const loadMoreWikis = async () => {
  // Placeholder for future pagination implementation
  loadingMore.value = true
  setTimeout(() => {
    loadingMore.value = false
  }, 1000)
}

const handleRepoAnalysisStarted = (response: AnalyzeRepoResponse, repoUrl: string) => {
  // Refresh user wikis to show the new analyzing entry
  loadUserWikis()
  
  // Navigate to the repository page after a short delay to show the status
  setTimeout(() => {
    router.push(`/${response.repo_id}`)
  }, 2000)
}

const handlePRAnalysisStarted = (response: AnalyzePRResponse, prUrl: string) => {
  // Navigate to the PR analysis page after a short delay to show the status
  setTimeout(() => {
    router.push(`/pr/${response.pr_id}`)
  }, 2000)
}

const handleWikiView = (repoId: string) => {
  router.push(`/${repoId}`)
}

const handleWikiDelete = async (wikiId: string) => {
  if (!confirm('Are you sure you want to delete this security wiki? This action cannot be undone.')) {
    return
  }
  
  try {
    const userId = getUserId()
    await api.deleteUserWiki(userId, wikiId)
    
    // Remove from local state
    userWikis.value = userWikis.value.filter(w => w.id !== wikiId)
    
    showSuccess('Wiki deleted', 'Security wiki has been removed from your collection')
  } catch (error) {
    console.error('Error deleting wiki:', error)
    showError('Delete failed', 'Failed to delete the security wiki')
  }
}

const handleWikiRetry = async (wiki: UserWiki) => {
  try {
    // Trigger re-analysis by calling the analyze endpoint again
    const response = await api.analyzeRepository({
      repo_url: wiki.repository_url
    })
    
    showSuccess('Analysis restarted', 'Repository analysis has been restarted')
    
    // Refresh wikis to show updated status
    loadUserWikis()
    
  } catch (error) {
    console.error('Error retrying analysis:', error)
    showError('Retry failed', 'Failed to restart the analysis')
  }
}

// Load user wikis on component mount
onMounted(() => {
  loadUserWikis()
})
</script>
