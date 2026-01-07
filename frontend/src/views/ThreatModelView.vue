<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <!-- Loading State -->
    <div v-if="loading" class="min-h-screen flex items-center justify-center">
      <LoadingSpinner size="large" message="Loading threat model..." />
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="min-h-screen flex items-center justify-center p-4">
      <div class="max-w-md w-full">
        <ErrorDisplay
          :error="error"
          title="Error Loading Threat Model"
          :on-retry="loadThreatModel"
          :show-retry="true"
        />
      </div>
    </div>

    <!-- Main Content -->
    <div v-else class="flex flex-col h-screen">
      <!-- Header -->
      <div class="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4">
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-2xl font-bold text-gray-900 dark:text-gray-100">
              Threat Model: {{ threatModel?.system_name || repoId }}
            </h1>
            <p class="text-sm text-gray-600 dark:text-gray-400 mt-1">
              OWASP Four Questions Methodology
            </p>
          </div>
          <div class="flex items-center space-x-3">
            <!-- Export Button -->
            <button
              @click="exportThreatModel"
              class="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
            >
              <Download class="w-4 h-4 mr-2" />
              Export
            </button>
            <!-- Refresh Button -->
            <button
              @click="loadThreatModel"
              class="inline-flex items-center px-3 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
            >
              <RefreshCw class="w-4 h-4 mr-2" />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <!-- Four Questions Navigation Tabs -->
      <div class="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <nav class="flex space-x-8 px-6" aria-label="Tabs">
          <button
            v-for="question in fourQuestions"
            :key="question.id"
            @click="activeQuestion = question.id"
            :class="cn(
              'whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm transition-colors',
              activeQuestion === question.id
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
            )"
          >
            <div class="flex items-center space-x-2">
              <component :is="question.icon" class="w-5 h-5" />
              <span>{{ question.title }}</span>
            </div>
          </button>
        </nav>
      </div>

      <!-- Question Content -->
      <div class="flex-1 overflow-hidden">
        <!-- Question 1: What are we working on? -->
        <div v-if="activeQuestion === 'system'" class="h-full overflow-y-auto">
          <SystemModelView 
            :system="threatModel?.system"
            :loading="loading"
          />
        </div>

        <!-- Question 2: What can go wrong? -->
        <div v-if="activeQuestion === 'threats'" class="h-full overflow-y-auto">
          <ThreatAnalysisView 
            :threats="threatModel?.threats || []"
            :system="threatModel?.system"
            :loading="loading"
          />
        </div>

        <!-- Question 3: What are we going to do about it? -->
        <div v-if="activeQuestion === 'mitigations'" class="h-full overflow-y-auto">
          <MitigationView 
            :threats="threatModel?.threats || []"
            :mitigations="threatModel?.mitigations || []"
            :loading="loading"
          />
        </div>

        <!-- Question 4: Did we do a good enough job? -->
        <div v-if="activeQuestion === 'review'" class="h-full overflow-y-auto">
          <ReviewStatusView 
            :threat-model="threatModel"
            :review-status="reviewStatus"
            :loading="loading"
            @update-review="handleReviewUpdate"
          />
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { 
  Building2, 
  AlertTriangle, 
  Shield, 
  CheckCircle, 
  Download, 
  RefreshCw 
} from 'lucide-vue-next'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import ErrorDisplay from '@/components/ErrorDisplay.vue'
import SystemModelView from '@/components/threat-model/SystemModelView.vue'
import ThreatAnalysisView from '@/components/threat-model/ThreatAnalysisView.vue'
import MitigationView from '@/components/threat-model/MitigationView.vue'
import ReviewStatusView from '@/components/threat-model/ReviewStatusView.vue'
import { useToast } from '@/composables/useToast'

// Types
interface ThreatModel {
  system_name: string
  system: {
    id: string
    name: string
    description: string
    components: Array<{
      id: string
      name: string
      type: string
      trust_level: string
      interfaces: any[]
    }>
    data_stores: Array<{
      id: string
      name: string
      type: string
      data_classification: string
    }>
    data_flows: Array<{
      id: string
      source: string
      destination: string
      data_classification: string
      protocol: string
      authentication_required: boolean
    }>
    external_entities: Array<{
      id: string
      name: string
      type: string
      trust_level: string
    }>
    trust_boundaries: Array<{
      id: string
      name: string
      components: string[]
    }>
    cloud_context: {
      provider: string
      services_used: string[]
      deployment_model: string
      compliance_requirements: string[]
    }
  }
  threats: Array<{
    id: string
    title: string
    description: string
    stride_category: string
    likelihood: string
    impact: string
    risk_score: number
    affected_assets: string[]
    attack_vectors: string[]
    mitigations: string[]
    owasp_references: string[]
  }>
  mitigations: Array<{
    id: string
    title: string
    description: string
    category: string
    owasp_cheatsheet_ids: string[]
    asvs_references: string[]
    implementation_guidance: string
    priority: string
  }>
  created_at: string
  updated_at: string
}

interface ReviewStatus {
  overall_status: string
  questions_reviewed: string[]
  checklist_items: Array<{
    id: string
    description: string
    status: 'pending' | 'completed' | 'not_applicable'
    notes?: string
  }>
  reviewer: string
  review_date: string
}

// Component setup
const route = useRoute()
const repoId = route.params.repoId as string
const { showSuccess, showError } = useToast()

// State
const threatModel = ref<ThreatModel | null>(null)
const reviewStatus = ref<ReviewStatus | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)
const activeQuestion = ref<string>('system')

// Four Questions Configuration
const fourQuestions = [
  {
    id: 'system',
    title: 'What are we working on?',
    icon: Building2,
    description: 'System architecture and components'
  },
  {
    id: 'threats',
    title: 'What can go wrong?',
    icon: AlertTriangle,
    description: 'STRIDE threat analysis'
  },
  {
    id: 'mitigations',
    title: 'What are we going to do about it?',
    icon: Shield,
    description: 'Mitigations and responses'
  },
  {
    id: 'review',
    title: 'Did we do a good enough job?',
    icon: CheckCircle,
    description: 'Review and validation'
  }
]

// Methods
const loadThreatModel = async () => {
  try {
    loading.value = true
    error.value = null

    // Load threat model data
    const response = await api.getThreatModel(repoId)
    threatModel.value = response

    // Load review status
    try {
      const reviewResponse = await api.getReviewStatus(repoId)
      reviewStatus.value = reviewResponse
    } catch (reviewError) {
      // Review status might not exist yet, that's okay
      console.log('No review status found, creating default')
      reviewStatus.value = {
        overall_status: 'pending',
        questions_reviewed: [],
        checklist_items: [],
        reviewer: '',
        review_date: ''
      }
    }

  } catch (err) {
    console.error('Error loading threat model:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load threat model'
  } finally {
    loading.value = false
  }
}

const handleReviewUpdate = async (updatedReview: ReviewStatus) => {
  try {
    await api.updateReviewStatus(repoId, updatedReview)
    reviewStatus.value = updatedReview
    showSuccess('Review Updated', 'Review status has been saved successfully')
  } catch (err) {
    console.error('Error updating review:', err)
    showError('Update Failed', 'Failed to save review status')
  }
}

const exportThreatModel = async () => {
  try {
    if (!threatModel.value) return

    const exportData = {
      ...threatModel.value,
      review_status: reviewStatus.value,
      export_date: new Date().toISOString()
    }

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { 
      type: 'application/json' 
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threat-model-${repoId}-${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    showSuccess('Export Complete', 'Threat model has been exported successfully')
  } catch (err) {
    console.error('Error exporting threat model:', err)
    showError('Export Failed', 'Failed to export threat model')
  }
}

// Computed properties
const currentQuestion = computed(() => {
  return fourQuestions.find(q => q.id === activeQuestion.value)
})

// Lifecycle
onMounted(() => {
  loadThreatModel()
})
</script>

<style scoped>
/* Custom styles for threat model view */
.threat-model-nav {
  @apply flex space-x-8 px-6;
}

.threat-model-tab {
  @apply whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm transition-colors;
}

.threat-model-tab.active {
  @apply border-blue-500 text-blue-600 dark:text-blue-400;
}

.threat-model-tab.inactive {
  @apply border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600;
}

.question-content {
  @apply h-full overflow-y-auto;
}
</style>