<template>
  <div class="p-6">
    <div class="max-w-7xl mx-auto">
      <!-- Header -->
      <div class="mb-8">
        <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Did we do a good enough job?
        </h2>
        <p class="text-gray-600 dark:text-gray-400">
          Review and validation of the threat modeling process
        </p>
      </div>

      <!-- Loading State -->
      <div v-if="loading" class="flex items-center justify-center py-12">
        <LoadingSpinner size="large" message="Loading review status..." />
      </div>

      <!-- Review Content -->
      <div v-else class="space-y-8">
        <!-- Overall Status -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Review Status
            </h3>
            <span
              :class="getOverallStatusClass(reviewStatus?.overall_status)"
              class="px-3 py-1 rounded-full text-sm font-medium"
            >
              {{ reviewStatus?.overall_status || 'Pending' }}
            </span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {{ reviewProgress.completed }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Questions Reviewed</div>
            </div>
            <div class="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <div class="text-2xl font-bold text-green-600 dark:text-green-400">
                {{ checklistProgress.completed }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Checklist Items</div>
            </div>
            <div class="text-center p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
              <div class="text-2xl font-bold text-purple-600 dark:text-purple-400">
                {{ Math.round(overallProgress) }}%
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Overall Progress</div>
            </div>
            <div class="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              <div class="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {{ threatModel?.threats?.length || 0 }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Threats Reviewed</div>
            </div>
          </div>

          <!-- Progress Bar -->
          <div class="mt-6">
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                Review Progress
              </span>
              <span class="text-sm text-gray-500 dark:text-gray-400">
                {{ Math.round(overallProgress) }}%
              </span>
            </div>
            <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                :class="getProgressBarClass(overallProgress)"
                class="h-2 rounded-full transition-all duration-300"
                :style="{ width: `${overallProgress}%` }"
              ></div>
            </div>
          </div>
        </div>

        <!-- Four Questions Review -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <CheckCircle class="w-5 h-5 mr-2" />
            Four Questions Review
          </h3>
          
          <div class="space-y-4">
            <div
              v-for="question in fourQuestions"
              :key="question.id"
              class="flex items-center justify-between p-4 border border-gray-200 dark:border-gray-600 rounded-lg"
            >
              <div class="flex items-center space-x-3">
                <component
                  :is="question.icon"
                  class="w-5 h-5 text-gray-500 dark:text-gray-400"
                />
                <div>
                  <h4 class="font-medium text-gray-900 dark:text-gray-100">
                    {{ question.title }}
                  </h4>
                  <p class="text-sm text-gray-600 dark:text-gray-400">
                    {{ question.description }}
                  </p>
                </div>
              </div>
              <div class="flex items-center space-x-3">
                <button
                  @click="toggleQuestionReview(question.id)"
                  :class="isQuestionReviewed(question.id) 
                    ? 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200' 
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'"
                  class="px-3 py-1 rounded-full text-sm font-medium transition-colors"
                >
                  {{ isQuestionReviewed(question.id) ? 'Reviewed' : 'Mark as Reviewed' }}
                </button>
              </div>
            </div>
          </div>
        </div>

        <!-- Review Checklist -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 flex items-center">
              <ClipboardList class="w-5 h-5 mr-2" />
              OWASP Review Checklist
            </h3>
            <button
              @click="generateChecklist"
              class="px-3 py-2 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors"
            >
              Generate Checklist
            </button>
          </div>

          <div v-if="reviewStatus?.checklist_items?.length" class="space-y-3">
            <div
              v-for="item in reviewStatus.checklist_items"
              :key="item.id"
              class="flex items-start space-x-3 p-3 border border-gray-200 dark:border-gray-600 rounded-lg"
            >
              <button
                @click="toggleChecklistItem(item.id)"
                :class="item.status === 'completed' 
                  ? 'text-green-600 dark:text-green-400' 
                  : item.status === 'not_applicable'
                  ? 'text-gray-400 dark:text-gray-500'
                  : 'text-gray-300 dark:text-gray-600'"
                class="mt-0.5 transition-colors"
              >
                <CheckCircle class="w-5 h-5" />
              </button>
              <div class="flex-1">
                <p class="text-sm text-gray-900 dark:text-gray-100">
                  {{ item.description }}
                </p>
                <div v-if="item.notes" class="mt-1">
                  <textarea
                    v-model="item.notes"
                    @blur="updateChecklistItem(item)"
                    placeholder="Add notes..."
                    class="w-full text-xs text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-700 border border-gray-200 dark:border-gray-600 rounded px-2 py-1 resize-none"
                    rows="2"
                  ></textarea>
                </div>
              </div>
              <div class="flex items-center space-x-2">
                <select
                  :value="item.status"
                  @change="updateChecklistItemStatus(item.id, ($event.target as HTMLSelectElement).value)"
                  class="text-xs rounded border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="pending">Pending</option>
                  <option value="completed">Completed</option>
                  <option value="not_applicable">N/A</option>
                </select>
              </div>
            </div>
          </div>

          <div v-else class="text-center py-8">
            <ClipboardList class="w-12 h-12 text-gray-400 mx-auto mb-3" />
            <p class="text-gray-600 dark:text-gray-400 mb-4">
              No review checklist generated yet
            </p>
            <button
              @click="generateChecklist"
              class="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700"
            >
              Generate OWASP Checklist
            </button>
          </div>
        </div>

        <!-- Review Summary -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <FileText class="w-5 h-5 mr-2" />
            Review Summary
          </h3>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <!-- Review Metadata -->
            <div class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Reviewer
                </label>
                <input
                  v-model="localReviewStatus.reviewer"
                  @blur="updateReviewStatus"
                  type="text"
                  placeholder="Enter reviewer name"
                  class="w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
                />
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Review Date
                </label>
                <input
                  v-model="localReviewStatus.review_date"
                  @blur="updateReviewStatus"
                  type="date"
                  class="w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
                />
              </div>
            </div>

            <!-- Review Actions -->
            <div class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Overall Status
                </label>
                <select
                  v-model="localReviewStatus.overall_status"
                  @change="updateReviewStatus"
                  class="w-full rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
                >
                  <option value="pending">Pending Review</option>
                  <option value="in_progress">In Progress</option>
                  <option value="completed">Completed</option>
                  <option value="requires_revision">Requires Revision</option>
                </select>
              </div>
              <div class="flex space-x-3">
                <button
                  @click="exportReview"
                  class="flex-1 inline-flex items-center justify-center px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 hover:bg-gray-50 dark:hover:bg-gray-600"
                >
                  <Download class="w-4 h-4 mr-2" />
                  Export Review
                </button>
                <button
                  @click="completeReview"
                  :disabled="!canCompleteReview"
                  :class="canCompleteReview 
                    ? 'bg-green-600 hover:bg-green-700 text-white' 
                    : 'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed'"
                  class="flex-1 inline-flex items-center justify-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium"
                >
                  <CheckCircle class="w-4 h-4 mr-2" />
                  Complete Review
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { 
  CheckCircle, 
  ClipboardList, 
  FileText, 
  Download,
  Building2,
  AlertTriangle,
  Shield
} from 'lucide-vue-next'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import { useToast } from '@/composables/useToast'

// Props
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

interface Props {
  threatModel?: any
  reviewStatus?: ReviewStatus
  loading?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  loading: false
})

// Emits
const emit = defineEmits<{
  updateReview: [reviewStatus: ReviewStatus]
}>()

// Composables
const { showSuccess, showError } = useToast()

// State
const localReviewStatus = ref<ReviewStatus>({
  overall_status: 'pending',
  questions_reviewed: [],
  checklist_items: [],
  reviewer: '',
  review_date: ''
})

// Watch for prop changes
watch(() => props.reviewStatus, (newStatus) => {
  if (newStatus) {
    localReviewStatus.value = { ...newStatus }
  }
}, { immediate: true, deep: true })

// Four Questions Configuration
const fourQuestions = [
  {
    id: 'system',
    title: 'What are we working on?',
    icon: Building2,
    description: 'System architecture and components reviewed'
  },
  {
    id: 'threats',
    title: 'What can go wrong?',
    icon: AlertTriangle,
    description: 'STRIDE threat analysis validated'
  },
  {
    id: 'mitigations',
    title: 'What are we going to do about it?',
    icon: Shield,
    description: 'Mitigations and responses assessed'
  },
  {
    id: 'review',
    title: 'Did we do a good enough job?',
    icon: CheckCircle,
    description: 'Review process completed'
  }
]

// Computed properties
const reviewProgress = computed(() => {
  const total = fourQuestions.length
  const completed = localReviewStatus.value.questions_reviewed?.length || 0
  return { total, completed }
})

const checklistProgress = computed(() => {
  const items = localReviewStatus.value.checklist_items || []
  const total = items.length
  const completed = items.filter(item => item.status === 'completed').length
  return { total, completed }
})

const overallProgress = computed(() => {
  const questionWeight = 0.6
  const checklistWeight = 0.4
  
  const questionProgress = reviewProgress.value.total > 0 
    ? (reviewProgress.value.completed / reviewProgress.value.total) * 100 
    : 0
  
  const checklistProgressValue = checklistProgress.value.total > 0 
    ? (checklistProgress.value.completed / checklistProgress.value.total) * 100 
    : 0
  
  return (questionProgress * questionWeight) + (checklistProgressValue * checklistWeight)
})

const canCompleteReview = computed(() => {
  return reviewProgress.value.completed === reviewProgress.value.total &&
         checklistProgress.value.completed === checklistProgress.value.total &&
         localReviewStatus.value.reviewer.trim() !== ''
})

// Methods
const isQuestionReviewed = (questionId: string) => {
  return localReviewStatus.value.questions_reviewed?.includes(questionId) || false
}

const toggleQuestionReview = (questionId: string) => {
  const reviewed = localReviewStatus.value.questions_reviewed || []
  const index = reviewed.indexOf(questionId)
  
  if (index > -1) {
    reviewed.splice(index, 1)
  } else {
    reviewed.push(questionId)
  }
  
  localReviewStatus.value.questions_reviewed = [...reviewed]
  updateReviewStatus()
}

const toggleChecklistItem = (itemId: string) => {
  const item = localReviewStatus.value.checklist_items?.find(i => i.id === itemId)
  if (item) {
    item.status = item.status === 'completed' ? 'pending' : 'completed'
    updateReviewStatus()
  }
}

const updateChecklistItemStatus = (itemId: string, status: string) => {
  const item = localReviewStatus.value.checklist_items?.find(i => i.id === itemId)
  if (item) {
    item.status = status as 'pending' | 'completed' | 'not_applicable'
    updateReviewStatus()
  }
}

const updateChecklistItem = (item: any) => {
  updateReviewStatus()
}

const updateReviewStatus = () => {
  emit('updateReview', { ...localReviewStatus.value })
}

const generateChecklist = async () => {
  try {
    // Generate OWASP-based checklist items
    const checklistItems = [
      {
        id: 'threat-model-scope',
        description: 'Threat model scope is clearly defined and documented',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'system-boundaries',
        description: 'System boundaries and trust boundaries are properly identified',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'data-flows',
        description: 'All data flows are documented and classified appropriately',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'stride-coverage',
        description: 'STRIDE analysis covers all system components and interfaces',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'threat-likelihood',
        description: 'Threat likelihood assessments are realistic and justified',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'impact-assessment',
        description: 'Impact assessments consider business and technical consequences',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'mitigation-coverage',
        description: 'All high and medium risk threats have appropriate mitigations',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'owasp-alignment',
        description: 'Mitigations align with OWASP best practices and guidelines',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'implementation-guidance',
        description: 'Implementation guidance is clear and actionable',
        status: 'pending' as const,
        notes: ''
      },
      {
        id: 'review-completeness',
        description: 'Threat model review is thorough and well-documented',
        status: 'pending' as const,
        notes: ''
      }
    ]

    localReviewStatus.value.checklist_items = checklistItems
    updateReviewStatus()
    showSuccess('Checklist Generated', 'OWASP review checklist has been generated')
  } catch (error) {
    showError('Generation Failed', 'Failed to generate review checklist')
  }
}

const exportReview = () => {
  try {
    const reviewData = {
      threat_model_id: props.threatModel?.id,
      review_status: localReviewStatus.value,
      export_date: new Date().toISOString(),
      progress: {
        questions: reviewProgress.value,
        checklist: checklistProgress.value,
        overall: overallProgress.value
      }
    }

    const blob = new Blob([JSON.stringify(reviewData, null, 2)], { 
      type: 'application/json' 
    })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threat-model-review-${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    showSuccess('Export Complete', 'Review data has been exported successfully')
  } catch (error) {
    showError('Export Failed', 'Failed to export review data')
  }
}

const completeReview = () => {
  if (!canCompleteReview.value) return

  localReviewStatus.value.overall_status = 'completed'
  localReviewStatus.value.review_date = new Date().toISOString().split('T')[0]
  updateReviewStatus()
  showSuccess('Review Complete', 'Threat model review has been marked as complete')
}

// Utility functions
const getOverallStatusClass = (status: string) => {
  switch (status?.toLowerCase()) {
    case 'completed':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    case 'in_progress':
      return 'bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200'
    case 'requires_revision':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    default:
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
  }
}

const getProgressBarClass = (progress: number) => {
  if (progress >= 90) return 'bg-green-600'
  if (progress >= 70) return 'bg-blue-600'
  if (progress >= 50) return 'bg-yellow-600'
  return 'bg-red-600'
}
</script>

<style scoped>
/* Component-specific styles */
.review-status-card {
  @apply bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6;
}

.question-review-item {
  @apply flex items-center justify-between p-4 border border-gray-200 dark:border-gray-600 rounded-lg;
}

.checklist-item {
  @apply flex items-start space-x-3 p-3 border border-gray-200 dark:border-gray-600 rounded-lg;
}

.progress-bar {
  @apply w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2;
}
</style>