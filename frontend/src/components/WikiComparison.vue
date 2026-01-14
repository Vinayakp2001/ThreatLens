<template>
  <div class="wiki-comparison">
    <div class="comparison-header">
      <h2 class="text-2xl font-bold mb-4">Security Wiki Comparison</h2>
      <div class="flex gap-4 mb-6">
        <div class="flex-1">
          <label class="block text-sm font-medium mb-2">Baseline Wiki</label>
          <select 
            v-model="selectedBaseline" 
            class="w-full p-2 border rounded-md"
            @change="loadComparison"
          >
            <option value="">Select baseline wiki...</option>
            <option v-for="wiki in availableWikis" :key="wiki.id" :value="wiki.id">
              {{ wiki.title }} ({{ formatDate(wiki.created_at) }})
            </option>
          </select>
        </div>
        <div class="flex-1">
          <label class="block text-sm font-medium mb-2">Current Wiki</label>
          <select 
            v-model="selectedCurrent" 
            class="w-full p-2 border rounded-md"
            @change="loadComparison"
          >
            <option value="">Select current wiki...</option>
            <option v-for="wiki in availableWikis" :key="wiki.id" :value="wiki.id">
              {{ wiki.title }} ({{ formatDate(wiki.created_at) }})
            </option>
          </select>
        </div>
      </div>
    </div>

    <div v-if="loading" class="text-center py-8">
      <LoadingSpinner />
      <p class="mt-2 text-gray-600">Analyzing security changes...</p>
    </div>

    <div v-else-if="comparison" class="comparison-results">
      <!-- Summary Section -->
      <div class="summary-card bg-white rounded-lg shadow-md p-6 mb-6">
        <h3 class="text-lg font-semibold mb-3">Comparison Summary</h3>
        <div class="flex items-center gap-4 mb-4">
          <div class="flex items-center gap-2">
            <div 
              :class="[
                'w-3 h-3 rounded-full',
                comparison.regression_detected ? 'bg-red-500' : 
                comparison.improvement_detected ? 'bg-green-500' : 'bg-yellow-500'
              ]"
            ></div>
            <span class="font-medium">
              {{ 
                comparison.regression_detected ? 'Security Regression' : 
                comparison.improvement_detected ? 'Security Improvement' : 'Stable'
              }}
            </span>
          </div>
          <div class="text-sm text-gray-600">
            {{ formatDate(comparison.comparison_timestamp) }}
          </div>
        </div>
        <p class="text-gray-700">{{ comparison.summary }}</p>
      </div>

      <!-- Metrics Overview -->
      <div class="metrics-grid grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <!-- Threat Metrics -->
        <div class="metric-card bg-white rounded-lg shadow-md p-4">
          <h4 class="font-semibold text-gray-800 mb-3">Threat Landscape</h4>
          <div class="space-y-2">
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">Total Threats:</span>
              <span class="font-medium">
                {{ comparison.threat_comparison.current_threats }}
                <span 
                  :class="[
                    'text-xs ml-1',
                    threatChange > 0 ? 'text-red-600' : threatChange < 0 ? 'text-green-600' : 'text-gray-500'
                  ]"
                >
                  ({{ threatChange > 0 ? '+' : '' }}{{ threatChange }})
                </span>
              </span>
            </div>
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">New Threats:</span>
              <span class="font-medium text-red-600">{{ comparison.threat_comparison.new_threats.length }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">Resolved:</span>
              <span class="font-medium text-green-600">{{ comparison.threat_comparison.resolved_threats.length }}</span>
            </div>
          </div>
        </div>

        <!-- Mitigation Metrics -->
        <div class="metric-card bg-white rounded-lg shadow-md p-4">
          <h4 class="font-semibold text-gray-800 mb-3">Mitigation Coverage</h4>
          <div class="space-y-2">
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">Total Mitigations:</span>
              <span class="font-medium">
                {{ comparison.mitigation_comparison.current_mitigations }}
                <span 
                  :class="[
                    'text-xs ml-1',
                    mitigationChange > 0 ? 'text-green-600' : mitigationChange < 0 ? 'text-red-600' : 'text-gray-500'
                  ]"
                >
                  ({{ mitigationChange > 0 ? '+' : '' }}{{ mitigationChange }})
                </span>
              </span>
            </div>
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">New Mitigations:</span>
              <span class="font-medium text-green-600">{{ comparison.mitigation_comparison.new_mitigations.length }}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">Removed:</span>
              <span class="font-medium text-red-600">{{ comparison.mitigation_comparison.removed_mitigations.length }}</span>
            </div>
          </div>
        </div>

        <!-- Compliance Metrics -->
        <div class="metric-card bg-white rounded-lg shadow-md p-4">
          <h4 class="font-semibold text-gray-800 mb-3">OWASP Compliance</h4>
          <div class="space-y-2">
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">Current Score:</span>
              <span class="font-medium">
                {{ (comparison.compliance_comparison.current_compliance_score * 100).toFixed(1) }}%
                <span 
                  :class="[
                    'text-xs ml-1',
                    complianceChange > 0 ? 'text-green-600' : complianceChange < 0 ? 'text-red-600' : 'text-gray-500'
                  ]"
                >
                  ({{ complianceChange > 0 ? '+' : '' }}{{ (complianceChange * 100).toFixed(1) }}%)
                </span>
              </span>
            </div>
            <div class="flex justify-between">
              <span class="text-sm text-gray-600">Trend:</span>
              <span 
                :class="[
                  'font-medium capitalize',
                  comparison.compliance_comparison.compliance_trend === 'improving' ? 'text-green-600' :
                  comparison.compliance_comparison.compliance_trend === 'declining' ? 'text-red-600' : 'text-gray-600'
                ]"
              >
                {{ comparison.compliance_comparison.compliance_trend }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Security Changes -->
      <div class="changes-section bg-white rounded-lg shadow-md p-6 mb-6">
        <h3 class="text-lg font-semibold mb-4">Security Changes</h3>
        <div v-if="comparison.security_changes.length === 0" class="text-gray-500 text-center py-4">
          No security changes detected
        </div>
        <div v-else class="space-y-3">
          <div 
            v-for="change in comparison.security_changes" 
            :key="`${change.section_id}_${change.change_type}`"
            class="change-item border rounded-lg p-4"
            :class="getChangeClass(change.change_type)"
          >
            <div class="flex items-start justify-between mb-2">
              <div class="flex items-center gap-2">
                <div 
                  class="w-2 h-2 rounded-full"
                  :class="getChangeIndicatorClass(change.change_type)"
                ></div>
                <span class="font-medium">{{ change.section_title }}</span>
                <span 
                  class="px-2 py-1 text-xs rounded-full"
                  :class="getChangeTypeClass(change.change_type)"
                >
                  {{ change.change_type }}
                </span>
                <span 
                  class="px-2 py-1 text-xs rounded-full"
                  :class="getImpactClass(change.impact_level)"
                >
                  {{ change.impact_level }} impact
                </span>
              </div>
            </div>
            <p class="text-sm text-gray-600 mb-2">{{ change.description }}</p>
            
            <!-- OWASP Categories -->
            <div v-if="change.owasp_categories && change.owasp_categories.length > 0" class="mb-2">
              <div class="flex flex-wrap gap-1">
                <span 
                  v-for="category in change.owasp_categories" 
                  :key="category"
                  class="px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded"
                >
                  {{ category }}
                </span>
              </div>
            </div>

            <!-- Content Diff -->
            <div v-if="change.old_content || change.new_content" class="diff-container">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div v-if="change.old_content" class="old-content">
                  <div class="text-xs font-medium text-red-700 mb-1">Before:</div>
                  <div class="bg-red-50 border border-red-200 rounded p-2 text-red-800">
                    {{ change.old_content }}
                  </div>
                </div>
                <div v-if="change.new_content" class="new-content">
                  <div class="text-xs font-medium text-green-700 mb-1">After:</div>
                  <div class="bg-green-50 border border-green-200 rounded p-2 text-green-800">
                    {{ change.new_content }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- OWASP Compliance Details -->
      <div class="compliance-details bg-white rounded-lg shadow-md p-6">
        <h3 class="text-lg font-semibold mb-4">OWASP Compliance Details</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 class="font-medium mb-3">Compliance Changes by Category</h4>
            <div class="space-y-2">
              <div 
                v-for="(change, category) in comparison.compliance_comparison.compliance_changes" 
                :key="category"
                class="flex justify-between items-center py-1"
              >
                <span class="text-sm text-gray-700">{{ formatOWASPCategory(category) }}</span>
                <span 
                  :class="[
                    'text-sm font-medium',
                    change > 0 ? 'text-green-600' : change < 0 ? 'text-red-600' : 'text-gray-500'
                  ]"
                >
                  {{ change > 0 ? '+' : '' }}{{ (change * 100).toFixed(1) }}%
                </span>
              </div>
            </div>
          </div>
          <div>
            <h4 class="font-medium mb-3">Guidelines Coverage</h4>
            <div class="space-y-3">
              <div v-if="comparison.compliance_comparison.new_guidelines_covered.length > 0">
                <div class="text-sm font-medium text-green-700 mb-1">New Guidelines Covered:</div>
                <div class="space-y-1">
                  <div 
                    v-for="guideline in comparison.compliance_comparison.new_guidelines_covered" 
                    :key="guideline"
                    class="text-xs bg-green-100 text-green-800 rounded px-2 py-1"
                  >
                    {{ guideline }}
                  </div>
                </div>
              </div>
              <div v-if="comparison.compliance_comparison.missing_guidelines.length > 0">
                <div class="text-sm font-medium text-red-700 mb-1">Missing Guidelines:</div>
                <div class="space-y-1">
                  <div 
                    v-for="guideline in comparison.compliance_comparison.missing_guidelines" 
                    :key="guideline"
                    class="text-xs bg-red-100 text-red-800 rounded px-2 py-1"
                  >
                    {{ guideline }}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else-if="selectedBaseline && selectedCurrent" class="text-center py-8 text-gray-500">
      Select both wikis to start comparison
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { api } from '@/lib/api'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

interface SecurityWiki {
  id: string
  title: string
  created_at: string
  repo_id: string
}

interface SecurityComparison {
  baseline_wiki_id: string
  current_wiki_id: string
  comparison_timestamp: string
  threat_comparison: {
    baseline_threats: number
    current_threats: number
    new_threats: any[]
    resolved_threats: any[]
    modified_threats: any[]
    threat_severity_distribution: Record<string, number>
    owasp_category_changes: Record<string, number>
  }
  mitigation_comparison: {
    baseline_mitigations: number
    current_mitigations: number
    new_mitigations: string[]
    removed_mitigations: string[]
    coverage_by_owasp: Record<string, number>
    effectiveness_changes: Record<string, number>
  }
  compliance_comparison: {
    baseline_compliance_score: number
    current_compliance_score: number
    compliance_changes: Record<string, number>
    missing_guidelines: string[]
    new_guidelines_covered: string[]
    compliance_trend: string
  }
  security_changes: Array<{
    change_type: string
    section_id: string
    section_title: string
    old_content?: string
    new_content?: string
    impact_level: string
    description: string
    owasp_categories: string[]
  }>
  regression_detected: boolean
  improvement_detected: boolean
  summary: string
}

const availableWikis = ref<SecurityWiki[]>([])
const selectedBaseline = ref('')
const selectedCurrent = ref('')
const comparison = ref<SecurityComparison | null>(null)
const loading = ref(false)

const threatChange = computed(() => {
  if (!comparison.value) return 0
  return comparison.value.threat_comparison.current_threats - comparison.value.threat_comparison.baseline_threats
})

const mitigationChange = computed(() => {
  if (!comparison.value) return 0
  return comparison.value.mitigation_comparison.current_mitigations - comparison.value.mitigation_comparison.baseline_mitigations
})

const complianceChange = computed(() => {
  if (!comparison.value) return 0
  return comparison.value.compliance_comparison.current_compliance_score - comparison.value.compliance_comparison.baseline_compliance_score
})

onMounted(async () => {
  await loadAvailableWikis()
})

const loadAvailableWikis = async () => {
  try {
    const response = await api.get('/api/wikis')
    availableWikis.value = response.data
  } catch (error) {
    console.error('Failed to load wikis:', error)
  }
}

const loadComparison = async () => {
  if (!selectedBaseline.value || !selectedCurrent.value) return
  
  loading.value = true
  try {
    const response = await api.post('/api/wikis/compare', {
      baseline_wiki_id: selectedBaseline.value,
      current_wiki_id: selectedCurrent.value
    })
    comparison.value = response.data
  } catch (error) {
    console.error('Failed to load comparison:', error)
  } finally {
    loading.value = false
  }
}

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString()
}

const formatOWASPCategory = (category: string) => {
  // Extract the main part of OWASP category (e.g., "A01" from "A01:2021 – Broken Access Control")
  const match = category.match(/^(A\d+)/)
  return match ? match[1] : category
}

const getChangeClass = (changeType: string) => {
  switch (changeType) {
    case 'added':
      return 'border-green-200 bg-green-50'
    case 'removed':
      return 'border-red-200 bg-red-50'
    case 'modified':
      return 'border-yellow-200 bg-yellow-50'
    default:
      return 'border-gray-200 bg-gray-50'
  }
}

const getChangeIndicatorClass = (changeType: string) => {
  switch (changeType) {
    case 'added':
      return 'bg-green-500'
    case 'removed':
      return 'bg-red-500'
    case 'modified':
      return 'bg-yellow-500'
    default:
      return 'bg-gray-500'
  }
}

const getChangeTypeClass = (changeType: string) => {
  switch (changeType) {
    case 'added':
      return 'bg-green-100 text-green-800'
    case 'removed':
      return 'bg-red-100 text-red-800'
    case 'modified':
      return 'bg-yellow-100 text-yellow-800'
    default:
      return 'bg-gray-100 text-gray-800'
  }
}

const getImpactClass = (impactLevel: string) => {
  switch (impactLevel) {
    case 'critical':
      return 'bg-red-100 text-red-800'
    case 'high':
      return 'bg-orange-100 text-orange-800'
    case 'medium':
      return 'bg-yellow-100 text-yellow-800'
    case 'low':
      return 'bg-blue-100 text-blue-800'
    default:
      return 'bg-gray-100 text-gray-800'
  }
}
</script>

<style scoped>
.wiki-comparison {
  max-width: 1200px;
  margin: 0 auto;
  padding: 1rem;
}

.diff-container {
  margin-top: 0.5rem;
  font-family: 'Courier New', monospace;
}

.change-item {
  transition: all 0.2s ease;
}

.change-item:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.metrics-grid .metric-card {
  transition: all 0.2s ease;
}

.metrics-grid .metric-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
</style>