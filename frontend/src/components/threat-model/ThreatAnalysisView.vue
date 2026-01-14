<template>
  <div class="p-6">
    <div class="max-w-7xl mx-auto">
      <!-- Header -->
      <div class="mb-8">
        <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          What can go wrong?
        </h2>
        <p class="text-gray-600 dark:text-gray-400">
          STRIDE threat analysis identifying potential security risks
        </p>
      </div>

      <!-- Loading State -->
      <div v-if="loading" class="flex items-center justify-center py-12">
        <LoadingSpinner size="large" message="Loading threat analysis..." />
      </div>

      <!-- Threat Analysis Content -->
      <div v-else-if="threats.length > 0" class="space-y-8">
        <!-- Threat Summary -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Threat Summary
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div class="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <div class="text-2xl font-bold text-red-600 dark:text-red-400">
                {{ highRiskThreats.length }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">High Risk</div>
            </div>
            <div class="text-center p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
              <div class="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                {{ mediumRiskThreats.length }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Medium Risk</div>
            </div>
            <div class="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <div class="text-2xl font-bold text-green-600 dark:text-green-400">
                {{ lowRiskThreats.length }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Low Risk</div>
            </div>
            <div class="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {{ effectiveThreats.length }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Total Threats</div>
            </div>
          </div>

          <!-- STRIDE Distribution -->
          <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
            <div
              v-for="(count, category) in strideDistribution"
              :key="category"
              class="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
            >
              <div class="text-lg font-semibold text-gray-900 dark:text-gray-100">
                {{ count }}
              </div>
              <div class="text-xs text-gray-600 dark:text-gray-400">
                {{ category }}
              </div>
            </div>
          </div>
        </div>

        <!-- Filters -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
          <div class="flex flex-wrap items-center gap-4">
            <div class="flex items-center space-x-2">
              <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
                Filter by STRIDE:
              </label>
              <select
                v-model="selectedStrideFilter"
                class="rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
              >
                <option value="">All Categories</option>
                <option value="S">Spoofing</option>
                <option value="T">Tampering</option>
                <option value="R">Repudiation</option>
                <option value="I">Information Disclosure</option>
                <option value="D">Denial of Service</option>
                <option value="E">Elevation of Privilege</option>
              </select>
            </div>
            <div class="flex items-center space-x-2">
              <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
                Risk Level:
              </label>
              <select
                v-model="selectedRiskFilter"
                class="rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
              >
                <option value="">All Levels</option>
                <option value="high">High Risk</option>
                <option value="medium">Medium Risk</option>
                <option value="low">Low Risk</option>
              </select>
            </div>
            <div class="flex items-center space-x-2">
              <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
                Sort by:
              </label>
              <select
                v-model="sortBy"
                class="rounded-md border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
              >
                <option value="risk_score">Risk Score</option>
                <option value="stride_category">STRIDE Category</option>
                <option value="title">Title</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Threat List -->
        <div class="space-y-4">
          <div
            v-for="threat in filteredAndSortedThreats"
            :key="threat.id"
            class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden"
          >
            <div class="p-6">
              <!-- Threat Header -->
              <div class="flex items-start justify-between mb-4">
                <div class="flex-1">
                  <div class="flex items-center space-x-3 mb-2">
                    <h4 class="text-lg font-semibold text-gray-900 dark:text-gray-100">
                      {{ threat.title }}
                    </h4>
                    <span
                      :class="getStrideClass(threat.stride_category)"
                      class="px-2 py-1 rounded-full text-xs font-medium"
                    >
                      {{ getStrideFullName(threat.stride_category) }}
                    </span>
                  </div>
                  <p class="text-gray-600 dark:text-gray-400 text-sm">
                    {{ threat.description }}
                  </p>
                </div>
                <div class="flex items-center space-x-3">
                  <div class="text-right">
                    <div class="text-sm text-gray-500 dark:text-gray-400">Risk Score</div>
                    <div
                      :class="getRiskScoreClass(threat.risk_score)"
                      class="text-lg font-bold"
                    >
                      {{ threat.risk_score?.toFixed(1) || 'N/A' }}
                    </div>
                  </div>
                  <div
                    :class="getRiskLevelClass(getRiskLevel(threat.risk_score))"
                    class="px-3 py-1 rounded-full text-sm font-medium"
                  >
                    {{ getRiskLevel(threat.risk_score) }}
                  </div>
                </div>
              </div>

              <!-- Threat Details -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Left Column -->
                <div class="space-y-4">
                  <!-- Likelihood and Impact -->
                  <div class="grid grid-cols-2 gap-4">
                    <div>
                      <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Likelihood</dt>
                      <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                        <span
                          :class="getLikelihoodClass(threat.likelihood)"
                          class="px-2 py-1 rounded-full text-xs font-medium"
                        >
                          {{ threat.likelihood || 'Not assessed' }}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Impact</dt>
                      <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                        <span
                          :class="getImpactClass(threat.impact)"
                          class="px-2 py-1 rounded-full text-xs font-medium"
                        >
                          {{ threat.impact || 'Not assessed' }}
                        </span>
                      </dd>
                    </div>
                  </div>

                  <!-- Affected Assets -->
                  <div v-if="threat.affected_assets?.length">
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Affected Assets</dt>
                    <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                      <div class="flex flex-wrap gap-1">
                        <span
                          v-for="asset in threat.affected_assets"
                          :key="asset"
                          class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200"
                        >
                          {{ asset }}
                        </span>
                      </div>
                    </dd>
                  </div>
                </div>

                <!-- Right Column -->
                <div class="space-y-4">
                  <!-- Attack Vectors -->
                  <div v-if="threat.attack_vectors?.length">
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Attack Vectors</dt>
                    <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                      <ul class="list-disc list-inside space-y-1">
                        <li v-for="vector in threat.attack_vectors" :key="vector">
                          {{ vector }}
                        </li>
                      </ul>
                    </dd>
                  </div>

                  <!-- OWASP References -->
                  <div v-if="threat.owasp_references?.length">
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">OWASP References</dt>
                    <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                      <div class="flex flex-wrap gap-1">
                        <span
                          v-for="ref in threat.owasp_references"
                          :key="ref"
                          class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200"
                        >
                          {{ ref }}
                        </span>
                      </div>
                    </dd>
                  </div>
                </div>
              </div>

              <!-- Mitigations Preview -->
              <div v-if="threat.mitigations?.length" class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                <div class="flex items-center justify-between">
                  <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">
                    Available Mitigations
                  </dt>
                  <span class="text-xs text-gray-500 dark:text-gray-400">
                    {{ threat.mitigations.length }} mitigation(s)
                  </span>
                </div>
                <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                  <div class="flex flex-wrap gap-1">
                    <span
                      v-for="mitigationId in threat.mitigations.slice(0, 3)"
                      :key="mitigationId"
                      class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 dark:bg-purple-900/20 text-purple-800 dark:text-purple-200"
                    >
                      {{ getMitigationTitle(mitigationId) }}
                    </span>
                    <span
                      v-if="threat.mitigations.length > 3"
                      class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200"
                    >
                      +{{ threat.mitigations.length - 3 }} more
                    </span>
                  </div>
                </dd>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Empty State -->
      <div v-else class="text-center py-12">
        <AlertTriangle class="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          No Threats Identified
        </h3>
        <p class="text-gray-600 dark:text-gray-400">
          No security threats have been identified for this system yet.
        </p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { AlertTriangle } from 'lucide-vue-next'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

// Props
interface Threat {
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
}

interface WikiSection {
  id: string
  title: string
  content: string
  security_findings: any[]
  owasp_mappings: string[]
  cross_references: string[]
}

interface Props {
  threats?: Threat[]
  wikiSection?: WikiSection
  system?: any
  loading?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  threats: () => [],
  loading: false
})

// Extract threats from wiki section if provided
const effectiveThreats = computed(() => {
  if (props.wikiSection?.security_findings) {
    // Convert security findings to threat format for compatibility
    return props.wikiSection.security_findings.map((finding: any) => ({
      id: finding.id || `finding-${Math.random()}`,
      title: finding.type || 'Security Finding',
      description: finding.description || '',
      stride_category: finding.stride_category || 'Unknown',
      likelihood: 'Medium', // Default values
      impact: 'Medium',
      risk_score: finding.severity === 'high' ? 8 : finding.severity === 'medium' ? 5 : 2,
      affected_assets: finding.affected_components || [],
      attack_vectors: [],
      mitigations: [],
      owasp_references: props.wikiSection?.owasp_mappings || []
    }))
  }
  return props.threats
})

// State
const selectedStrideFilter = ref('')
const selectedRiskFilter = ref('')
const sortBy = ref('risk_score')

// Computed properties
const highRiskThreats = computed(() => 
  effectiveThreats.value.filter(t => t.risk_score >= 7)
)

const mediumRiskThreats = computed(() => 
  effectiveThreats.value.filter(t => t.risk_score >= 4 && t.risk_score < 7)
)

const lowRiskThreats = computed(() => 
  effectiveThreats.value.filter(t => t.risk_score < 4)
)

const strideDistribution = computed(() => {
  const distribution = {
    'S': 0, 'T': 0, 'R': 0, 'I': 0, 'D': 0, 'E': 0
  }
  effectiveThreats.value.forEach(threat => {
    const category = threat.stride_category?.charAt(0)?.toUpperCase()
    if (category && category in distribution) {
      distribution[category as keyof typeof distribution]++
    }
  })
  return distribution
})

const filteredAndSortedThreats = computed(() => {
  let filtered = effectiveThreats.value

  // Apply STRIDE filter
  if (selectedStrideFilter.value) {
    filtered = filtered.filter(t => 
      t.stride_category?.charAt(0)?.toUpperCase() === selectedStrideFilter.value
    )
  }

  // Apply risk level filter
  if (selectedRiskFilter.value) {
    filtered = filtered.filter(t => {
      const riskLevel = getRiskLevel(t.risk_score)
      return riskLevel.toLowerCase() === selectedRiskFilter.value
    })
  }

  // Sort
  return filtered.sort((a, b) => {
    switch (sortBy.value) {
      case 'risk_score':
        return (b.risk_score || 0) - (a.risk_score || 0)
      case 'stride_category':
        return (a.stride_category || '').localeCompare(b.stride_category || '')
      case 'title':
        return (a.title || '').localeCompare(b.title || '')
      default:
        return 0
    }
  })
})

// Utility functions
const getStrideClass = (category: string) => {
  const colors = {
    'S': 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200',
    'T': 'bg-orange-100 dark:bg-orange-900/20 text-orange-800 dark:text-orange-200',
    'R': 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200',
    'I': 'bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200',
    'D': 'bg-purple-100 dark:bg-purple-900/20 text-purple-800 dark:text-purple-200',
    'E': 'bg-pink-100 dark:bg-pink-900/20 text-pink-800 dark:text-pink-200'
  }
  const key = category?.charAt(0)?.toUpperCase() as keyof typeof colors
  return colors[key] || 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
}

const getStrideFullName = (category: string) => {
  const names = {
    'S': 'Spoofing',
    'T': 'Tampering',
    'R': 'Repudiation',
    'I': 'Information Disclosure',
    'D': 'Denial of Service',
    'E': 'Elevation of Privilege'
  }
  const key = category?.charAt(0)?.toUpperCase() as keyof typeof names
  return names[key] || category
}

const getRiskLevel = (score: number) => {
  if (score >= 7) return 'High'
  if (score >= 4) return 'Medium'
  return 'Low'
}

const getRiskLevelClass = (level: string) => {
  switch (level.toLowerCase()) {
    case 'high':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
    case 'low':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const getRiskScoreClass = (score: number) => {
  if (score >= 7) return 'text-red-600 dark:text-red-400'
  if (score >= 4) return 'text-yellow-600 dark:text-yellow-400'
  return 'text-green-600 dark:text-green-400'
}

const getLikelihoodClass = (likelihood: string) => {
  switch (likelihood?.toLowerCase()) {
    case 'high':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
    case 'low':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const getImpactClass = (impact: string) => {
  switch (impact?.toLowerCase()) {
    case 'high':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
    case 'low':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const getMitigationTitle = (mitigationId: string) => {
  // This would typically look up the mitigation by ID
  // For now, return a simplified version
  return mitigationId.replace(/[-_]/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
}
</script>

<style scoped>
/* Component-specific styles */
.threat-card {
  @apply bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 overflow-hidden;
}

.threat-header {
  @apply flex items-start justify-between mb-4;
}

.threat-details {
  @apply grid grid-cols-1 md:grid-cols-2 gap-6;
}

.filter-controls {
  @apply flex flex-wrap items-center gap-4;
}
</style>