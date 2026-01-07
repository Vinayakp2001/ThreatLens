<template>
  <div class="p-6">
    <div class="max-w-7xl mx-auto">
      <!-- Header -->
      <div class="mb-8">
        <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          What are we going to do about it?
        </h2>
        <p class="text-gray-600 dark:text-gray-400">
          Mitigation strategies and responses to identified threats
        </p>
      </div>

      <!-- Loading State -->
      <div v-if="loading" class="flex items-center justify-center py-12">
        <LoadingSpinner size="large" message="Loading mitigations..." />
      </div>

      <!-- Mitigation Content -->
      <div v-else-if="mitigations.length > 0 || threats.length > 0" class="space-y-8">
        <!-- Mitigation Summary -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Mitigation Overview
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <div class="text-2xl font-bold text-green-600 dark:text-green-400">
                {{ mitigations.length }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Total Mitigations</div>
            </div>
            <div class="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {{ highPriorityMitigations.length }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">High Priority</div>
            </div>
            <div class="text-center p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
              <div class="text-2xl font-bold text-purple-600 dark:text-purple-400">
                {{ owaspReferences.size }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">OWASP References</div>
            </div>
            <div class="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              <div class="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {{ threatsWithMitigations.length }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Threats Addressed</div>
            </div>
          </div>
        </div>

        <!-- Threat-Mitigation Mapping -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <Shield class="w-5 h-5 mr-2" />
            Threat Response Strategy
          </h3>
          
          <div class="space-y-4">
            <div
              v-for="threat in threatsWithMitigations"
              :key="threat.id"
              class="border border-gray-200 dark:border-gray-600 rounded-lg p-4"
            >
              <!-- Threat Header -->
              <div class="flex items-start justify-between mb-3">
                <div class="flex-1">
                  <h4 class="font-medium text-gray-900 dark:text-gray-100 mb-1">
                    {{ threat.title }}
                  </h4>
                  <div class="flex items-center space-x-2">
                    <span
                      :class="getStrideClass(threat.stride_category)"
                      class="px-2 py-1 rounded-full text-xs font-medium"
                    >
                      {{ getStrideFullName(threat.stride_category) }}
                    </span>
                    <span
                      :class="getRiskLevelClass(getRiskLevel(threat.risk_score))"
                      class="px-2 py-1 rounded-full text-xs font-medium"
                    >
                      {{ getRiskLevel(threat.risk_score) }} Risk
                    </span>
                  </div>
                </div>
                <div class="text-right">
                  <div class="text-sm text-gray-500 dark:text-gray-400">
                    {{ getThreatMitigations(threat.id).length }} mitigation(s)
                  </div>
                </div>
              </div>

              <!-- Associated Mitigations -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div
                  v-for="mitigation in getThreatMitigations(threat.id)"
                  :key="mitigation.id"
                  class="bg-gray-50 dark:bg-gray-700 rounded-lg p-3"
                >
                  <div class="flex items-start justify-between mb-2">
                    <h5 class="text-sm font-medium text-gray-900 dark:text-gray-100">
                      {{ mitigation.title }}
                    </h5>
                    <span
                      :class="getPriorityClass(mitigation.priority)"
                      class="px-2 py-1 rounded-full text-xs font-medium"
                    >
                      {{ mitigation.priority }}
                    </span>
                  </div>
                  <p class="text-xs text-gray-600 dark:text-gray-400 mb-2">
                    {{ mitigation.description }}
                  </p>
                  <div v-if="mitigation.owasp_cheatsheet_ids?.length" class="flex flex-wrap gap-1">
                    <span
                      v-for="ref in mitigation.owasp_cheatsheet_ids.slice(0, 2)"
                      :key="ref"
                      class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200"
                    >
                      {{ ref }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Mitigation Categories -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <Layers class="w-5 h-5 mr-2" />
            Mitigation Categories
          </h3>
          
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div
              v-for="(categoryMitigations, category) in mitigationsByCategory"
              :key="category"
              class="border border-gray-200 dark:border-gray-600 rounded-lg p-4"
            >
              <h4 class="font-medium text-gray-900 dark:text-gray-100 mb-3 capitalize">
                {{ category.replace(/_/g, ' ') }}
              </h4>
              <div class="space-y-2">
                <div
                  v-for="mitigation in categoryMitigations.slice(0, 3)"
                  :key="mitigation.id"
                  class="text-sm"
                >
                  <div class="flex items-center justify-between">
                    <span class="text-gray-900 dark:text-gray-100 truncate">
                      {{ mitigation.title }}
                    </span>
                    <span
                      :class="getPriorityClass(mitigation.priority)"
                      class="px-1.5 py-0.5 rounded text-xs font-medium ml-2"
                    >
                      {{ mitigation.priority }}
                    </span>
                  </div>
                </div>
                <div
                  v-if="categoryMitigations.length > 3"
                  class="text-xs text-gray-500 dark:text-gray-400"
                >
                  +{{ categoryMitigations.length - 3 }} more
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Detailed Mitigations -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <BookOpen class="w-5 h-5 mr-2" />
            Implementation Guidance
          </h3>
          
          <div class="space-y-6">
            <div
              v-for="mitigation in sortedMitigations"
              :key="mitigation.id"
              class="border border-gray-200 dark:border-gray-600 rounded-lg p-4"
            >
              <!-- Mitigation Header -->
              <div class="flex items-start justify-between mb-3">
                <div class="flex-1">
                  <h4 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-1">
                    {{ mitigation.title }}
                  </h4>
                  <p class="text-sm text-gray-600 dark:text-gray-400">
                    {{ mitigation.description }}
                  </p>
                </div>
                <div class="flex items-center space-x-2">
                  <span
                    :class="getPriorityClass(mitigation.priority)"
                    class="px-2 py-1 rounded-full text-xs font-medium"
                  >
                    {{ mitigation.priority }} Priority
                  </span>
                  <span
                    class="px-2 py-1 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200"
                  >
                    {{ mitigation.category }}
                  </span>
                </div>
              </div>

              <!-- Implementation Details -->
              <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- Left Column -->
                <div class="space-y-4">
                  <!-- Implementation Guidance -->
                  <div v-if="mitigation.implementation_guidance">
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                      Implementation Guidance
                    </dt>
                    <dd class="text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-gray-700 rounded-lg p-3">
                      {{ mitigation.implementation_guidance }}
                    </dd>
                  </div>

                  <!-- OWASP References -->
                  <div v-if="mitigation.owasp_cheatsheet_ids?.length">
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                      OWASP Cheat Sheets
                    </dt>
                    <dd class="flex flex-wrap gap-2">
                      <a
                        v-for="ref in mitigation.owasp_cheatsheet_ids"
                        :key="ref"
                        :href="getOwaspUrl(ref)"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200 hover:bg-green-200 dark:hover:bg-green-900/40 transition-colors"
                      >
                        <ExternalLink class="w-3 h-3 mr-1" />
                        {{ ref }}
                      </a>
                    </dd>
                  </div>
                </div>

                <!-- Right Column -->
                <div class="space-y-4">
                  <!-- ASVS References -->
                  <div v-if="mitigation.asvs_references?.length">
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                      ASVS References
                    </dt>
                    <dd class="flex flex-wrap gap-1">
                      <span
                        v-for="ref in mitigation.asvs_references"
                        :key="ref"
                        class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200"
                      >
                        {{ ref }}
                      </span>
                    </dd>
                  </div>

                  <!-- Related Threats -->
                  <div>
                    <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                      Addresses Threats
                    </dt>
                    <dd class="text-sm text-gray-900 dark:text-gray-100">
                      <div class="space-y-1">
                        <div
                          v-for="threat in getThreatsForMitigation(mitigation.id)"
                          :key="threat.id"
                          class="flex items-center justify-between text-xs bg-gray-50 dark:bg-gray-700 rounded px-2 py-1"
                        >
                          <span class="truncate">{{ threat.title }}</span>
                          <span
                            :class="getStrideClass(threat.stride_category)"
                            class="px-1.5 py-0.5 rounded text-xs font-medium ml-2"
                          >
                            {{ threat.stride_category }}
                          </span>
                        </div>
                      </div>
                    </dd>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Empty State -->
      <div v-else class="text-center py-12">
        <Shield class="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          No Mitigations Available
        </h3>
        <p class="text-gray-600 dark:text-gray-400">
          No mitigation strategies have been defined for the identified threats yet.
        </p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Shield, Layers, BookOpen, ExternalLink } from 'lucide-vue-next'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

// Props
interface Threat {
  id: string
  title: string
  description: string
  stride_category: string
  risk_score: number
  mitigations: string[]
}

interface Mitigation {
  id: string
  title: string
  description: string
  category: string
  owasp_cheatsheet_ids: string[]
  asvs_references: string[]
  implementation_guidance: string
  priority: string
}

interface Props {
  threats: Threat[]
  mitigations: Mitigation[]
  loading?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  threats: () => [],
  mitigations: () => [],
  loading: false
})

// Computed properties
const highPriorityMitigations = computed(() =>
  props.mitigations.filter(m => m.priority?.toLowerCase() === 'high')
)

const owaspReferences = computed(() => {
  const refs = new Set<string>()
  props.mitigations.forEach(m => {
    m.owasp_cheatsheet_ids?.forEach(ref => refs.add(ref))
  })
  return refs
})

const threatsWithMitigations = computed(() =>
  props.threats.filter(t => t.mitigations?.length > 0)
)

const mitigationsByCategory = computed(() => {
  const categories: Record<string, Mitigation[]> = {}
  props.mitigations.forEach(mitigation => {
    const category = mitigation.category || 'uncategorized'
    if (!categories[category]) {
      categories[category] = []
    }
    categories[category].push(mitigation)
  })
  return categories
})

const sortedMitigations = computed(() => {
  return [...props.mitigations].sort((a, b) => {
    // Sort by priority first (High > Medium > Low)
    const priorityOrder = { 'high': 3, 'medium': 2, 'low': 1 }
    const aPriority = priorityOrder[a.priority?.toLowerCase() as keyof typeof priorityOrder] || 0
    const bPriority = priorityOrder[b.priority?.toLowerCase() as keyof typeof priorityOrder] || 0
    
    if (aPriority !== bPriority) {
      return bPriority - aPriority
    }
    
    // Then by title
    return a.title.localeCompare(b.title)
  })
})

// Methods
const getThreatMitigations = (threatId: string) => {
  const threat = props.threats.find(t => t.id === threatId)
  if (!threat?.mitigations) return []
  
  return props.mitigations.filter(m => threat.mitigations.includes(m.id))
}

const getThreatsForMitigation = (mitigationId: string) => {
  return props.threats.filter(t => t.mitigations?.includes(mitigationId))
}

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

const getPriorityClass = (priority: string) => {
  switch (priority?.toLowerCase()) {
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

const getOwaspUrl = (cheatsheetId: string) => {
  // Convert cheatsheet ID to OWASP URL
  const baseUrl = 'https://cheatsheetseries.owasp.org/cheatsheets/'
  const formattedId = cheatsheetId.replace(/-/g, '_').replace(/\b\w/g, l => l.toUpperCase())
  return `${baseUrl}${formattedId}_Cheat_Sheet.html`
}
</script>

<style scoped>
/* Component-specific styles */
.mitigation-card {
  @apply border border-gray-200 dark:border-gray-600 rounded-lg p-4;
}

.threat-mitigation-mapping {
  @apply border border-gray-200 dark:border-gray-600 rounded-lg p-4;
}

.implementation-guidance {
  @apply text-sm text-gray-900 dark:text-gray-100 bg-gray-50 dark:bg-gray-700 rounded-lg p-3;
}
</style>