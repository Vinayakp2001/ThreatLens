<template>
  <div class="p-6">
    <div class="max-w-7xl mx-auto">
      <!-- Header -->
      <div class="mb-8">
        <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          What are we working on?
        </h2>
        <p class="text-gray-600 dark:text-gray-400">
          System architecture overview showing components, data flows, and trust boundaries
        </p>
      </div>

      <!-- Loading State -->
      <div v-if="loading" class="flex items-center justify-center py-12">
        <LoadingSpinner size="large" message="Loading system model..." />
      </div>

      <!-- System Overview -->
      <div v-else-if="system" class="space-y-8">
        <!-- System Summary -->
        <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
            System Overview
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div class="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {{ system.components?.length || 0 }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Components</div>
            </div>
            <div class="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <div class="text-2xl font-bold text-green-600 dark:text-green-400">
                {{ system.data_stores?.length || 0 }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Data Stores</div>
            </div>
            <div class="text-center p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
              <div class="text-2xl font-bold text-purple-600 dark:text-purple-400">
                {{ system.data_flows?.length || 0 }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">Data Flows</div>
            </div>
            <div class="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              <div class="text-2xl font-bold text-orange-600 dark:text-orange-400">
                {{ system.external_entities?.length || 0 }}
              </div>
              <div class="text-sm text-gray-600 dark:text-gray-400">External Entities</div>
            </div>
          </div>
        </div>

        <!-- Cloud Context -->
        <div v-if="system.cloud_context" class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <Cloud class="w-5 h-5 mr-2" />
            Cloud Context
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Provider</dt>
              <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                {{ system.cloud_context.provider || 'Not specified' }}
              </dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Deployment Model</dt>
              <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                {{ system.cloud_context.deployment_model || 'Not specified' }}
              </dd>
            </div>
            <div v-if="system.cloud_context.services_used?.length">
              <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Services Used</dt>
              <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                <div class="flex flex-wrap gap-1">
                  <span
                    v-for="service in system.cloud_context.services_used"
                    :key="service"
                    class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200"
                  >
                    {{ service }}
                  </span>
                </div>
              </dd>
            </div>
            <div v-if="system.cloud_context.compliance_requirements?.length">
              <dt class="text-sm font-medium text-gray-500 dark:text-gray-400">Compliance Requirements</dt>
              <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                <div class="flex flex-wrap gap-1">
                  <span
                    v-for="req in system.cloud_context.compliance_requirements"
                    :key="req"
                    class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200"
                  >
                    {{ req }}
                  </span>
                </div>
              </dd>
            </div>
          </div>
        </div>

        <!-- Components -->
        <div v-if="system.components?.length" class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <Building2 class="w-5 h-5 mr-2" />
            Components
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div
              v-for="component in system.components"
              :key="component.id"
              class="border border-gray-200 dark:border-gray-600 rounded-lg p-4 hover:shadow-md transition-shadow"
            >
              <div class="flex items-start justify-between mb-2">
                <h4 class="font-medium text-gray-900 dark:text-gray-100">
                  {{ component.name }}
                </h4>
                <span
                  :class="getTrustLevelClass(component.trust_level)"
                  class="px-2 py-1 rounded-full text-xs font-medium"
                >
                  {{ component.trust_level }}
                </span>
              </div>
              <p class="text-sm text-gray-600 dark:text-gray-400 mb-2">
                Type: {{ component.type }}
              </p>
              <div v-if="component.interfaces?.length" class="text-xs text-gray-500 dark:text-gray-400">
                Interfaces: {{ component.interfaces.length }}
              </div>
            </div>
          </div>
        </div>

        <!-- Data Stores -->
        <div v-if="system.data_stores?.length" class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <Database class="w-5 h-5 mr-2" />
            Data Stores
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div
              v-for="dataStore in system.data_stores"
              :key="dataStore.id"
              class="border border-gray-200 dark:border-gray-600 rounded-lg p-4 hover:shadow-md transition-shadow"
            >
              <div class="flex items-start justify-between mb-2">
                <h4 class="font-medium text-gray-900 dark:text-gray-100">
                  {{ dataStore.name }}
                </h4>
                <span
                  :class="getDataClassificationClass(dataStore.data_classification)"
                  class="px-2 py-1 rounded-full text-xs font-medium"
                >
                  {{ dataStore.data_classification }}
                </span>
              </div>
              <p class="text-sm text-gray-600 dark:text-gray-400">
                Type: {{ dataStore.type }}
              </p>
            </div>
          </div>
        </div>

        <!-- Data Flows -->
        <div v-if="system.data_flows?.length" class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <ArrowRightLeft class="w-5 h-5 mr-2" />
            Data Flows
          </h3>
          <div class="space-y-3">
            <div
              v-for="flow in system.data_flows"
              :key="flow.id"
              class="flex items-center justify-between p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
            >
              <div class="flex items-center space-x-4">
                <div class="text-sm font-medium text-gray-900 dark:text-gray-100">
                  {{ flow.source }}
                </div>
                <ArrowRight class="w-4 h-4 text-gray-400" />
                <div class="text-sm font-medium text-gray-900 dark:text-gray-100">
                  {{ flow.destination }}
                </div>
              </div>
              <div class="flex items-center space-x-2">
                <span
                  :class="getDataClassificationClass(flow.data_classification)"
                  class="px-2 py-1 rounded-full text-xs font-medium"
                >
                  {{ flow.data_classification }}
                </span>
                <span class="text-xs text-gray-500 dark:text-gray-400">
                  {{ flow.protocol }}
                </span>
                <span
                  v-if="flow.authentication_required"
                  class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200"
                >
                  <Lock class="w-3 h-3 mr-1" />
                  Auth Required
                </span>
              </div>
            </div>
          </div>
        </div>

        <!-- External Entities -->
        <div v-if="system.external_entities?.length" class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <Users class="w-5 h-5 mr-2" />
            External Entities
          </h3>
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div
              v-for="entity in system.external_entities"
              :key="entity.id"
              class="border border-gray-200 dark:border-gray-600 rounded-lg p-4 hover:shadow-md transition-shadow"
            >
              <div class="flex items-start justify-between mb-2">
                <h4 class="font-medium text-gray-900 dark:text-gray-100">
                  {{ entity.name }}
                </h4>
                <span
                  :class="getTrustLevelClass(entity.trust_level)"
                  class="px-2 py-1 rounded-full text-xs font-medium"
                >
                  {{ entity.trust_level }}
                </span>
              </div>
              <p class="text-sm text-gray-600 dark:text-gray-400">
                Type: {{ entity.type }}
              </p>
            </div>
          </div>
        </div>

        <!-- Trust Boundaries -->
        <div v-if="system.trust_boundaries?.length" class="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
            <Shield class="w-5 h-5 mr-2" />
            Trust Boundaries
          </h3>
          <div class="space-y-3">
            <div
              v-for="boundary in system.trust_boundaries"
              :key="boundary.id"
              class="border border-gray-200 dark:border-gray-600 rounded-lg p-4"
            >
              <h4 class="font-medium text-gray-900 dark:text-gray-100 mb-2">
                {{ boundary.name }}
              </h4>
              <div v-if="boundary.components?.length" class="flex flex-wrap gap-1">
                <span
                  v-for="componentId in boundary.components"
                  :key="componentId"
                  class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200"
                >
                  {{ getComponentName(componentId) }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Empty State -->
      <div v-else class="text-center py-12">
        <Building2 class="w-16 h-16 text-gray-400 mx-auto mb-4" />
        <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
          No System Model Available
        </h3>
        <p class="text-gray-600 dark:text-gray-400">
          The system model has not been generated yet or is not available.
        </p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { 
  Building2, 
  Database, 
  ArrowRightLeft, 
  ArrowRight, 
  Users, 
  Shield, 
  Cloud, 
  Lock 
} from 'lucide-vue-next'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

// Props
interface Props {
  system?: {
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
  loading?: boolean
}

const props = withDefaults(defineProps<Props>(), {
  loading: false
})

// Computed properties
const componentMap = computed(() => {
  if (!props.system?.components) return new Map()
  return new Map(props.system.components.map(c => [c.id, c.name]))
})

// Utility functions
const getTrustLevelClass = (trustLevel: string) => {
  switch (trustLevel?.toLowerCase()) {
    case 'high':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
    case 'low':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const getDataClassificationClass = (classification: string) => {
  switch (classification?.toLowerCase()) {
    case 'confidential':
    case 'sensitive':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    case 'internal':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
    case 'public':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const getComponentName = (componentId: string) => {
  return componentMap.value.get(componentId) || componentId
}
</script>

<style scoped>
/* Component-specific styles */
.system-overview-grid {
  @apply grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4;
}

.metric-card {
  @apply text-center p-4 rounded-lg;
}

.component-card {
  @apply border border-gray-200 dark:border-gray-600 rounded-lg p-4 hover:shadow-md transition-shadow;
}

.data-flow-item {
  @apply flex items-center justify-between p-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors;
}
</style>