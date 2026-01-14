<template>
  <div class="security-risk-heatmap">
    <div class="heatmap-header mb-6">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-xl font-semibold text-gray-900">Security Risk Heatmap</h3>
          <p class="text-sm text-gray-600 mt-1">Visual representation of security hotspots and risk distribution</p>
        </div>
        <div class="flex gap-2">
          <select 
            v-model="selectedView" 
            @change="updateHeatmapView"
            class="px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="repository">By Repository</option>
            <option value="component">By Component</option>
            <option value="owasp">By OWASP Category</option>
            <option value="severity">By Severity</option>
          </select>
          <button 
            @click="refreshHeatmap"
            class="px-3 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>
    </div>

    <div v-if="loading" class="flex justify-center py-12">
      <LoadingSpinner />
    </div>

    <div v-else-if="heatmapData" class="heatmap-content">
      <!-- Risk Summary Cards -->
      <div class="risk-summary grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div class="summary-card bg-red-50 border border-red-200 rounded-lg p-4">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-red-800">Critical Risk</div>
              <div class="text-2xl font-bold text-red-900">{{ heatmapData.summary.critical_count }}</div>
            </div>
            <div class="w-10 h-10 bg-red-500 rounded-full flex items-center justify-center">
              <span class="text-white text-xs font-bold">!</span>
            </div>
          </div>
        </div>
        
        <div class="summary-card bg-orange-50 border border-orange-200 rounded-lg p-4">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-orange-800">High Risk</div>
              <div class="text-2xl font-bold text-orange-900">{{ heatmapData.summary.high_count }}</div>
            </div>
            <div class="w-10 h-10 bg-orange-500 rounded-full flex items-center justify-center">
              <span class="text-white text-xs font-bold">⚠</span>
            </div>
          </div>
        </div>
        
        <div class="summary-card bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-yellow-800">Medium Risk</div>
              <div class="text-2xl font-bold text-yellow-900">{{ heatmapData.summary.medium_count }}</div>
            </div>
            <div class="w-10 h-10 bg-yellow-500 rounded-full flex items-center justify-center">
              <span class="text-white text-xs font-bold">△</span>
            </div>
          </div>
        </div>
        
        <div class="summary-card bg-green-50 border border-green-200 rounded-lg p-4">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-green-800">Low Risk</div>
              <div class="text-2xl font-bold text-green-900">{{ heatmapData.summary.low_count }}</div>
            </div>
            <div class="w-10 h-10 bg-green-500 rounded-full flex items-center justify-center">
              <span class="text-white text-xs font-bold">✓</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Heatmap Visualization -->
      <div class="heatmap-visualization bg-white rounded-lg shadow-md p-6 mb-6">
        <div class="flex items-center justify-between mb-4">
          <h4 class="text-lg font-semibold text-gray-900">Risk Distribution</h4>
          <div class="flex items-center gap-4">
            <!-- Legend -->
            <div class="flex items-center gap-2 text-xs">
              <span class="text-gray-600">Risk Level:</span>
              <div class="flex items-center gap-1">
                <div class="w-3 h-3 bg-green-400 rounded"></div>
                <span>Low</span>
              </div>
              <div class="flex items-center gap-1">
                <div class="w-3 h-3 bg-yellow-400 rounded"></div>
                <span>Medium</span>
              </div>
              <div class="flex items-center gap-1">
                <div class="w-3 h-3 bg-orange-400 rounded"></div>
                <span>High</span>
              </div>
              <div class="flex items-center gap-1">
                <div class="w-3 h-3 bg-red-500 rounded"></div>
                <span>Critical</span>
              </div>
            </div>
          </div>
        </div>
        
        <!-- Heatmap Grid -->
        <div class="heatmap-grid">
          <div 
            v-if="selectedView === 'repository'"
            class="repository-heatmap grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4"
          >
            <div 
              v-for="item in heatmapData.items" 
              :key="item.id"
              class="heatmap-cell repository-cell rounded-lg p-4 cursor-pointer transition-all hover:scale-105"
              :class="getRiskCellClass(item.risk_score)"
              @click="selectHeatmapItem(item)"
            >
              <div class="cell-header flex items-center justify-between mb-2">
                <h5 class="font-medium text-sm truncate" :title="item.name">{{ item.name }}</h5>
                <span class="text-xs font-bold px-2 py-1 rounded" :class="getRiskBadgeClass(item.risk_score)">
                  {{ item.risk_score.toFixed(1) }}
                </span>
              </div>
              <div class="cell-content text-xs space-y-1">
                <div class="flex justify-between">
                  <span class="text-gray-600">Threats:</span>
                  <span class="font-medium">{{ item.threat_count }}</span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600">Vulnerabilities:</span>
                  <span class="font-medium">{{ item.vulnerability_count }}</span>
                </div>
                <div class="flex justify-between">
                  <span class="text-gray-600">Last Updated:</span>
                  <span class="font-medium">{{ formatDate(item.last_updated) }}</span>
                </div>
              </div>
            </div>
          </div>
          
          <!-- Component View -->
          <div 
            v-else-if="selectedView === 'component'"
            class="component-heatmap"
          >
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div 
                v-for="item in heatmapData.items" 
                :key="item.id"
                class="component-cell bg-white border rounded-lg p-4 hover:shadow-md transition-shadow"
              >
                <div class="flex items-center justify-between mb-3">
                  <h5 class="font-medium text-sm">{{ item.component_name }}</h5>
                  <div class="risk-indicator w-4 h-4 rounded-full" :class="getRiskIndicatorClass(item.risk_score)"></div>
                </div>
                <div class="space-y-2 text-xs">
                  <div class="flex justify-between">
                    <span>Risk Score:</span>
                    <span class="font-bold">{{ item.risk_score.toFixed(1) }}/100</span>
                  </div>
                  <div class="risk-breakdown">
                    <div class="flex justify-between">
                      <span>Critical:</span>
                      <span class="text-red-600 font-medium">{{ item.severity_distribution.critical || 0 }}</span>
                    </div>
                    <div class="flex justify-between">
                      <span>High:</span>
                      <span class="text-orange-600 font-medium">{{ item.severity_distribution.high || 0 }}</span>
                    </div>
                    <div class="flex justify-between">
                      <span>Medium:</span>
                      <span class="text-yellow-600 font-medium">{{ item.severity_distribution.medium || 0 }}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <!-- OWASP Category View -->
          <div 
            v-else-if="selectedView === 'owasp'"
            class="owasp-heatmap grid grid-cols-2 md:grid-cols-5 gap-3"
          >
            <div 
              v-for="category in owaspCategories" 
              :key="category.code"
              class="owasp-cell rounded-lg p-3 text-center cursor-pointer transition-all hover:scale-105"
              :class="getOWASPCellClass(category.risk_level)"
              @click="selectOWASPCategory(category)"
            >
              <div class="font-bold text-sm mb-1">{{ category.code }}</div>
              <div class="text-xs mb-2">{{ category.name }}</div>
              <div class="text-lg font-bold">{{ category.issue_count }}</div>
              <div class="text-xs opacity-75">issues</div>
            </div>
          </div>
          
          <!-- Severity View -->
          <div 
            v-else-if="selectedView === 'severity'"
            class="severity-heatmap"
          >
            <canvas ref="severityCanvas" class="w-full h-64"></canvas>
          </div>
        </div>
      </div>

      <!-- Selected Item Details -->
      <div v-if="selectedItem" class="item-details bg-white rounded-lg shadow-md p-6 mb-6">
        <div class="flex items-center justify-between mb-4">
          <h4 class="text-lg font-semibold text-gray-900">{{ selectedItem.name }} Details</h4>
          <button 
            @click="selectedItem = null"
            class="text-gray-400 hover:text-gray-600"
          >
            <span class="sr-only">Close</span>
            ✕
          </button>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h5 class="font-medium text-gray-900 mb-3">Risk Breakdown</h5>
            <div class="space-y-2 text-sm">
              <div class="flex justify-between">
                <span>Overall Risk Score:</span>
                <span class="font-bold" :class="getRiskScoreColor(selectedItem.risk_score)">
                  {{ selectedItem.risk_score.toFixed(1) }}/100
                </span>
              </div>
              <div class="flex justify-between">
                <span>Total Threats:</span>
                <span class="font-medium">{{ selectedItem.threat_count }}</span>
              </div>
              <div class="flex justify-between">
                <span>Total Vulnerabilities:</span>
                <span class="font-medium">{{ selectedItem.vulnerability_count }}</span>
              </div>
              <div class="flex justify-between">
                <span>OWASP Categories:</span>
                <span class="font-medium">{{ selectedItem.owasp_categories?.length || 0 }}</span>
              </div>
            </div>
          </div>
          
          <div>
            <h5 class="font-medium text-gray-900 mb-3">Severity Distribution</h5>
            <div class="space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-sm">Critical</span>
                <div class="flex items-center gap-2">
                  <div class="w-20 bg-gray-200 rounded-full h-2">
                    <div 
                      class="bg-red-500 h-2 rounded-full"
                      :style="{ width: `${getSeverityPercentage(selectedItem, 'critical')}%` }"
                    ></div>
                  </div>
                  <span class="text-sm font-medium w-8">{{ selectedItem.severity_distribution?.critical || 0 }}</span>
                </div>
              </div>
              <div class="flex items-center justify-between">
                <span class="text-sm">High</span>
                <div class="flex items-center gap-2">
                  <div class="w-20 bg-gray-200 rounded-full h-2">
                    <div 
                      class="bg-orange-500 h-2 rounded-full"
                      :style="{ width: `${getSeverityPercentage(selectedItem, 'high')}%` }"
                    ></div>
                  </div>
                  <span class="text-sm font-medium w-8">{{ selectedItem.severity_distribution?.high || 0 }}</span>
                </div>
              </div>
              <div class="flex items-center justify-between">
                <span class="text-sm">Medium</span>
                <div class="flex items-center gap-2">
                  <div class="w-20 bg-gray-200 rounded-full h-2">
                    <div 
                      class="bg-yellow-500 h-2 rounded-full"
                      :style="{ width: `${getSeverityPercentage(selectedItem, 'medium')}%` }"
                    ></div>
                  </div>
                  <span class="text-sm font-medium w-8">{{ selectedItem.severity_distribution?.medium || 0 }}</span>
                </div>
              </div>
              <div class="flex items-center justify-between">
                <span class="text-sm">Low</span>
                <div class="flex items-center gap-2">
                  <div class="w-20 bg-gray-200 rounded-full h-2">
                    <div 
                      class="bg-green-500 h-2 rounded-full"
                      :style="{ width: `${getSeverityPercentage(selectedItem, 'low')}%` }"
                    ></div>
                  </div>
                  <span class="text-sm font-medium w-8">{{ selectedItem.severity_distribution?.low || 0 }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        
        <!-- OWASP Categories -->
        <div v-if="selectedItem.owasp_categories && selectedItem.owasp_categories.length > 0" class="mt-6">
          <h5 class="font-medium text-gray-900 mb-3">Affected OWASP Categories</h5>
          <div class="flex flex-wrap gap-2">
            <span 
              v-for="category in selectedItem.owasp_categories" 
              :key="category"
              class="px-3 py-1 bg-blue-100 text-blue-800 text-sm rounded-full"
            >
              {{ category }}
            </span>
          </div>
        </div>
      </div>

      <!-- Top Risk Items -->
      <div class="top-risks bg-white rounded-lg shadow-md p-6">
        <h4 class="text-lg font-semibold text-gray-900 mb-4">Top Security Risks</h4>
        
        <div class="space-y-3">
          <div 
            v-for="(item, index) in topRiskItems" 
            :key="item.id"
            class="risk-item flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors cursor-pointer"
            @click="selectHeatmapItem(item)"
          >
            <div class="flex items-center gap-3">
              <div class="rank-badge w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold text-white"
                   :class="getRankBadgeClass(index)">
                {{ index + 1 }}
              </div>
              <div>
                <div class="font-medium text-sm">{{ item.name }}</div>
                <div class="text-xs text-gray-600">{{ item.component_name || 'Repository' }}</div>
              </div>
            </div>
            <div class="text-right">
              <div class="font-bold text-sm" :class="getRiskScoreColor(item.risk_score)">
                {{ item.risk_score.toFixed(1) }}
              </div>
              <div class="text-xs text-gray-600">
                {{ item.threat_count }}T / {{ item.vulnerability_count }}V
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="text-center py-12 text-gray-500">
      <div class="text-lg font-medium mb-2">No risk data available</div>
      <p class="text-sm">Run a security analysis to generate risk heatmap data</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed, nextTick } from 'vue'
import { Chart, registerables } from 'chart.js'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

Chart.register(...registerables)

interface Props {
  repoId?: string
  refreshTrigger?: number
}

const props = withDefaults(defineProps<Props>(), {
  repoId: undefined,
  refreshTrigger: 0
})

interface HeatmapItem {
  id: string
  name: string
  component_name?: string
  risk_score: number
  threat_count: number
  vulnerability_count: number
  severity_distribution: Record<string, number>
  owasp_categories: string[]
  last_updated: string
}

interface HeatmapData {
  summary: {
    critical_count: number
    high_count: number
    medium_count: number
    low_count: number
  }
  items: HeatmapItem[]
}

const loading = ref(false)
const selectedView = ref('repository')
const heatmapData = ref<HeatmapData | null>(null)
const selectedItem = ref<HeatmapItem | null>(null)
const severityCanvas = ref<HTMLCanvasElement>()

const owaspCategories = ref([
  { code: 'A01', name: 'Access Control', risk_level: 'high', issue_count: 12 },
  { code: 'A02', name: 'Cryptographic', risk_level: 'critical', issue_count: 8 },
  { code: 'A03', name: 'Injection', risk_level: 'medium', issue_count: 15 },
  { code: 'A04', name: 'Insecure Design', risk_level: 'medium', issue_count: 6 },
  { code: 'A05', name: 'Misconfiguration', risk_level: 'high', issue_count: 10 },
  { code: 'A06', name: 'Vulnerable Components', risk_level: 'low', issue_count: 4 },
  { code: 'A07', name: 'Auth Failures', risk_level: 'high', issue_count: 9 },
  { code: 'A08', name: 'Integrity Failures', risk_level: 'critical', issue_count: 7 },
  { code: 'A09', name: 'Logging Failures', risk_level: 'low', issue_count: 3 },
  { code: 'A10', name: 'SSRF', risk_level: 'medium', issue_count: 5 }
])

onMounted(() => {
  loadHeatmapData()
})

const topRiskItems = computed(() => {
  if (!heatmapData.value) return []
  return [...heatmapData.value.items]
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 5)
})

const loadHeatmapData = async () => {
  loading.value = true
  try {
    // Mock data for demonstration
    const mockData: HeatmapData = {
      summary: {
        critical_count: 8,
        high_count: 15,
        medium_count: 23,
        low_count: 12
      },
      items: [
        {
          id: 'repo-1',
          name: 'user-authentication-service',
          component_name: 'Authentication Module',
          risk_score: 85.2,
          threat_count: 12,
          vulnerability_count: 8,
          severity_distribution: { critical: 3, high: 5, medium: 4, low: 0 },
          owasp_categories: ['A01', 'A02', 'A07'],
          last_updated: new Date().toISOString()
        },
        {
          id: 'repo-2',
          name: 'payment-processing-api',
          component_name: 'Payment Gateway',
          risk_score: 78.9,
          threat_count: 10,
          vulnerability_count: 6,
          severity_distribution: { critical: 2, high: 4, medium: 4, low: 0 },
          owasp_categories: ['A02', 'A03', 'A05'],
          last_updated: new Date(Date.now() - 86400000).toISOString()
        },
        {
          id: 'repo-3',
          name: 'data-analytics-dashboard',
          component_name: 'Analytics Engine',
          risk_score: 65.4,
          threat_count: 8,
          vulnerability_count: 4,
          severity_distribution: { critical: 1, high: 3, medium: 4, low: 0 },
          owasp_categories: ['A01', 'A05', 'A09'],
          last_updated: new Date(Date.now() - 172800000).toISOString()
        },
        {
          id: 'repo-4',
          name: 'file-upload-service',
          component_name: 'File Handler',
          risk_score: 72.1,
          threat_count: 9,
          vulnerability_count: 5,
          severity_distribution: { critical: 2, high: 3, medium: 4, low: 0 },
          owasp_categories: ['A03', 'A06', 'A08'],
          last_updated: new Date(Date.now() - 259200000).toISOString()
        },
        {
          id: 'repo-5',
          name: 'notification-system',
          component_name: 'Notification Service',
          risk_score: 45.8,
          threat_count: 5,
          vulnerability_count: 2,
          severity_distribution: { critical: 0, high: 2, medium: 3, low: 0 },
          owasp_categories: ['A09', 'A10'],
          last_updated: new Date(Date.now() - 345600000).toISOString()
        },
        {
          id: 'repo-6',
          name: 'user-profile-service',
          component_name: 'Profile Manager',
          risk_score: 38.2,
          threat_count: 4,
          vulnerability_count: 1,
          severity_distribution: { critical: 0, high: 1, medium: 3, low: 0 },
          owasp_categories: ['A01', 'A07'],
          last_updated: new Date(Date.now() - 432000000).toISOString()
        }
      ]
    }
    
    heatmapData.value = mockData
    
    if (selectedView.value === 'severity') {
      await nextTick()
      renderSeverityChart()
    }
  } catch (error) {
    console.error('Failed to load heatmap data:', error)
  } finally {
    loading.value = false
  }
}

const updateHeatmapView = async () => {
  if (selectedView.value === 'severity') {
    await nextTick()
    renderSeverityChart()
  }
}

const renderSeverityChart = () => {
  if (!severityCanvas.value || !heatmapData.value) return
  
  const ctx = severityCanvas.value.getContext('2d')
  if (!ctx) return
  
  // Aggregate severity data
  const severityData = heatmapData.value.items.reduce((acc, item) => {
    acc.critical += item.severity_distribution.critical || 0
    acc.high += item.severity_distribution.high || 0
    acc.medium += item.severity_distribution.medium || 0
    acc.low += item.severity_distribution.low || 0
    return acc
  }, { critical: 0, high: 0, medium: 0, low: 0 })
  
  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [severityData.critical, severityData.high, severityData.medium, severityData.low],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
        borderWidth: 2,
        borderColor: '#ffffff'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom'
        }
      }
    }
  })
}

const refreshHeatmap = () => {
  loadHeatmapData()
}

const selectHeatmapItem = (item: HeatmapItem) => {
  selectedItem.value = item
}

const selectOWASPCategory = (category: any) => {
  console.log('Selected OWASP category:', category)
  // Implementation for OWASP category selection
}

const getRiskCellClass = (riskScore: number): string => {
  if (riskScore >= 80) return 'bg-red-100 border-red-300 text-red-900'
  if (riskScore >= 60) return 'bg-orange-100 border-orange-300 text-orange-900'
  if (riskScore >= 40) return 'bg-yellow-100 border-yellow-300 text-yellow-900'
  return 'bg-green-100 border-green-300 text-green-900'
}

const getRiskBadgeClass = (riskScore: number): string => {
  if (riskScore >= 80) return 'bg-red-500 text-white'
  if (riskScore >= 60) return 'bg-orange-500 text-white'
  if (riskScore >= 40) return 'bg-yellow-500 text-white'
  return 'bg-green-500 text-white'
}

const getRiskIndicatorClass = (riskScore: number): string => {
  if (riskScore >= 80) return 'bg-red-500'
  if (riskScore >= 60) return 'bg-orange-500'
  if (riskScore >= 40) return 'bg-yellow-500'
  return 'bg-green-500'
}

const getOWASPCellClass = (riskLevel: string): string => {
  switch (riskLevel) {
    case 'critical': return 'bg-red-100 border-red-300 text-red-900'
    case 'high': return 'bg-orange-100 border-orange-300 text-orange-900'
    case 'medium': return 'bg-yellow-100 border-yellow-300 text-yellow-900'
    case 'low': return 'bg-green-100 border-green-300 text-green-900'
    default: return 'bg-gray-100 border-gray-300 text-gray-900'
  }
}

const getRiskScoreColor = (riskScore: number): string => {
  if (riskScore >= 80) return 'text-red-600'
  if (riskScore >= 60) return 'text-orange-600'
  if (riskScore >= 40) return 'text-yellow-600'
  return 'text-green-600'
}

const getRankBadgeClass = (index: number): string => {
  if (index === 0) return 'bg-red-500'
  if (index === 1) return 'bg-orange-500'
  if (index === 2) return 'bg-yellow-500'
  return 'bg-gray-500'
}

const getSeverityPercentage = (item: HeatmapItem, severity: string): number => {
  const total = Object.values(item.severity_distribution).reduce((sum, count) => sum + count, 0)
  if (total === 0) return 0
  return ((item.severity_distribution[severity] || 0) / total) * 100
}

const formatDate = (dateString: string): string => {
  const date = new Date(dateString)
  const now = new Date()
  const diffTime = Math.abs(now.getTime() - date.getTime())
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
  
  if (diffDays === 1) return 'Today'
  if (diffDays === 2) return 'Yesterday'
  if (diffDays <= 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}
</script>

<style scoped>
.security-risk-heatmap {
  max-width: 100%;
}

.heatmap-cell {
  min-height: 120px;
  border: 2px solid;
  transition: all 0.2s ease;
}

.heatmap-cell:hover {
  transform: scale(1.02);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.component-cell {
  min-height: 140px;
}

.owasp-cell {
  min-height: 100px;
  border: 2px solid;
}

.risk-item {
  transition: all 0.2s ease;
}

.risk-item:hover {
  transform: translateX(4px);
}

.summary-card {
  transition: all 0.2s ease;
}

.summary-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
</style>