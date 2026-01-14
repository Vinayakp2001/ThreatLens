<template>
  <div class="security-trend-chart">
    <div class="chart-header mb-4">
      <h3 class="text-lg font-semibold">{{ title }}</h3>
      <div class="flex gap-2 mt-2">
        <button
          v-for="period in availablePeriods"
          :key="period"
          @click="selectedPeriod = period"
          :class="[
            'px-3 py-1 text-sm rounded-md transition-colors',
            selectedPeriod === period
              ? 'bg-blue-500 text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          ]"
        >
          {{ period }}
        </button>
      </div>
    </div>

    <div v-if="loading" class="flex justify-center py-8">
      <LoadingSpinner />
    </div>

    <div v-else-if="trendData" class="trend-content">
      <!-- Trend Summary -->
      <div class="trend-summary bg-white rounded-lg shadow-md p-4 mb-6">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div class="metric-card">
            <div class="text-sm text-gray-600">Overall Trend</div>
            <div class="flex items-center gap-2 mt-1">
              <div 
                :class="[
                  'w-3 h-3 rounded-full',
                  getTrendColor(trendData.trend_direction)
                ]"
              ></div>
              <span class="font-semibold capitalize">{{ trendData.trend_direction }}</span>
            </div>
            <div class="text-xs text-gray-500 mt-1">
              Strength: {{ (trendData.trend_strength * 100).toFixed(1) }}%
            </div>
          </div>
          
          <div class="metric-card">
            <div class="text-sm text-gray-600">Current Score</div>
            <div class="text-2xl font-bold mt-1">
              {{ (trendData.latest_score * 100).toFixed(1) }}%
            </div>
            <div 
              :class="[
                'text-xs mt-1',
                trendData.score_change > 0 ? 'text-green-600' : 
                trendData.score_change < 0 ? 'text-red-600' : 'text-gray-500'
              ]"
            >
              {{ trendData.score_change > 0 ? '+' : '' }}{{ (trendData.score_change * 100).toFixed(1) }}%
            </div>
          </div>
          
          <div class="metric-card">
            <div class="text-sm text-gray-600">Volatility</div>
            <div class="text-lg font-semibold mt-1">
              {{ getVolatilityLevel(trendData.volatility) }}
            </div>
            <div class="text-xs text-gray-500 mt-1">
              {{ (trendData.volatility * 100).toFixed(1) }}%
            </div>
          </div>
          
          <div class="metric-card">
            <div class="text-sm text-gray-600">Duration</div>
            <div class="text-lg font-semibold mt-1">
              {{ trendData.duration_days }} days
            </div>
            <div class="text-xs text-gray-500 mt-1">
              {{ trendData.data_points.length }} data points
            </div>
          </div>
        </div>
      </div>

      <!-- Chart Container -->
      <div class="chart-container bg-white rounded-lg shadow-md p-6 mb-6">
        <canvas ref="chartCanvas" class="w-full h-64"></canvas>
      </div>

      <!-- Regression Alerts -->
      <div v-if="regressionAlerts && regressionAlerts.length > 0" class="alerts-section mb-6">
        <h4 class="text-md font-semibold mb-3 text-red-700">Security Regression Alerts</h4>
        <div class="space-y-3">
          <div 
            v-for="alert in regressionAlerts" 
            :key="`${alert.timestamp}_${alert.regression_type}`"
            class="alert-card border-l-4 border-red-500 bg-red-50 p-4 rounded-r-lg"
          >
            <div class="flex justify-between items-start mb-2">
              <div class="flex items-center gap-2">
                <span 
                  :class="[
                    'px-2 py-1 text-xs rounded-full font-medium',
                    getSeverityClass(alert.severity)
                  ]"
                >
                  {{ alert.severity.toUpperCase() }}
                </span>
                <span class="font-medium">{{ formatRegressionType(alert.regression_type) }}</span>
              </div>
              <span class="text-xs text-gray-500">{{ formatDate(alert.timestamp) }}</span>
            </div>
            <p class="text-sm text-gray-700 mb-3">{{ alert.description }}</p>
            
            <div v-if="alert.recommended_actions.length > 0" class="recommended-actions">
              <div class="text-xs font-medium text-gray-600 mb-1">Recommended Actions:</div>
              <ul class="text-xs text-gray-600 space-y-1">
                <li v-for="action in alert.recommended_actions" :key="action" class="flex items-start gap-1">
                  <span class="text-red-500 mt-0.5">•</span>
                  <span>{{ action }}</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      <!-- Key Insights -->
      <div class="insights-section bg-white rounded-lg shadow-md p-6">
        <h4 class="text-md font-semibold mb-3">Key Insights</h4>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div v-if="keyInsights && keyInsights.length > 0">
            <h5 class="text-sm font-medium text-gray-700 mb-2">Analysis Insights</h5>
            <ul class="space-y-2">
              <li v-for="insight in keyInsights" :key="insight" class="flex items-start gap-2 text-sm">
                <span class="text-blue-500 mt-1">ℹ</span>
                <span>{{ insight }}</span>
              </li>
            </ul>
          </div>
          
          <div v-if="improvementHighlights && improvementHighlights.length > 0">
            <h5 class="text-sm font-medium text-gray-700 mb-2">Improvements</h5>
            <ul class="space-y-2">
              <li v-for="improvement in improvementHighlights" :key="improvement" class="flex items-start gap-2 text-sm">
                <span class="text-green-500 mt-1">✓</span>
                <span>{{ improvement }}</span>
              </li>
            </ul>
          </div>
        </div>
        
        <div v-if="recommendations && recommendations.length > 0" class="mt-4 pt-4 border-t">
          <h5 class="text-sm font-medium text-gray-700 mb-2">Recommendations</h5>
          <ul class="space-y-2">
            <li v-for="recommendation in recommendations" :key="recommendation" class="flex items-start gap-2 text-sm">
              <span class="text-orange-500 mt-1">→</span>
              <span>{{ recommendation }}</span>
            </li>
          </ul>
        </div>
      </div>
    </div>

    <div v-else class="text-center py-8 text-gray-500">
      No trend data available
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch, nextTick } from 'vue'
import { Chart, registerables } from 'chart.js'
import { api } from '@/lib/api'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

Chart.register(...registerables)

interface Props {
  repoId: string
  title?: string
}

const props = withDefaults(defineProps<Props>(), {
  title: 'Security Trend Analysis'
})

interface SecurityTrendData {
  repo_id: string
  period: string
  data_points: Array<{
    timestamp: string
    wiki_id: string
    maturity_score: number
    threat_count: number
    mitigation_count: number
    compliance_score: number
    critical_threats: number
    high_threats: number
    medium_threats: number
    low_threats: number
    owasp_coverage: Record<string, number>
    regression_detected: boolean
    improvement_detected: boolean
  }>
  trend_direction: string
  trend_strength: number
  volatility: number
  analysis_period: [string, string]
  duration_days: number
  latest_score: number
  score_change: number
}

interface SecurityRegressionAlert {
  timestamp: string
  repo_id: string
  wiki_id: string
  severity: string
  regression_type: string
  description: string
  impact_score: number
  recommended_actions: string[]
  affected_owasp_categories: string[]
}

const availablePeriods = ['weekly', 'monthly', 'quarterly']
const selectedPeriod = ref('weekly')
const loading = ref(false)
const trendData = ref<SecurityTrendData | null>(null)
const regressionAlerts = ref<SecurityRegressionAlert[]>([])
const keyInsights = ref<string[]>([])
const improvementHighlights = ref<string[]>([])
const recommendations = ref<string[]>([])
const chartCanvas = ref<HTMLCanvasElement>()
const chartInstance = ref<Chart | null>(null)

onMounted(() => {
  loadTrendData()
})

watch(selectedPeriod, () => {
  loadTrendData()
})

const loadTrendData = async () => {
  if (!props.repoId) return
  
  loading.value = true
  try {
    const response = await api.post(`/api/wikis/${props.repoId}/trend-analysis`, {
      period: selectedPeriod.value,
      lookback_days: selectedPeriod.value === 'weekly' ? 30 : 
                     selectedPeriod.value === 'monthly' ? 90 : 180
    })
    
    const analysis = response.data
    trendData.value = analysis.trend_data
    regressionAlerts.value = analysis.regression_alerts || []
    keyInsights.value = analysis.key_insights || []
    improvementHighlights.value = analysis.improvement_highlights || []
    recommendations.value = analysis.recommendations || []
    
    await nextTick()
    renderChart()
  } catch (error) {
    console.error('Failed to load trend data:', error)
  } finally {
    loading.value = false
  }
}

const renderChart = () => {
  if (!chartCanvas.value || !trendData.value) return
  
  // Destroy existing chart
  if (chartInstance.value) {
    chartInstance.value.destroy()
  }
  
  const ctx = chartCanvas.value.getContext('2d')
  if (!ctx) return
  
  const dataPoints = trendData.value.data_points
  const labels = dataPoints.map(point => formatDate(point.timestamp))
  
  chartInstance.value = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Security Maturity Score',
          data: dataPoints.map(point => point.maturity_score * 100),
          borderColor: 'rgb(59, 130, 246)',
          backgroundColor: 'rgba(59, 130, 246, 0.1)',
          tension: 0.1,
          fill: true
        },
        {
          label: 'OWASP Compliance',
          data: dataPoints.map(point => point.compliance_score * 100),
          borderColor: 'rgb(16, 185, 129)',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          tension: 0.1,
          fill: false
        },
        {
          label: 'Threat Count',
          data: dataPoints.map(point => point.threat_count),
          borderColor: 'rgb(239, 68, 68)',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          tension: 0.1,
          fill: false,
          yAxisID: 'y1'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false,
      },
      scales: {
        x: {
          display: true,
          title: {
            display: true,
            text: 'Time'
          }
        },
        y: {
          type: 'linear',
          display: true,
          position: 'left',
          title: {
            display: true,
            text: 'Score (%)'
          },
          min: 0,
          max: 100
        },
        y1: {
          type: 'linear',
          display: true,
          position: 'right',
          title: {
            display: true,
            text: 'Threat Count'
          },
          grid: {
            drawOnChartArea: false,
          },
        }
      },
      plugins: {
        legend: {
          position: 'top' as const,
        },
        tooltip: {
          callbacks: {
            afterBody: (context) => {
              const dataIndex = context[0].dataIndex
              const point = dataPoints[dataIndex]
              return [
                `Critical Threats: ${point.critical_threats}`,
                `High Threats: ${point.high_threats}`,
                `Mitigations: ${point.mitigation_count}`
              ]
            }
          }
        }
      }
    }
  })
}

const getTrendColor = (direction: string) => {
  switch (direction) {
    case 'improving':
      return 'bg-green-500'
    case 'declining':
      return 'bg-red-500'
    case 'volatile':
      return 'bg-yellow-500'
    default:
      return 'bg-gray-500'
  }
}

const getVolatilityLevel = (volatility: number) => {
  if (volatility < 0.1) return 'Low'
  if (volatility < 0.25) return 'Medium'
  if (volatility < 0.4) return 'High'
  return 'Very High'
}

const getSeverityClass = (severity: string) => {
  switch (severity) {
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

const formatRegressionType = (type: string) => {
  return type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
}

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString()
}
</script>

<style scoped>
.security-trend-chart {
  max-width: 100%;
}

.metric-card {
  text-align: center;
}

.chart-container {
  position: relative;
  height: 300px;
}

.alert-card {
  transition: all 0.2s ease;
}

.alert-card:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}
</style>