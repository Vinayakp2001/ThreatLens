<template>
  <div class="security-metrics-chart">
    <div class="chart-header mb-6">
      <div class="flex items-center justify-between">
        <div>
          <h3 class="text-xl font-semibold text-gray-900">{{ title }}</h3>
          <p class="text-sm text-gray-600 mt-1">{{ description }}</p>
        </div>
        <div class="flex gap-2">
          <select 
            v-model="selectedTimeRange" 
            @change="updateTimeRange"
            class="px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <select 
            v-model="selectedChartType" 
            @change="updateChartType"
            class="px-3 py-2 text-sm border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="line">Line Chart</option>
            <option value="bar">Bar Chart</option>
            <option value="area">Area Chart</option>
            <option value="radar">Radar Chart</option>
          </select>
          <button 
            @click="refreshChart"
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

    <div v-else-if="chartData" class="chart-content">
      <!-- Metrics Summary Cards -->
      <div class="metrics-summary grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div class="metric-card bg-white rounded-lg shadow-md p-4 border-l-4 border-blue-500">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-gray-600">Security Score</div>
              <div class="text-2xl font-bold text-gray-900">{{ chartData.current_metrics.security_score.toFixed(1) }}%</div>
              <div class="text-xs" :class="getTrendColor(chartData.trends.security_score_trend)">
                {{ formatTrend(chartData.trends.security_score_trend) }}
              </div>
            </div>
            <div class="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
              <span class="text-blue-600 text-xl">🛡️</span>
            </div>
          </div>
        </div>
        
        <div class="metric-card bg-white rounded-lg shadow-md p-4 border-l-4 border-red-500">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-gray-600">Total Threats</div>
              <div class="text-2xl font-bold text-gray-900">{{ chartData.current_metrics.total_threats }}</div>
              <div class="text-xs" :class="getTrendColor(chartData.trends.threat_trend)">
                {{ formatTrend(chartData.trends.threat_trend) }}
              </div>
            </div>
            <div class="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
              <span class="text-red-600 text-xl">⚠️</span>
            </div>
          </div>
        </div>
        
        <div class="metric-card bg-white rounded-lg shadow-md p-4 border-l-4 border-orange-500">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-gray-600">Vulnerabilities</div>
              <div class="text-2xl font-bold text-gray-900">{{ chartData.current_metrics.total_vulnerabilities }}</div>
              <div class="text-xs" :class="getTrendColor(chartData.trends.vulnerability_trend)">
                {{ formatTrend(chartData.trends.vulnerability_trend) }}
              </div>
            </div>
            <div class="w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center">
              <span class="text-orange-600 text-xl">🔍</span>
            </div>
          </div>
        </div>
        
        <div class="metric-card bg-white rounded-lg shadow-md p-4 border-l-4 border-green-500">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm font-medium text-gray-600">Mitigations</div>
              <div class="text-2xl font-bold text-gray-900">{{ chartData.current_metrics.total_mitigations }}</div>
              <div class="text-xs" :class="getTrendColor(chartData.trends.mitigation_trend)">
                {{ formatTrend(chartData.trends.mitigation_trend) }}
              </div>
            </div>
            <div class="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
              <span class="text-green-600 text-xl">✅</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Main Chart -->
      <div class="main-chart bg-white rounded-lg shadow-md p-6 mb-6">
        <div class="flex items-center justify-between mb-4">
          <h4 class="text-lg font-semibold text-gray-900">Security Metrics Over Time</h4>
          <div class="chart-controls flex gap-2">
            <button 
              v-for="metric in availableMetrics" 
              :key="metric.key"
              @click="toggleMetric(metric.key)"
              :class="[
                'px-3 py-1 text-xs rounded-full transition-colors',
                visibleMetrics.includes(metric.key)
                  ? 'bg-blue-500 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              ]"
            >
              {{ metric.label }}
            </button>
          </div>
        </div>
        
        <div class="chart-container relative">
          <canvas ref="mainChartCanvas" class="w-full h-80"></canvas>
        </div>
      </div>

      <!-- Secondary Charts Grid -->
      <div class="secondary-charts grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <!-- OWASP Coverage Chart -->
        <div class="owasp-chart bg-white rounded-lg shadow-md p-6">
          <h4 class="text-lg font-semibold text-gray-900 mb-4">OWASP Coverage Distribution</h4>
          <canvas ref="owaspChartCanvas" class="w-full h-64"></canvas>
        </div>
        
        <!-- Severity Distribution Chart -->
        <div class="severity-chart bg-white rounded-lg shadow-md p-6">
          <h4 class="text-lg font-semibold text-gray-900 mb-4">Threat Severity Distribution</h4>
          <canvas ref="severityChartCanvas" class="w-full h-64"></canvas>
        </div>
      </div>

      <!-- Performance Metrics -->
      <div class="performance-metrics bg-white rounded-lg shadow-md p-6 mb-6">
        <h4 class="text-lg font-semibold text-gray-900 mb-4">Analysis Performance</h4>
        
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="performance-stat">
            <div class="text-sm font-medium text-gray-600 mb-2">Analysis Throughput</div>
            <div class="text-xl font-bold text-gray-900">{{ chartData.performance_metrics.analysis_throughput.toFixed(1) }}</div>
            <div class="text-xs text-gray-500">analyses/hour</div>
          </div>
          
          <div class="performance-stat">
            <div class="text-sm font-medium text-gray-600 mb-2">Avg Processing Time</div>
            <div class="text-xl font-bold text-gray-900">{{ formatDuration(chartData.performance_metrics.average_processing_time) }}</div>
            <div class="text-xs text-gray-500">per analysis</div>
          </div>
          
          <div class="performance-stat">
            <div class="text-sm font-medium text-gray-600 mb-2">Queue Length</div>
            <div class="text-xl font-bold text-gray-900">{{ chartData.performance_metrics.queue_length }}</div>
            <div class="text-xs text-gray-500">pending analyses</div>
          </div>
        </div>
        
        <!-- Resource Utilization -->
        <div class="resource-utilization mt-6">
          <h5 class="text-md font-medium text-gray-900 mb-3">Resource Utilization</h5>
          <div class="space-y-3">
            <div class="resource-bar">
              <div class="flex justify-between text-sm mb-1">
                <span>CPU Usage</span>
                <span>{{ chartData.performance_metrics.resource_utilization.cpu_usage.toFixed(1) }}%</span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div 
                  class="h-2 rounded-full transition-all duration-300"
                  :class="getResourceBarColor(chartData.performance_metrics.resource_utilization.cpu_usage)"
                  :style="{ width: `${chartData.performance_metrics.resource_utilization.cpu_usage}%` }"
                ></div>
              </div>
            </div>
            
            <div class="resource-bar">
              <div class="flex justify-between text-sm mb-1">
                <span>Memory Usage</span>
                <span>{{ chartData.performance_metrics.resource_utilization.memory_usage.toFixed(1) }}%</span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div 
                  class="h-2 rounded-full transition-all duration-300"
                  :class="getResourceBarColor(chartData.performance_metrics.resource_utilization.memory_usage)"
                  :style="{ width: `${chartData.performance_metrics.resource_utilization.memory_usage}%` }"
                ></div>
              </div>
            </div>
            
            <div class="resource-bar">
              <div class="flex justify-between text-sm mb-1">
                <span>Storage Usage</span>
                <span>{{ chartData.performance_metrics.resource_utilization.storage_usage.toFixed(1) }}%</span>
              </div>
              <div class="w-full bg-gray-200 rounded-full h-2">
                <div 
                  class="h-2 rounded-full transition-all duration-300"
                  :class="getResourceBarColor(chartData.performance_metrics.resource_utilization.storage_usage)"
                  :style="{ width: `${chartData.performance_metrics.resource_utilization.storage_usage}%` }"
                ></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Insights and Recommendations -->
      <div class="insights bg-white rounded-lg shadow-md p-6">
        <h4 class="text-lg font-semibold text-gray-900 mb-4">Key Insights</h4>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="insights-section">
            <h5 class="text-md font-medium text-gray-900 mb-3">Trend Analysis</h5>
            <div class="space-y-2 text-sm">
              <div class="insight-item flex items-start gap-2">
                <span class="text-blue-500 mt-1">📈</span>
                <span>Security score has {{ chartData.trends.security_score_trend > 0 ? 'improved' : 'declined' }} by {{ Math.abs(chartData.trends.security_score_trend).toFixed(1) }}% over the selected period</span>
              </div>
              <div class="insight-item flex items-start gap-2">
                <span class="text-orange-500 mt-1">⚡</span>
                <span>{{ chartData.trends.new_threats_count }} new threats identified, {{ chartData.trends.resolved_threats_count }} threats resolved</span>
              </div>
              <div class="insight-item flex items-start gap-2">
                <span class="text-green-500 mt-1">🔧</span>
                <span>Mitigation coverage has {{ chartData.trends.mitigation_trend > 0 ? 'increased' : 'decreased' }} by {{ Math.abs(chartData.trends.mitigation_trend).toFixed(1) }}%</span>
              </div>
            </div>
          </div>
          
          <div class="recommendations-section">
            <h5 class="text-md font-medium text-gray-900 mb-3">Recommendations</h5>
            <div class="space-y-2 text-sm">
              <div v-if="chartData.trends.security_score_trend < -5" class="recommendation-item flex items-start gap-2">
                <span class="text-red-500 mt-1">🚨</span>
                <span>Security score declining - immediate review recommended</span>
              </div>
              <div v-if="chartData.trends.threat_trend > 10" class="recommendation-item flex items-start gap-2">
                <span class="text-orange-500 mt-1">⚠️</span>
                <span>Threat count increasing - enhance monitoring and mitigation efforts</span>
              </div>
              <div v-if="chartData.performance_metrics.queue_length > 5" class="recommendation-item flex items-start gap-2">
                <span class="text-yellow-500 mt-1">⏱️</span>
                <span>Analysis queue building up - consider scaling resources</span>
              </div>
              <div v-if="chartData.performance_metrics.resource_utilization.cpu_usage > 80" class="recommendation-item flex items-start gap-2">
                <span class="text-red-500 mt-1">💻</span>
                <span>High CPU usage detected - monitor system performance</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-else class="text-center py-12 text-gray-500">
      <div class="text-lg font-medium mb-2">No metrics data available</div>
      <p class="text-sm">Run a security analysis to generate metrics data</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, nextTick, watch } from 'vue'
import { Chart, registerables } from 'chart.js'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

Chart.register(...registerables)

interface Props {
  title?: string
  description?: string
  repoId?: string
  refreshTrigger?: number
}

const props = withDefaults(defineProps<Props>(), {
  title: 'Security Metrics Dashboard',
  description: 'Real-time security metrics and performance analytics',
  repoId: undefined,
  refreshTrigger: 0
})

interface ChartData {
  current_metrics: {
    security_score: number
    total_threats: number
    total_vulnerabilities: number
    total_mitigations: number
    owasp_coverage: number
  }
  trends: {
    security_score_trend: number
    threat_trend: number
    vulnerability_trend: number
    mitigation_trend: number
    new_threats_count: number
    resolved_threats_count: number
    regression_count: number
  }
  historical_data: Array<{
    timestamp: string
    security_score: number
    threats: number
    vulnerabilities: number
    mitigations: number
    owasp_coverage: number
  }>
  owasp_distribution: Record<string, number>
  severity_distribution: Record<string, number>
  performance_metrics: {
    analysis_throughput: number
    average_processing_time: number
    queue_length: number
    resource_utilization: {
      cpu_usage: number
      memory_usage: number
      storage_usage: number
    }
    cache_performance: {
      hit_rate: number
      miss_rate: number
    }
  }
}

const loading = ref(false)
const selectedTimeRange = ref('24h')
const selectedChartType = ref('line')
const chartData = ref<ChartData | null>(null)
const visibleMetrics = ref(['security_score', 'threats', 'mitigations'])

const mainChartCanvas = ref<HTMLCanvasElement>()
const owaspChartCanvas = ref<HTMLCanvasElement>()
const severityChartCanvas = ref<HTMLCanvasElement>()

const mainChart = ref<Chart | null>(null)
const owaspChart = ref<Chart | null>(null)
const severityChart = ref<Chart | null>(null)

const availableMetrics = [
  { key: 'security_score', label: 'Security Score', color: '#3b82f6' },
  { key: 'threats', label: 'Threats', color: '#ef4444' },
  { key: 'vulnerabilities', label: 'Vulnerabilities', color: '#f97316' },
  { key: 'mitigations', label: 'Mitigations', color: '#22c55e' },
  { key: 'owasp_coverage', label: 'OWASP Coverage', color: '#8b5cf6' }
]

onMounted(() => {
  loadChartData()
})

watch(() => props.refreshTrigger, () => {
  loadChartData()
})

const loadChartData = async () => {
  loading.value = true
  try {
    // Mock data for demonstration
    const mockData: ChartData = {
      current_metrics: {
        security_score: 75.8,
        total_threats: 23,
        total_vulnerabilities: 15,
        total_mitigations: 18,
        owasp_coverage: 67.5
      },
      trends: {
        security_score_trend: 5.2,
        threat_trend: -8.1,
        vulnerability_trend: -12.3,
        mitigation_trend: 15.7,
        new_threats_count: 3,
        resolved_threats_count: 7,
        regression_count: 1
      },
      historical_data: generateHistoricalData(),
      owasp_distribution: {
        'A01': 12, 'A02': 8, 'A03': 15, 'A04': 6, 'A05': 10,
        'A06': 4, 'A07': 9, 'A08': 7, 'A09': 3, 'A10': 5
      },
      severity_distribution: {
        'Critical': 8,
        'High': 15,
        'Medium': 23,
        'Low': 12
      },
      performance_metrics: {
        analysis_throughput: 12.5,
        average_processing_time: 145.2,
        queue_length: 3,
        resource_utilization: {
          cpu_usage: 65.4,
          memory_usage: 72.1,
          storage_usage: 45.8
        },
        cache_performance: {
          hit_rate: 85.2,
          miss_rate: 14.8
        }
      }
    }
    
    chartData.value = mockData
    
    await nextTick()
    renderCharts()
  } catch (error) {
    console.error('Failed to load chart data:', error)
  } finally {
    loading.value = false
  }
}

const generateHistoricalData = () => {
  const data = []
  const now = new Date()
  
  for (let i = 23; i >= 0; i--) {
    const timestamp = new Date(now.getTime() - i * 60 * 60 * 1000)
    data.push({
      timestamp: timestamp.toISOString(),
      security_score: 70 + Math.random() * 20 + Math.sin(i * 0.5) * 5,
      threats: 20 + Math.floor(Math.random() * 10) + Math.sin(i * 0.3) * 3,
      vulnerabilities: 12 + Math.floor(Math.random() * 8) + Math.sin(i * 0.4) * 2,
      mitigations: 15 + Math.floor(Math.random() * 8) + Math.sin(i * 0.2) * 3,
      owasp_coverage: 60 + Math.random() * 15 + Math.sin(i * 0.6) * 5
    })
  }
  
  return data
}

const renderCharts = () => {
  renderMainChart()
  renderOWASPChart()
  renderSeverityChart()
}

const renderMainChart = () => {
  if (!mainChartCanvas.value || !chartData.value) return
  
  if (mainChart.value) {
    mainChart.value.destroy()
  }
  
  const ctx = mainChartCanvas.value.getContext('2d')
  if (!ctx) return
  
  const labels = chartData.value.historical_data.map(point => 
    new Date(point.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  )
  
  const datasets = availableMetrics
    .filter(metric => visibleMetrics.value.includes(metric.key))
    .map(metric => {
      let data: number[]
      let yAxisID = 'y'
      
      switch (metric.key) {
        case 'security_score':
          data = chartData.value!.historical_data.map(point => point.security_score)
          break
        case 'threats':
          data = chartData.value!.historical_data.map(point => point.threats)
          yAxisID = 'y1'
          break
        case 'vulnerabilities':
          data = chartData.value!.historical_data.map(point => point.vulnerabilities)
          yAxisID = 'y1'
          break
        case 'mitigations':
          data = chartData.value!.historical_data.map(point => point.mitigations)
          yAxisID = 'y1'
          break
        case 'owasp_coverage':
          data = chartData.value!.historical_data.map(point => point.owasp_coverage)
          break
        default:
          data = []
      }
      
      return {
        label: metric.label,
        data,
        borderColor: metric.color,
        backgroundColor: metric.color + '20',
        tension: 0.1,
        fill: selectedChartType.value === 'area',
        yAxisID
      }
    })
  
  mainChart.value = new Chart(ctx, {
    type: selectedChartType.value === 'radar' ? 'radar' : 
          selectedChartType.value === 'area' ? 'line' : selectedChartType.value as any,
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false,
      },
      scales: selectedChartType.value === 'radar' ? {} : {
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
            text: 'Count'
          },
          grid: {
            drawOnChartArea: false,
          },
        }
      },
      plugins: {
        legend: {
          position: 'top' as const,
        }
      }
    }
  })
}

const renderOWASPChart = () => {
  if (!owaspChartCanvas.value || !chartData.value) return
  
  if (owaspChart.value) {
    owaspChart.value.destroy()
  }
  
  const ctx = owaspChartCanvas.value.getContext('2d')
  if (!ctx) return
  
  const labels = Object.keys(chartData.value.owasp_distribution)
  const data = Object.values(chartData.value.owasp_distribution)
  
  owaspChart.value = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Issues Count',
        data,
        backgroundColor: [
          '#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4',
          '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981'
        ],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: 'Number of Issues'
          }
        },
        x: {
          title: {
            display: true,
            text: 'OWASP Categories'
          }
        }
      }
    }
  })
}

const renderSeverityChart = () => {
  if (!severityChartCanvas.value || !chartData.value) return
  
  if (severityChart.value) {
    severityChart.value.destroy()
  }
  
  const ctx = severityChartCanvas.value.getContext('2d')
  if (!ctx) return
  
  const labels = Object.keys(chartData.value.severity_distribution)
  const data = Object.values(chartData.value.severity_distribution)
  
  severityChart.value = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
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

const updateTimeRange = () => {
  loadChartData()
}

const updateChartType = () => {
  renderMainChart()
}

const refreshChart = () => {
  loadChartData()
}

const toggleMetric = (metricKey: string) => {
  const index = visibleMetrics.value.indexOf(metricKey)
  if (index > -1) {
    visibleMetrics.value.splice(index, 1)
  } else {
    visibleMetrics.value.push(metricKey)
  }
  renderMainChart()
}

const getTrendColor = (trend: number): string => {
  if (trend > 0) return 'text-green-600'
  if (trend < 0) return 'text-red-600'
  return 'text-gray-600'
}

const formatTrend = (trend: number): string => {
  const sign = trend > 0 ? '+' : ''
  return `${sign}${trend.toFixed(1)}%`
}

const formatDuration = (seconds: number): string => {
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  return `${minutes}m ${remainingSeconds.toFixed(0)}s`
}

const getResourceBarColor = (usage: number): string => {
  if (usage >= 90) return 'bg-red-500'
  if (usage >= 75) return 'bg-orange-500'
  if (usage >= 50) return 'bg-yellow-500'
  return 'bg-green-500'
}
</script>

<style scoped>
.security-metrics-chart {
  max-width: 100%;
}

.metric-card {
  transition: all 0.2s ease;
}

.metric-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.chart-container {
  position: relative;
  height: 320px;
}

.insight-item, .recommendation-item {
  transition: all 0.2s ease;
}

.insight-item:hover, .recommendation-item:hover {
  transform: translateX(4px);
}

.resource-bar {
  transition: all 0.3s ease;
}
</style>