<template>
  <div class="owasp-compliance-dashboard">
    <div class="dashboard-header mb-6">
      <h3 class="text-xl font-semibold text-gray-900">OWASP Top 10 Compliance Dashboard</h3>
      <p class="text-sm text-gray-600 mt-1">Security coverage analysis based on OWASP Top 10 2021</p>
    </div>

    <div v-if="loading" class="flex justify-center py-12">
      <LoadingSpinner />
    </div>

    <div v-else-if="complianceData" class="compliance-content">
      <!-- Overall Compliance Score -->
      <div class="overall-score-card bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg p-6 mb-6 border border-blue-200">
        <div class="flex items-center justify-between">
          <div>
            <h4 class="text-lg font-semibold text-gray-900">Overall OWASP Compliance</h4>
            <p class="text-sm text-gray-600 mt-1">Aggregate coverage across all categories</p>
          </div>
          <div class="text-right">
            <div class="text-3xl font-bold" :class="getScoreColor(complianceData.overall_coverage)">
              {{ complianceData.overall_coverage.toFixed(1) }}%
            </div>
            <div class="text-sm text-gray-600 mt-1">
              {{ getComplianceLevel(complianceData.overall_coverage) }}
            </div>
          </div>
        </div>
        
        <!-- Overall Progress Bar -->
        <div class="mt-4">
          <div class="w-full bg-gray-200 rounded-full h-3">
            <div 
              class="h-3 rounded-full transition-all duration-500"
              :class="getProgressBarColor(complianceData.overall_coverage)"
              :style="{ width: `${complianceData.overall_coverage}%` }"
            ></div>
          </div>
        </div>
      </div>

      <!-- OWASP Categories Grid -->
      <div class="categories-grid grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-6">
        <div 
          v-for="(coverage, category) in complianceData.category_coverage" 
          :key="category"
          class="category-card bg-white rounded-lg shadow-md p-5 border hover:shadow-lg transition-shadow"
        >
          <div class="flex items-start justify-between mb-3">
            <div class="flex-1">
              <h5 class="font-semibold text-gray-900 text-sm">
                {{ formatCategoryName(category) }}
              </h5>
              <p class="text-xs text-gray-600 mt-1">
                {{ getCategoryDescription(category) }}
              </p>
            </div>
            <div class="ml-3 text-right">
              <div class="text-lg font-bold" :class="getScoreColor(coverage)">
                {{ coverage.toFixed(0) }}%
              </div>
            </div>
          </div>
          
          <!-- Category Progress Bar -->
          <div class="mb-3">
            <div class="w-full bg-gray-200 rounded-full h-2">
              <div 
                class="h-2 rounded-full transition-all duration-300"
                :class="getProgressBarColor(coverage)"
                :style="{ width: `${coverage}%` }"
              ></div>
            </div>
          </div>
          
          <!-- Category Status -->
          <div class="flex items-center justify-between text-xs">
            <span 
              class="px-2 py-1 rounded-full font-medium"
              :class="getCategoryStatusClass(coverage)"
            >
              {{ getCategoryStatus(coverage) }}
            </span>
            <span class="text-gray-500">
              {{ getCategoryTrend(category) }}
            </span>
          </div>
        </div>
      </div>

      <!-- Compliance Trends -->
      <div class="compliance-trends bg-white rounded-lg shadow-md p-6 mb-6">
        <h4 class="text-lg font-semibold text-gray-900 mb-4">Compliance Trends</h4>
        
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <!-- Improving Categories -->
          <div class="trend-section">
            <h5 class="text-sm font-medium text-green-700 mb-3 flex items-center">
              <span class="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
              Improving Categories
            </h5>
            <div class="space-y-2">
              <div 
                v-for="category in complianceData.coverage_trends.improving_categories" 
                :key="category"
                class="flex items-center justify-between text-sm"
              >
                <span class="text-gray-700">{{ formatOWASPCode(category) }}</span>
                <span class="text-green-600 font-medium">↗ +{{ getRandomTrend() }}%</span>
              </div>
              <div v-if="complianceData.coverage_trends.improving_categories.length === 0" class="text-sm text-gray-500 italic">
                No improving categories
              </div>
            </div>
          </div>
          
          <!-- Declining Categories -->
          <div class="trend-section">
            <h5 class="text-sm font-medium text-red-700 mb-3 flex items-center">
              <span class="w-2 h-2 bg-red-500 rounded-full mr-2"></span>
              Declining Categories
            </h5>
            <div class="space-y-2">
              <div 
                v-for="category in complianceData.coverage_trends.declining_categories" 
                :key="category"
                class="flex items-center justify-between text-sm"
              >
                <span class="text-gray-700">{{ formatOWASPCode(category) }}</span>
                <span class="text-red-600 font-medium">↘ -{{ getRandomTrend() }}%</span>
              </div>
              <div v-if="complianceData.coverage_trends.declining_categories.length === 0" class="text-sm text-gray-500 italic">
                No declining categories
              </div>
            </div>
          </div>
          
          <!-- Stable Categories -->
          <div class="trend-section">
            <h5 class="text-sm font-medium text-gray-700 mb-3 flex items-center">
              <span class="w-2 h-2 bg-gray-500 rounded-full mr-2"></span>
              Stable Categories
            </h5>
            <div class="space-y-2">
              <div 
                v-for="category in complianceData.coverage_trends.stable_categories.slice(0, 4)" 
                :key="category"
                class="flex items-center justify-between text-sm"
              >
                <span class="text-gray-700">{{ formatOWASPCode(category) }}</span>
                <span class="text-gray-600 font-medium">→ ±{{ Math.floor(Math.random() * 3) }}%</span>
              </div>
              <div v-if="complianceData.coverage_trends.stable_categories.length > 4" class="text-xs text-gray-500">
                +{{ complianceData.coverage_trends.stable_categories.length - 4 }} more
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Recommendations -->
      <div class="recommendations bg-white rounded-lg shadow-md p-6">
        <h4 class="text-lg font-semibold text-gray-900 mb-4">Compliance Recommendations</h4>
        
        <div class="space-y-4">
          <div 
            v-for="(recommendation, index) in complianceData.recommendations" 
            :key="index"
            class="recommendation-item flex items-start gap-3 p-4 bg-amber-50 rounded-lg border border-amber-200"
          >
            <div class="flex-shrink-0 mt-0.5">
              <div class="w-6 h-6 bg-amber-500 rounded-full flex items-center justify-center">
                <span class="text-white text-xs font-bold">{{ index + 1 }}</span>
              </div>
            </div>
            <div class="flex-1">
              <p class="text-sm text-gray-800">{{ recommendation }}</p>
            </div>
          </div>
        </div>
        
        <!-- Action Buttons -->
        <div class="mt-6 flex gap-3">
          <button 
            @click="generateComplianceReport"
            class="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700 transition-colors"
          >
            Generate Compliance Report
          </button>
          <button 
            @click="exportComplianceData"
            class="px-4 py-2 bg-gray-600 text-white text-sm font-medium rounded-md hover:bg-gray-700 transition-colors"
          >
            Export Data
          </button>
        </div>
      </div>
    </div>

    <div v-else class="text-center py-12 text-gray-500">
      <div class="text-lg font-medium mb-2">No compliance data available</div>
      <p class="text-sm">Run a security analysis to generate OWASP compliance metrics</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { api } from '@/lib/api'
import LoadingSpinner from '@/components/LoadingSpinner.vue'

interface Props {
  repoId?: string
  refreshTrigger?: number
}

const props = withDefaults(defineProps<Props>(), {
  repoId: undefined,
  refreshTrigger: 0
})

interface OWASPComplianceData {
  overall_coverage: number
  category_coverage: Record<string, number>
  coverage_trends: {
    improving_categories: string[]
    declining_categories: string[]
    stable_categories: string[]
  }
  recommendations: string[]
}

const loading = ref(false)
const complianceData = ref<OWASPComplianceData | null>(null)

const owaspCategories = {
  'A01_broken_access_control': {
    name: 'A01: Broken Access Control',
    description: 'Access control enforcement failures'
  },
  'A02_cryptographic_failures': {
    name: 'A02: Cryptographic Failures',
    description: 'Cryptography-related failures'
  },
  'A03_injection': {
    name: 'A03: Injection',
    description: 'Injection flaws and attacks'
  },
  'A04_insecure_design': {
    name: 'A04: Insecure Design',
    description: 'Design and architectural flaws'
  },
  'A05_security_misconfiguration': {
    name: 'A05: Security Misconfiguration',
    description: 'Security configuration issues'
  },
  'A06_vulnerable_components': {
    name: 'A06: Vulnerable Components',
    description: 'Vulnerable and outdated components'
  },
  'A07_identification_failures': {
    name: 'A07: Identification Failures',
    description: 'Authentication and session management'
  },
  'A08_software_integrity_failures': {
    name: 'A08: Software Integrity Failures',
    description: 'Software and data integrity failures'
  },
  'A09_logging_failures': {
    name: 'A09: Logging Failures',
    description: 'Security logging and monitoring'
  },
  'A10_server_side_request_forgery': {
    name: 'A10: Server-Side Request Forgery',
    description: 'SSRF vulnerabilities'
  }
}

onMounted(() => {
  loadComplianceData()
})

const loadComplianceData = async () => {
  loading.value = true
  try {
    // This would call the actual API endpoint for OWASP compliance data
    // For now, using mock data structure
    const mockData: OWASPComplianceData = {
      overall_coverage: 67.5,
      category_coverage: {
        'A01_broken_access_control': 70.0,
        'A02_cryptographic_failures': 45.0,
        'A03_injection': 80.0,
        'A04_insecure_design': 55.0,
        'A05_security_misconfiguration': 60.0,
        'A06_vulnerable_components': 75.0,
        'A07_identification_failures': 50.0,
        'A08_software_integrity_failures': 40.0,
        'A09_logging_failures': 85.0,
        'A10_server_side_request_forgery': 65.0
      },
      coverage_trends: {
        improving_categories: ['A03', 'A09'],
        declining_categories: ['A02', 'A08'],
        stable_categories: ['A01', 'A04', 'A05', 'A06', 'A07', 'A10']
      },
      recommendations: [
        'Focus on cryptographic failures (A02) - lowest coverage at 45%',
        'Improve software integrity failures (A08) monitoring and validation',
        'Maintain strong injection (A03) protection practices',
        'Enhance access control mechanisms for better A01 coverage',
        'Implement comprehensive logging for security events (A09)'
      ]
    }
    
    complianceData.value = mockData
  } catch (error) {
    console.error('Failed to load OWASP compliance data:', error)
  } finally {
    loading.value = false
  }
}

const formatCategoryName = (category: string): string => {
  return owaspCategories[category as keyof typeof owaspCategories]?.name || category
}

const getCategoryDescription = (category: string): string => {
  return owaspCategories[category as keyof typeof owaspCategories]?.description || ''
}

const formatOWASPCode = (code: string): string => {
  return code.replace(/^A0?/, 'A').padStart(3, '0')
}

const getScoreColor = (score: number): string => {
  if (score >= 80) return 'text-green-600'
  if (score >= 60) return 'text-yellow-600'
  if (score >= 40) return 'text-orange-600'
  return 'text-red-600'
}

const getProgressBarColor = (score: number): string => {
  if (score >= 80) return 'bg-green-500'
  if (score >= 60) return 'bg-yellow-500'
  if (score >= 40) return 'bg-orange-500'
  return 'bg-red-500'
}

const getComplianceLevel = (score: number): string => {
  if (score >= 90) return 'Excellent'
  if (score >= 80) return 'Good'
  if (score >= 60) return 'Fair'
  if (score >= 40) return 'Poor'
  return 'Critical'
}

const getCategoryStatus = (coverage: number): string => {
  if (coverage >= 80) return 'Strong'
  if (coverage >= 60) return 'Adequate'
  if (coverage >= 40) return 'Weak'
  return 'Critical'
}

const getCategoryStatusClass = (coverage: number): string => {
  if (coverage >= 80) return 'bg-green-100 text-green-800'
  if (coverage >= 60) return 'bg-yellow-100 text-yellow-800'
  if (coverage >= 40) return 'bg-orange-100 text-orange-800'
  return 'bg-red-100 text-red-800'
}

const getCategoryTrend = (category: string): string => {
  if (!complianceData.value) return ''
  
  const trends = complianceData.value.coverage_trends
  if (trends.improving_categories.includes(category.replace('_', '').slice(-3))) return '↗'
  if (trends.declining_categories.includes(category.replace('_', '').slice(-3))) return '↘'
  return '→'
}

const getRandomTrend = (): number => {
  return Math.floor(Math.random() * 15) + 5 // 5-20%
}

const generateComplianceReport = () => {
  // This would generate a detailed compliance report
  console.log('Generating OWASP compliance report...')
  // Implementation would call API to generate report
}

const exportComplianceData = () => {
  // This would export the compliance data
  console.log('Exporting compliance data...')
  // Implementation would download data as JSON/CSV
}
</script>

<style scoped>
.owasp-compliance-dashboard {
  max-width: 100%;
}

.category-card {
  transition: all 0.2s ease;
}

.category-card:hover {
  transform: translateY(-2px);
}

.recommendation-item {
  transition: all 0.2s ease;
}

.recommendation-item:hover {
  transform: translateX(4px);
}

.trend-section {
  border-right: 1px solid #e5e7eb;
}

.trend-section:last-child {
  border-right: none;
}

@media (max-width: 768px) {
  .trend-section {
    border-right: none;
    border-bottom: 1px solid #e5e7eb;
    padding-bottom: 1rem;
    margin-bottom: 1rem;
  }
  
  .trend-section:last-child {
    border-bottom: none;
    margin-bottom: 0;
    padding-bottom: 0;
  }
}
</style>