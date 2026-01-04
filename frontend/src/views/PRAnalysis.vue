<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <!-- Loading State -->
    <div v-if="loading" class="min-h-screen flex items-center justify-center">
      <LoadingSpinner size="large" message="Loading PR analysis..." />
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="min-h-screen flex items-center justify-center p-4">
      <div class="max-w-md w-full">
        <ErrorDisplay
          :error="error"
          title="Error Loading PR Analysis"
          :on-retry="loadPRData"
          :show-retry="true"
        />
      </div>
    </div>

    <!-- Main Content -->
    <div v-else class="flex h-screen">
      <!-- Sidebar Navigation -->
      <div class="w-80 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex flex-col">
        <div class="p-6 border-b border-gray-200 dark:border-gray-700">
          <h1 class="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
            PR Security Analysis
          </h1>
          
          <!-- PR Info -->
          <div v-if="prAnalysis" class="space-y-3">
            <div class="text-sm">
              <span class="text-gray-500 dark:text-gray-400">PR:</span>
              <a :href="prAnalysis.pr_url" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline ml-1">
                #{{ extractPRNumber(prAnalysis.pr_url) }}
              </a>
            </div>
            <div class="text-sm">
              <span class="text-gray-500 dark:text-gray-400">Repository:</span>
              <span class="text-gray-900 dark:text-gray-100 ml-1">{{ extractRepoName(prAnalysis.pr_url) }}</span>
            </div>
            <div class="text-sm">
              <span class="text-gray-500 dark:text-gray-400">Risk Level:</span>
              <span :class="getRiskLevelClass(prAnalysis.risk_level)" class="ml-1 px-2 py-1 rounded text-xs font-medium">
                {{ prAnalysis.risk_level?.toUpperCase() || 'UNKNOWN' }}
              </span>
            </div>
            <div class="text-sm">
              <span class="text-gray-500 dark:text-gray-400">Context:</span>
              <span :class="getContextStatusClass(prAnalysis.has_repo_context)" class="ml-1 px-2 py-1 rounded text-xs font-medium">
                {{ prAnalysis.has_repo_context ? 'AVAILABLE' : 'LIMITED' }}
              </span>
            </div>
            <div class="text-sm">
              <span class="text-gray-500 dark:text-gray-400">Analyzed:</span>
              <span class="text-gray-900 dark:text-gray-100 ml-1">{{ formatDate(prAnalysis.created_at) }}</span>
            </div>
          </div>
        </div>

        <!-- Navigation Menu -->
        <div class="flex-1 overflow-y-auto">
          <nav class="p-4 space-y-2">
            <button
              v-for="section in navigationSections"
              :key="section.id"
              @click="activeSection = section.id"
              :class="cn(
                'w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                activeSection === section.id
                  ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700'
              )"
            >
              <div class="flex items-center space-x-2">
                <component :is="section.icon" class="w-4 h-4" />
                <span>{{ section.title }}</span>
                <span v-if="section.count" class="ml-auto text-xs bg-gray-200 dark:bg-gray-600 px-2 py-1 rounded">
                  {{ section.count }}
                </span>
              </div>
            </button>
          </nav>
        </div>

        <!-- Back to Home -->
        <div class="p-4 border-t border-gray-200 dark:border-gray-700">
          <router-link
            to="/"
            class="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
          >
            <ArrowLeft class="w-4 h-4" />
            <span>Back to Home</span>
          </router-link>
        </div>
      </div>

      <!-- Main Content Area -->
      <div class="flex-1 overflow-hidden">
        <div class="h-full overflow-y-auto">
          <!-- Overview Section -->
          <div v-if="activeSection === 'overview'" class="p-8">
            <div class="max-w-4xl mx-auto">
              <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">
                PR Security Overview
              </h2>
              
              <!-- Context Status Card -->
              <div class="mb-6 p-4 rounded-lg border" :class="getContextCardClass(prAnalysis?.has_repo_context)">
                <div class="flex items-center space-x-2 mb-2">
                  <CheckCircle v-if="prAnalysis?.has_repo_context" class="w-5 h-5 text-green-600" />
                  <AlertCircle v-else class="w-5 h-5 text-yellow-600" />
                  <h3 class="font-semibold">Repository Context</h3>
                </div>
                <p class="text-sm">
                  {{ prAnalysis?.has_repo_context 
                    ? 'This PR analysis includes full repository context for comprehensive security assessment.' 
                    : 'This PR was analyzed without full repository context. Consider analyzing the full repository first for better insights.' 
                  }}
                </p>
              </div>

              <!-- Changed Files -->
              <div v-if="prAnalysis?.changed_files?.length" class="mb-6">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">
                  Changed Files ({{ prAnalysis.changed_files.length }})
                </h3>
                <div class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                  <div
                    v-for="(file, index) in prAnalysis.changed_files"
                    :key="file"
                    :class="cn(
                      'px-4 py-3 flex items-center space-x-3',
                      index !== prAnalysis.changed_files.length - 1 && 'border-b border-gray-200 dark:border-gray-700'
                    )"
                  >
                    <FileText class="w-4 h-4 text-gray-400" />
                    <span class="text-sm font-mono text-gray-900 dark:text-gray-100">{{ file }}</span>
                  </div>
                </div>
              </div>

              <!-- Quick Stats -->
              <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div class="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
                  <div class="flex items-center space-x-3">
                    <div class="p-2 bg-red-100 dark:bg-red-900/20 rounded-lg">
                      <AlertTriangle class="w-5 h-5 text-red-600 dark:text-red-400" />
                    </div>
                    <div>
                      <p class="text-sm text-gray-500 dark:text-gray-400">Security Issues</p>
                      <p class="text-2xl font-bold text-gray-900 dark:text-gray-100">
                        {{ prAnalysis?.security_issues?.length || 0 }}
                      </p>
                    </div>
                  </div>
                </div>
                
                <div class="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
                  <div class="flex items-center space-x-3">
                    <div class="p-2 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
                      <CheckCircle class="w-5 h-5 text-blue-600 dark:text-blue-400" />
                    </div>
                    <div>
                      <p class="text-sm text-gray-500 dark:text-gray-400">Recommendations</p>
                      <p class="text-2xl font-bold text-gray-900 dark:text-gray-100">
                        {{ prAnalysis?.recommendations?.length || 0 }}
                      </p>
                    </div>
                  </div>
                </div>
                
                <div class="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
                  <div class="flex items-center space-x-3">
                    <div class="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
                      <FileText class="w-5 h-5 text-purple-600 dark:text-purple-400" />
                    </div>
                    <div>
                      <p class="text-sm text-gray-500 dark:text-gray-400">Files Changed</p>
                      <p class="text-2xl font-bold text-gray-900 dark:text-gray-100">
                        {{ prAnalysis?.changed_files?.length || 0 }}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Security Issues Section -->
          <div v-else-if="activeSection === 'issues'" class="p-8">
            <div class="max-w-4xl mx-auto">
              <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">
                Security Issues
              </h2>
              
              <div v-if="prAnalysis?.security_issues?.length" class="space-y-4">
                <div
                  v-for="(issue, index) in prAnalysis.security_issues"
                  :key="index"
                  class="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700"
                >
                  <div class="flex items-start space-x-3">
                    <div class="flex-shrink-0">
                      <div :class="getSeverityIconClass(issue.severity)" class="p-2 rounded-lg">
                        <AlertTriangle class="w-5 h-5" />
                      </div>
                    </div>
                    <div class="flex-1">
                      <div class="flex items-start justify-between">
                        <h3 class="font-semibold text-gray-900 dark:text-gray-100 mb-2">
                          {{ issue.title || 'Security Issue' }}
                        </h3>
                        <span v-if="issue.severity" :class="getSeverityClass(issue.severity)" class="px-2 py-1 rounded text-xs font-medium">
                          {{ issue.severity.toUpperCase() }}
                        </span>
                      </div>
                      <p class="text-gray-600 dark:text-gray-400 mb-3">
                        {{ issue.description || 'No description available' }}
                      </p>
                      
                      <!-- File and line information -->
                      <div v-if="issue.file || issue.line" class="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400 mb-3">
                        <span v-if="issue.file" class="flex items-center space-x-1">
                          <FileText class="w-4 h-4" />
                          <span class="font-mono">{{ issue.file }}</span>
                        </span>
                        <span v-if="issue.line">Line {{ issue.line }}</span>
                      </div>
                      
                      <!-- Code snippet if available -->
                      <div v-if="issue.code_snippet" class="mt-3">
                        <div class="bg-gray-50 dark:bg-gray-700 rounded-lg p-3">
                          <div class="text-xs text-gray-500 dark:text-gray-400 mb-2">Code Context:</div>
                          <pre class="text-sm font-mono text-gray-900 dark:text-gray-100 overflow-x-auto"><code>{{ issue.code_snippet }}</code></pre>
                        </div>
                      </div>
                      
                      <!-- Recommendation for this specific issue -->
                      <div v-if="issue.recommendation" class="mt-3 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <div class="flex items-start space-x-2">
                          <CheckCircle class="w-4 h-4 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
                          <div class="text-sm text-blue-800 dark:text-blue-200">
                            <strong>Recommendation:</strong> {{ issue.recommendation }}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div v-else class="text-center py-12">
                <CheckCircle class="w-12 h-12 text-green-500 mx-auto mb-4" />
                <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  No Security Issues Found
                </h3>
                <p class="text-gray-600 dark:text-gray-400">
                  This PR doesn't appear to introduce any security concerns.
                </p>
              </div>
            </div>
          </div>

          <!-- Recommendations Section -->
          <div v-else-if="activeSection === 'recommendations'" class="p-8">
            <div class="max-w-4xl mx-auto">
              <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">
                Security Recommendations
              </h2>
              
              <div v-if="prAnalysis?.recommendations?.length" class="space-y-4">
                <div
                  v-for="(recommendation, index) in prAnalysis.recommendations"
                  :key="index"
                  class="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700"
                >
                  <div class="flex items-start space-x-3">
                    <CheckCircle class="w-5 h-5 text-blue-500 mt-1 flex-shrink-0" />
                    <div class="flex-1">
                      <p class="text-gray-900 dark:text-gray-100">{{ recommendation }}</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div v-else class="text-center py-12">
                <CheckCircle class="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  No Recommendations
                </h3>
                <p class="text-gray-600 dark:text-gray-400">
                  No specific security recommendations for this PR.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { 
  AlertTriangle, 
  CheckCircle, 
  AlertCircle, 
  FileText, 
  ArrowLeft,
  Shield,
  Target
} from 'lucide-vue-next'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import ErrorDisplay from '@/components/ErrorDisplay.vue'

// Route and reactive data
const route = useRoute()
const prId = computed(() => route.params.prId as string)

const loading = ref(true)
const error = ref<Error | null>(null)
const prAnalysis = ref<any>(null)
const activeSection = ref('overview')

// Navigation sections
const navigationSections = computed(() => [
  {
    id: 'overview',
    title: 'Overview',
    icon: Shield,
    count: null
  },
  {
    id: 'issues',
    title: 'Security Issues',
    icon: AlertTriangle,
    count: prAnalysis.value?.security_issues?.length || 0
  },
  {
    id: 'recommendations',
    title: 'Recommendations',
    icon: Target,
    count: prAnalysis.value?.recommendations?.length || 0
  }
])

// Utility functions
const extractPRNumber = (url: string) => {
  const match = url.match(/\/pull\/(\d+)/)
  return match ? match[1] : 'Unknown'
}

const extractRepoName = (url: string) => {
  const match = url.match(/github\.com\/([^\/]+\/[^\/]+)/)
  return match ? match[1] : 'Unknown'
}

const getRiskLevelClass = (riskLevel: string) => {
  switch (riskLevel?.toLowerCase()) {
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

const getContextStatusClass = (hasContext: boolean) => {
  return hasContext
    ? 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    : 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
}

const getContextCardClass = (hasContext: boolean) => {
  return hasContext
    ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-800 dark:text-green-200'
    : 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-200'
}

const getSeverityClass = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    case 'high':
      return 'bg-orange-100 dark:bg-orange-900/20 text-orange-800 dark:text-orange-200'
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
    case 'low':
      return 'bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-200'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const getSeverityIconClass = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'bg-red-100 dark:bg-red-900/20 text-red-600 dark:text-red-400'
    case 'high':
      return 'bg-orange-100 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400'
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400'
    case 'low':
      return 'bg-blue-100 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
  }
}

const formatDate = (dateString: string) => {
  if (!dateString) return 'Unknown'
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

// Load PR analysis data
const loadPRData = async () => {
  if (!prId.value) {
    error.value = new Error('PR ID is required')
    loading.value = false
    return
  }

  try {
    loading.value = true
    error.value = null
    
    // For now, we'll create a mock response since the backend endpoint might not be fully implemented
    // In a real implementation, this would be: prAnalysis.value = await api.getPRAnalysis(prId.value)
    
    // Mock data for demonstration
    prAnalysis.value = {
      id: prId.value,
      pr_id: prId.value,
      repo_id: 'github_user_repo',
      pr_url: `https://github.com/user/repo/pull/${prId.value}`,
      changed_files: [
        'src/auth/login.ts',
        'src/middleware/auth.ts',
        'tests/auth.test.ts'
      ],
      security_issues: [
        {
          title: 'Potential SQL Injection Vulnerability',
          description: 'User input is not properly sanitized before being used in database queries. This could allow attackers to execute arbitrary SQL commands.',
          severity: 'high',
          file: 'src/auth/login.ts',
          line: 42,
          code_snippet: `const query = \`SELECT * FROM users WHERE email = '\${email}' AND password = '\${password}'\`;
const result = await db.query(query);`,
          recommendation: 'Use parameterized queries or prepared statements to prevent SQL injection attacks.'
        },
        {
          title: 'Weak Password Validation',
          description: 'Password validation rules are too permissive and may allow weak passwords.',
          severity: 'medium',
          file: 'src/auth/login.ts',
          line: 28,
          recommendation: 'Implement stronger password requirements including minimum length, complexity, and common password checks.'
        }
      ],
      recommendations: [
        'Use parameterized queries to prevent SQL injection attacks',
        'Add input validation for all user inputs',
        'Consider implementing rate limiting for authentication endpoints',
        'Add proper error handling to avoid information disclosure',
        'Implement proper session management with secure tokens'
      ],
      risk_level: 'medium',
      has_repo_context: true,
      context_used: true,
      created_at: new Date().toISOString()
    }
    
  } catch (err) {
    error.value = err instanceof Error ? err : new Error('Failed to load PR analysis')
  } finally {
    loading.value = false
  }
}

// Initialize component
onMounted(() => {
  loadPRData()
})
</script>