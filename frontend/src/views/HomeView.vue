<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <div class="container mx-auto px-4 py-12">
      <!-- Header -->
      <div class="text-center mb-12">
        <h1 class="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          ThreatLens
        </h1>
        <p class="text-xl text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
          GPU-powered security documentation generator. 
          Analyze repositories or pull requests to generate comprehensive security analysis and documentation.
        </p>
      </div>

      <!-- Main Content -->
      <div class="space-y-12">
        <!-- Analysis Mode Selection -->
        <section>
          <div class="text-center mb-8">
            <h2 class="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-6">
              Choose Analysis Mode
            </h2>
          </div>
          
          <AnalysisModeToggle v-model="analysisMode" />
          
          <!-- Repository Analysis Form -->
          <div v-if="analysisMode === 'repository'">
            <RepoForm @analysis-started="handleRepoAnalysisStarted" />
          </div>
          
          <!-- PR Analysis Form -->
          <div v-else>
            <PRForm @analysis-started="handlePRAnalysisStarted" />
          </div>
        </section>

        <!-- Features Overview -->
        <section class="mt-16">
          <div class="text-center mb-8">
            <h2 class="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
              What ThreatLens Does
            </h2>
          </div>
          <div class="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div class="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <div class="w-12 h-12 bg-blue-100 dark:bg-blue-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <CheckCircle class="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Code Analysis
              </h3>
              <p class="text-gray-600 dark:text-gray-400 text-sm">
                Automatically analyzes your codebase to identify components, data flows, and security patterns
              </p>
            </div>
            
            <div class="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <div class="w-12 h-12 bg-red-100 dark:bg-red-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <AlertTriangle class="w-6 h-6 text-red-600 dark:text-red-400" />
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Security Assessment
              </h3>
              <p class="text-gray-600 dark:text-gray-400 text-sm">
                Identifies potential security threats, vulnerabilities, and provides comprehensive security analysis
              </p>
            </div>
            
            <div class="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <div class="w-12 h-12 bg-green-100 dark:bg-green-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                <FileText class="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
              <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Documentation
              </h3>
              <p class="text-gray-600 dark:text-gray-400 text-sm">
                Generates comprehensive security documentation with recommendations and mitigation strategies
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { CheckCircle, AlertTriangle, FileText } from 'lucide-vue-next'
import RepoForm from '@/components/RepoForm.vue'
import PRForm from '@/components/PRForm.vue'
import AnalysisModeToggle from '@/components/AnalysisModeToggle.vue'
import type { AnalyzeRepoResponse, AnalyzePRResponse } from '@/lib/types'

const router = useRouter()
const analysisMode = ref<'repository' | 'pr'>('repository')

const handleRepoAnalysisStarted = (response: AnalyzeRepoResponse, repoUrl: string) => {
  // Navigate to the repository page after a short delay to show the status
  setTimeout(() => {
    router.push(`/${response.repo_id}`)
  }, 2000)
}

const handlePRAnalysisStarted = (response: AnalyzePRResponse, prUrl: string) => {
  // Navigate to the PR analysis page after a short delay to show the status
  setTimeout(() => {
    router.push(`/pr/${response.pr_id}`)
  }, 2000)
}
</script>
