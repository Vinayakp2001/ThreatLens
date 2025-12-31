<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <div class="container mx-auto px-4 py-12">
      <!-- Header -->
      <div class="text-center mb-12">
        <h1 class="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-4">
          ThreatLens
        </h1>
        <p class="text-xl text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
          GPU-powered threat modeling documentation generator. 
          Analyze your code repositories to identify security threats and generate comprehensive threat models.
        </p>
      </div>

      <!-- Main Content -->
      <div class="space-y-12">
        <!-- Repository Analysis Form -->
        <section>
          <div class="text-center mb-8">
            <h2 class="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
              Analyze Repository
            </h2>
            <p class="text-gray-600 dark:text-gray-400">
              Enter a Git repository URL to start threat modeling analysis
            </p>
          </div>
          <RepoForm @analysis-started="handleAnalysisStarted" />
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
                Threat Identification
              </h3>
              <p class="text-gray-600 dark:text-gray-400 text-sm">
                Uses STRIDE methodology to identify potential security threats and vulnerabilities
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
                Generates comprehensive threat modeling documentation with mitigation strategies
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import { CheckCircle, AlertTriangle, FileText } from 'lucide-vue-next'
import RepoForm from '@/components/RepoForm.vue'
import type { AnalyzeRepoResponse } from '@/lib/types'

const router = useRouter()

const handleAnalysisStarted = (response: AnalyzeRepoResponse, repoUrl: string) => {
  // Navigate to the repository page after a short delay to show the status
  setTimeout(() => {
    router.push(`/${response.repo_id}`)
  }, 2000)
}
</script>
