<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <!-- Loading State -->
    <div v-if="loading" class="min-h-screen flex items-center justify-center">
      <LoadingSpinner size="large" message="Loading repository..." />
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="min-h-screen flex items-center justify-center p-4">
      <div class="max-w-md w-full">
        <ErrorDisplay
          :error="error"
          title="Error Loading Repository"
          :on-retry="loadRepositoryData"
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
            Repository Analysis
          </h1>
          <AnalysisStatus
            :repo-id="repoId"
            @status-change="handleAnalysisStatusChange"
            @complete="handleAnalysisComplete"
            @error="handleAnalysisError"
          />
        </div>
        
        <div class="flex-1 overflow-y-auto">
          <!-- Navigation placeholder - will implement RepoNav later -->
          <div class="p-4">
            <div class="text-sm text-gray-600 dark:text-gray-400">
              Document navigation will be implemented here
            </div>
          </div>
        </div>
      </div>

      <!-- Main Content Area -->
      <div class="flex-1 flex flex-col">
        <!-- Top Bar with Search -->
        <div class="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-4">
          <div class="flex items-center space-x-4">
            <div class="flex-1">
              <SearchBox
                :repo-id="repoId"
                :on-document-select="handleDocumentSelect"
              />
            </div>
          </div>
        </div>

        <!-- Document Content -->
        <div class="flex-1 overflow-y-auto">
          <div v-if="analysisStatus?.status === 'analyzing' || analysisStatus?.status === 'queued'" class="flex items-center justify-center h-full">
            <div class="text-center max-w-md">
              <AnalysisStatus
                :repo-id="repoId"
                @status-change="handleAnalysisStatusChange"
                @complete="handleAnalysisComplete"
                @error="handleAnalysisError"
                class="text-left"
              />
              <div class="mt-6">
                <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
                  Analyzing Repository
                </h3>
                <p class="text-gray-600 dark:text-gray-400">
                  This may take a few minutes depending on repository size and complexity.
                </p>
              </div>
            </div>
          </div>
          
          <div v-else-if="selectedDoc" class="p-6">
            <!-- Document viewer placeholder -->
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
              <h2 class="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
                {{ selectedDoc.title }}
              </h2>
              <div class="prose prose-gray dark:prose-invert max-w-none">
                <pre class="whitespace-pre-wrap">{{ selectedDoc.content }}</pre>
              </div>
            </div>
          </div>
          
          <div v-else class="flex items-center justify-center h-full">
            <div class="text-center">
              <div class="text-gray-400 dark:text-gray-600 mb-4">
                <FileText class="w-16 h-16 mx-auto" />
              </div>
              <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
                No Document Selected
              </h3>
              <p class="text-gray-600 dark:text-gray-400">
                Select a document from the navigation to view its content
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { FileText } from 'lucide-vue-next'
import { api } from '@/lib/api'
import type { AnalysisProgress, ThreatDoc } from '@/lib/types'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import ErrorDisplay from '@/components/ErrorDisplay.vue'
import AnalysisStatus from '@/components/AnalysisStatus.vue'
import SearchBox from '@/components/SearchBox.vue'

const route = useRoute()
const repoId = route.params.repoId as string

const analysisStatus = ref<AnalysisProgress | null>(null)
const documents = ref<ThreatDoc[]>([])
const selectedDoc = ref<ThreatDoc | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)
const documentCache = new Map<string, ThreatDoc>()

const loadRepositoryData = async () => {
  try {
    loading.value = true
    error.value = null

    // Load analysis status
    const status = await api.getAnalysisStatus(repoId)
    analysisStatus.value = status

    // Load documents if analysis is complete
    if (status.status === 'completed') {
      await loadDocuments()
    }
  } catch (err) {
    console.error('Error loading repository data:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load repository data'
  } finally {
    loading.value = false
  }
}

const handleAnalysisStatusChange = (status: AnalysisProgress) => {
  analysisStatus.value = status
}

const handleAnalysisComplete = async (status: AnalysisProgress) => {
  analysisStatus.value = status
  // Reload documents when analysis completes
  await loadDocuments()
}

const handleAnalysisError = (errorMessage: string) => {
  error.value = errorMessage
}

const loadDocuments = async () => {
  try {
    const response = await api.getRepositoryDocuments(repoId)
    documents.value = response.documents
    
    // Cache all loaded documents
    response.documents.forEach(doc => {
      documentCache.set(doc.id, doc)
    })
    
    // Select first document by default
    if (response.documents.length > 0 && !selectedDoc.value) {
      selectedDoc.value = response.documents[0]
    }
  } catch (err) {
    console.error('Error loading documents:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load documents'
  }
}

const handleDocumentSelect = async (docId: string) => {
  try {
    error.value = null
    
    // Check cache first
    const cachedDoc = documentCache.get(docId)
    if (cachedDoc) {
      selectedDoc.value = cachedDoc
      return
    }

    // Check if document is already in the documents array
    const existingDoc = documents.value.find(d => d.id === docId)
    if (existingDoc) {
      selectedDoc.value = existingDoc
      documentCache.set(docId, existingDoc)
      return
    }

    // Load document from API
    const loadedDoc = await api.getDocument(repoId, docId)
    documentCache.set(docId, loadedDoc)
    selectedDoc.value = loadedDoc
  } catch (err) {
    console.error('Error loading document:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load document'
  }
}

onMounted(() => {
  loadRepositoryData()
})
</script>