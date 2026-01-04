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
          <!-- Document Navigation -->
          <nav class="p-4 space-y-2">
            <div v-if="documents.length > 0">
              <h3 class="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">
                Security Documentation
              </h3>
              <div class="space-y-1">
                <button
                  v-for="doc in documents"
                  :key="doc.id"
                  @click="handleDocumentSelect(doc.id)"
                  :class="cn(
                    'w-full text-left px-3 py-2 rounded-lg text-sm transition-colors',
                    selectedDoc?.id === doc.id
                      ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700'
                  )"
                >
                  <div class="flex items-center space-x-2">
                    <FileText class="w-4 h-4 flex-shrink-0" />
                    <span class="truncate">{{ doc.title }}</span>
                  </div>
                  <div v-if="doc.metadata?.section" class="text-xs text-gray-500 dark:text-gray-400 mt-1 ml-6">
                    {{ doc.metadata.section }}
                  </div>
                </button>
              </div>
            </div>
            
            <div v-else-if="analysisStatus?.status === 'completed'" class="text-center py-8">
              <FileText class="w-8 h-8 text-gray-400 mx-auto mb-2" />
              <p class="text-sm text-gray-500 dark:text-gray-400">
                No security documents found
              </p>
            </div>
          </nav>
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
            <!-- Enhanced Document Viewer -->
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <!-- Document Header -->
              <div class="p-6 border-b border-gray-200 dark:border-gray-700">
                <div class="flex items-start justify-between">
                  <div>
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
                      {{ selectedDoc.title }}
                    </h2>
                    <div class="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                      <span v-if="selectedDoc.metadata?.section">
                        Section: {{ selectedDoc.metadata.section }}
                      </span>
                      <span v-if="selectedDoc.created_at">
                        Created: {{ formatDate(selectedDoc.created_at) }}
                      </span>
                      <span v-if="selectedDoc.metadata?.risk_level">
                        Risk Level: 
                        <span :class="getRiskLevelClass(selectedDoc.metadata.risk_level)" class="px-2 py-1 rounded text-xs font-medium ml-1">
                          {{ selectedDoc.metadata.risk_level.toUpperCase() }}
                        </span>
                      </span>
                    </div>
                  </div>
                  
                  <!-- Document Actions -->
                  <div class="flex items-center space-x-2">
                    <button
                      @click="copyToClipboard(selectedDoc.content)"
                      class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                      title="Copy content"
                    >
                      <Copy class="w-4 h-4" />
                    </button>
                    <button
                      @click="exportDocument(selectedDoc)"
                      class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                      title="Export document"
                    >
                      <Download class="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
              
              <!-- Document Content -->
              <div class="p-6">
                <div class="prose prose-gray dark:prose-invert max-w-none">
                  <!-- Render markdown content -->
                  <div v-html="renderMarkdown(selectedDoc.content)" class="security-content"></div>
                </div>
                
                <!-- Code References -->
                <div v-if="selectedDoc.code_references?.length" class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                    Code References
                  </h3>
                  <div class="space-y-3">
                    <div
                      v-for="(ref, index) in selectedDoc.code_references"
                      :key="index"
                      class="bg-gray-50 dark:bg-gray-700 rounded-lg p-4"
                    >
                      <div class="flex items-center space-x-2 mb-2">
                        <FileText class="w-4 h-4 text-gray-500" />
                        <span class="font-mono text-sm text-gray-900 dark:text-gray-100">
                          {{ ref.file_path }}
                        </span>
                        <span v-if="ref.line_number" class="text-xs text-gray-500 dark:text-gray-400">
                          Line {{ ref.line_number }}
                        </span>
                      </div>
                      <pre v-if="ref.code_snippet" class="text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded overflow-x-auto"><code>{{ ref.code_snippet }}</code></pre>
                    </div>
                  </div>
                </div>
                
                <!-- Metadata -->
                <div v-if="selectedDoc.metadata && Object.keys(selectedDoc.metadata).length > 0" class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                    Additional Information
                  </h3>
                  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div
                      v-for="[key, value] in Object.entries(selectedDoc.metadata)"
                      :key="key"
                      v-if="!['section', 'risk_level'].includes(key)"
                      class="bg-gray-50 dark:bg-gray-700 rounded-lg p-3"
                    >
                      <dt class="text-sm font-medium text-gray-500 dark:text-gray-400 capitalize">
                        {{ key.replace(/_/g, ' ') }}
                      </dt>
                      <dd class="text-sm text-gray-900 dark:text-gray-100 mt-1">
                        {{ formatMetadataValue(value) }}
                      </dd>
                    </div>
                  </div>
                </div>
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
import { FileText, Copy, Download } from 'lucide-vue-next'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { AnalysisProgress, ThreatDoc } from '@/lib/types'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import ErrorDisplay from '@/components/ErrorDisplay.vue'
import AnalysisStatus from '@/components/AnalysisStatus.vue'
import SearchBox from '@/components/SearchBox.vue'
import { useToast } from '@/composables/useToast'

const route = useRoute()
const repoId = route.params.repoId as string
const { showSuccess, showError } = useToast()

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

// Utility functions
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

const renderMarkdown = (content: string) => {
  // Simple markdown rendering - in a real app, you'd use a proper markdown parser
  return content
    .replace(/^### (.*$)/gim, '<h3 class="text-lg font-semibold mt-6 mb-3">$1</h3>')
    .replace(/^## (.*$)/gim, '<h2 class="text-xl font-semibold mt-8 mb-4">$1</h2>')
    .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold mt-8 mb-4">$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code class="bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-sm">$1</code>')
    .replace(/\n\n/g, '</p><p class="mb-4">')
    .replace(/^(.*)$/gm, '<p class="mb-4">$1</p>')
    .replace(/^<p class="mb-4"><\/p>$/gm, '')
}

const formatMetadataValue = (value: any) => {
  if (Array.isArray(value)) {
    return value.join(', ')
  }
  if (typeof value === 'object' && value !== null) {
    return JSON.stringify(value, null, 2)
  }
  return String(value)
}

const copyToClipboard = async (content: string) => {
  try {
    await navigator.clipboard.writeText(content)
    showSuccess('Copied to clipboard', 'Document content has been copied to your clipboard')
  } catch (err) {
    showError('Copy failed', 'Failed to copy content to clipboard')
  }
}

const exportDocument = (doc: ThreatDoc) => {
  const blob = new Blob([doc.content], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${doc.title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.md`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
  showSuccess('Document exported', `${doc.title} has been downloaded`)
}

onMounted(() => {
  loadRepositoryData()
})
</script>

<style scoped>
.security-content {
  @apply text-gray-900 dark:text-gray-100;
}

.security-content h1,
.security-content h2,
.security-content h3,
.security-content h4,
.security-content h5,
.security-content h6 {
  @apply text-gray-900 dark:text-gray-100 font-semibold;
}

.security-content p {
  @apply mb-4 leading-relaxed;
}

.security-content ul,
.security-content ol {
  @apply mb-4 pl-6;
}

.security-content li {
  @apply mb-2;
}

.security-content code {
  @apply bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-sm font-mono;
}

.security-content pre {
  @apply bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto mb-4;
}

.security-content pre code {
  @apply bg-transparent p-0;
}

.security-content blockquote {
  @apply border-l-4 border-blue-500 pl-4 italic text-gray-700 dark:text-gray-300 mb-4;
}

.security-content table {
  @apply w-full border-collapse border border-gray-300 dark:border-gray-600 mb-4;
}

.security-content th,
.security-content td {
  @apply border border-gray-300 dark:border-gray-600 px-4 py-2 text-left;
}

.security-content th {
  @apply bg-gray-100 dark:bg-gray-700 font-semibold;
}
</style>