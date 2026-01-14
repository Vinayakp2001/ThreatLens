<template>
  <div class="min-h-screen bg-gray-50 dark:bg-gray-900">
    <!-- Loading State -->
    <div v-if="loading" class="min-h-screen flex items-center justify-center">
      <LoadingSpinner size="large" message="Loading security wiki..." />
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="min-h-screen flex items-center justify-center p-4">
      <div class="max-w-md w-full">
        <ErrorDisplay
          :error="error"
          title="Error Loading Security Wiki"
          :on-retry="loadWikiData"
          :show-retry="true"
        />
      </div>
    </div>

    <!-- Main Content -->
    <div v-else class="flex h-screen">
      <!-- Wiki Navigation Sidebar -->
      <div class="w-80 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex flex-col">
        <div class="p-6 border-b border-gray-200 dark:border-gray-700">
          <h1 class="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
            Security Wiki
          </h1>
          <AnalysisStatus
            :repo-id="repoId"
            @status-change="handleAnalysisStatusChange"
            @complete="handleAnalysisComplete"
            @error="handleAnalysisError"
          />
        </div>
        
        <div class="flex-1 overflow-y-auto">
          <!-- Wiki Section Navigation -->
          <nav class="p-4 space-y-2">
            <div v-if="wiki && Object.keys(wiki.sections).length > 0">
              <h3 class="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">
                Wiki Sections
              </h3>
              <div class="space-y-1">
                <button
                  v-for="(section, sectionId) in wiki.sections"
                  :key="sectionId"
                  @click="handleSectionSelect(sectionId)"
                  :class="cn(
                    'w-full text-left px-3 py-2 rounded-lg text-sm transition-colors',
                    selectedSectionId === sectionId
                      ? 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700'
                  )"
                >
                  <div class="flex items-center space-x-2">
                    <component :is="getSectionIcon(sectionId)" class="w-4 h-4 flex-shrink-0" />
                    <span class="truncate">{{ section.title }}</span>
                  </div>
                  <div v-if="section.security_findings?.length" class="text-xs text-red-500 dark:text-red-400 mt-1 ml-6">
                    {{ section.security_findings.length }} finding(s)
                  </div>
                </button>
              </div>

              <!-- Cross-References -->
              <div v-if="selectedSection?.cross_references?.length" class="mt-6">
                <h4 class="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">
                  Related Sections
                </h4>
                <div class="space-y-1">
                  <button
                    v-for="refId in selectedSection.cross_references"
                    :key="refId"
                    @click="handleSectionSelect(refId)"
                    class="w-full text-left px-2 py-1 rounded text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    <ArrowRight class="w-3 h-3 inline mr-1" />
                    {{ wiki?.sections[refId]?.title || refId }}
                  </button>
                </div>
              </div>
            </div>
            
            <div v-else-if="analysisStatus?.status === 'completed'" class="text-center py-8">
              <BookOpen class="w-8 h-8 text-gray-400 mx-auto mb-2" />
              <p class="text-sm text-gray-500 dark:text-gray-400">
                No wiki sections found
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
                :on-section-select="handleSectionSelect"
                search-type="wiki"
              />
            </div>
          </div>
        </div>

        <!-- Wiki Section Content -->
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
                  Generating Security Wiki
                </h3>
                <p class="text-gray-600 dark:text-gray-400">
                  This may take a few minutes depending on repository size and complexity.
                </p>
              </div>
            </div>
          </div>
          
          <div v-else-if="selectedSection" class="p-6">
            <!-- Wiki Section Viewer -->
            <div class="bg-white dark:bg-gray-800 rounded-lg shadow-sm">
              <!-- Section Header -->
              <div class="p-6 border-b border-gray-200 dark:border-gray-700">
                <div class="flex items-start justify-between">
                  <div>
                    <h2 class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
                      {{ selectedSection.title }}
                    </h2>
                    <div class="flex items-center space-x-4 text-sm text-gray-500 dark:text-gray-400">
                      <span v-if="selectedSection.security_findings?.length">
                        {{ selectedSection.security_findings.length }} Security Finding(s)
                      </span>
                      <span v-if="selectedSection.owasp_mappings?.length">
                        {{ selectedSection.owasp_mappings.length }} OWASP Reference(s)
                      </span>
                      <span v-if="selectedSection.code_references?.length">
                        {{ selectedSection.code_references.length }} Code Reference(s)
                      </span>
                    </div>
                  </div>
                  
                  <!-- Section Actions -->
                  <div class="flex items-center space-x-2">
                    <button
                      @click="copyToClipboard(selectedSection.content)"
                      class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                      title="Copy content"
                    >
                      <Copy class="w-4 h-4" />
                    </button>
                    <button
                      @click="exportSection(selectedSection)"
                      class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                      title="Export section"
                    >
                      <Download class="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
              
              <!-- Section Content -->
              <div class="p-6">
                <div class="prose prose-gray dark:prose-invert max-w-none">
                  <!-- Render markdown content with cross-reference links -->
                  <div v-html="renderWikiContent(selectedSection.content)" class="wiki-content"></div>
                </div>
                
                <!-- Security Findings -->
                <div v-if="selectedSection.security_findings?.length" class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
                    <AlertTriangle class="w-5 h-5 mr-2 text-red-500" />
                    Security Findings
                  </h3>
                  <div class="space-y-3">
                    <div
                      v-for="finding in selectedSection.security_findings"
                      :key="finding.id"
                      class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4"
                    >
                      <div class="flex items-start justify-between mb-2">
                        <h4 class="font-medium text-red-900 dark:text-red-100">
                          {{ finding.type }}
                        </h4>
                        <span
                          :class="getSeverityClass(finding.severity)"
                          class="px-2 py-1 rounded-full text-xs font-medium"
                        >
                          {{ finding.severity.toUpperCase() }}
                        </span>
                      </div>
                      <p class="text-sm text-red-800 dark:text-red-200 mb-2">
                        {{ finding.description }}
                      </p>
                      <div v-if="finding.recommendations?.length" class="text-xs text-red-700 dark:text-red-300">
                        <strong>Recommendations:</strong>
                        <ul class="list-disc list-inside mt-1">
                          <li v-for="rec in finding.recommendations" :key="rec">{{ rec }}</li>
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- OWASP Mappings -->
                <div v-if="selectedSection.owasp_mappings?.length" class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
                    <Shield class="w-5 h-5 mr-2 text-green-500" />
                    OWASP References
                  </h3>
                  <div class="flex flex-wrap gap-2">
                    <a
                      v-for="mapping in selectedSection.owasp_mappings"
                      :key="mapping"
                      :href="getOwaspUrl(mapping)"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200 hover:bg-green-200 dark:hover:bg-green-900/40 transition-colors"
                    >
                      <ExternalLink class="w-3 h-3 mr-1" />
                      {{ mapping }}
                    </a>
                  </div>
                </div>
                
                <!-- Code References -->
                <div v-if="selectedSection.code_references?.length" class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4 flex items-center">
                    <Code class="w-5 h-5 mr-2" />
                    Code References
                  </h3>
                  <div class="space-y-3">
                    <div
                      v-for="(ref, index) in selectedSection.code_references"
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

                <!-- Subsections -->
                <div v-if="selectedSection.subsections?.length" class="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                    Subsections
                  </h3>
                  <div class="space-y-4">
                    <div
                      v-for="subsection in selectedSection.subsections"
                      :key="subsection.id"
                      class="border border-gray-200 dark:border-gray-600 rounded-lg p-4"
                    >
                      <h4 class="font-medium text-gray-900 dark:text-gray-100 mb-2">
                        {{ subsection.title }}
                      </h4>
                      <div class="prose prose-sm prose-gray dark:prose-invert">
                        <div v-html="renderWikiContent(subsection.content)" class="wiki-content"></div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <div v-else class="flex items-center justify-center h-full">
            <div class="text-center">
              <div class="text-gray-400 dark:text-gray-600 mb-4">
                <BookOpen class="w-16 h-16 mx-auto" />
              </div>
              <h3 class="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
                No Section Selected
              </h3>
              <p class="text-gray-600 dark:text-gray-400">
                Select a wiki section from the navigation to view its content
              </p>
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
  BookOpen, 
  Copy, 
  Download, 
  ArrowRight, 
  AlertTriangle, 
  Shield, 
  ExternalLink, 
  Code, 
  FileText,
  Database,
  Users,
  Building2,
  Lock,
  Search,
  Settings,
  BarChart3
} from 'lucide-vue-next'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { AnalysisProgress, SecurityWiki, WikiSection } from '@/lib/types'
import LoadingSpinner from '@/components/LoadingSpinner.vue'
import ErrorDisplay from '@/components/ErrorDisplay.vue'
import AnalysisStatus from '@/components/AnalysisStatus.vue'
import SearchBox from '@/components/SearchBox.vue'
import { useToast } from '@/composables/useToast'

const route = useRoute()
const repoId = route.params.repoId as string
const { showSuccess, showError } = useToast()

const analysisStatus = ref<AnalysisProgress | null>(null)
const wiki = ref<SecurityWiki | null>(null)
const selectedSectionId = ref<string | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)
const sectionCache = new Map<string, WikiSection>()

const selectedSection = computed(() => {
  if (!selectedSectionId.value || !wiki.value) return null
  return wiki.value.sections[selectedSectionId.value] || null
})

const loadWikiData = async () => {
  try {
    loading.value = true
    error.value = null

    // Load analysis status
    const status = await api.getAnalysisStatus(repoId)
    analysisStatus.value = status

    // Load wiki if analysis is complete
    if (status.status === 'completed') {
      await loadWiki()
    }
  } catch (err) {
    console.error('Error loading wiki data:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load security wiki'
  } finally {
    loading.value = false
  }
}

const handleAnalysisStatusChange = (status: AnalysisProgress) => {
  analysisStatus.value = status
}

const handleAnalysisComplete = async (status: AnalysisProgress) => {
  analysisStatus.value = status
  // Reload wiki when analysis completes
  await loadWiki()
}

const handleAnalysisError = (errorMessage: string) => {
  error.value = errorMessage
}

const loadWiki = async () => {
  try {
    const wikiData = await api.getSecurityWiki(repoId)
    wiki.value = wikiData
    
    // Cache all sections (with null check)
    if (wikiData && wikiData.sections) {
      Object.entries(wikiData.sections).forEach(([sectionId, section]) => {
        sectionCache.set(sectionId, section)
      })
      
      // Select first section by default
      const sectionIds = Object.keys(wikiData.sections)
      if (sectionIds.length > 0 && !selectedSectionId.value) {
        selectedSectionId.value = sectionIds[0]
      }
    }
  } catch (err) {
    console.error('Error loading wiki:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load security wiki'
  }
}

const handleSectionSelect = async (sectionId: string) => {
  try {
    error.value = null
    
    // Check cache first
    const cachedSection = sectionCache.get(sectionId)
    if (cachedSection) {
      selectedSectionId.value = sectionId
      return
    }

    // Check if section is already in the wiki
    if (wiki.value?.sections[sectionId]) {
      selectedSectionId.value = sectionId
      sectionCache.set(sectionId, wiki.value.sections[sectionId])
      return
    }

    // Load section from API if needed
    const loadedSection = await api.getWikiSection(repoId, sectionId)
    sectionCache.set(sectionId, loadedSection)
    selectedSectionId.value = sectionId
    
    // Update wiki sections if needed
    if (wiki.value) {
      wiki.value.sections[sectionId] = loadedSection
    }
  } catch (err) {
    console.error('Error loading section:', err)
    error.value = err instanceof Error ? err.message : 'Failed to load wiki section'
  }
}

// Section icon mapping
const getSectionIcon = (sectionId: string) => {
  const iconMap: Record<string, any> = {
    'executive_summary': BarChart3,
    'system_architecture': Building2,
    'authentication_analysis': Lock,
    'data_flow_security': ArrowRight,
    'vulnerability_analysis': AlertTriangle,
    'threat_landscape': Shield,
    'security_controls': Settings,
    'risk_assessment': BarChart3,
    'security_checklist': FileText,
    'code_findings': Code
  }
  return iconMap[sectionId] || BookOpen
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

const getSeverityClass = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'high':
    case 'critical':
      return 'bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-200'
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200'
    case 'low':
      return 'bg-green-100 dark:bg-green-900/20 text-green-800 dark:text-green-200'
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
  }
}

const renderWikiContent = (content: string) => {
  // Enhanced markdown rendering with cross-reference support
  let rendered = content
    .replace(/^### (.*$)/gim, '<h3 class="text-lg font-semibold mt-6 mb-3">$1</h3>')
    .replace(/^## (.*$)/gim, '<h2 class="text-xl font-semibold mt-8 mb-4">$1</h2>')
    .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold mt-8 mb-4">$1</h1>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code class="bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-sm">$1</code>')
    .replace(/\n\n/g, '</p><p class="mb-4">')
    .replace(/^(.*)$/gm, '<p class="mb-4">$1</p>')
    .replace(/^<p class="mb-4"><\/p>$/gm, '')

  // Handle cross-references (format: [[section_id]])
  rendered = rendered.replace(/\[\[([^\]]+)\]\]/g, (match, sectionId) => {
    const sectionTitle = wiki.value?.sections[sectionId]?.title || sectionId
    return `<button onclick="handleSectionSelect('${sectionId}')" class="text-blue-600 dark:text-blue-400 hover:underline">${sectionTitle}</button>`
  })

  return rendered
}

const getOwaspUrl = (mapping: string) => {
  // Convert OWASP mapping to URL
  const baseUrl = 'https://cheatsheetseries.owasp.org/cheatsheets/'
  const formattedMapping = mapping.replace(/-/g, '_').replace(/\b\w/g, l => l.toUpperCase())
  return `${baseUrl}${formattedMapping}_Cheat_Sheet.html`
}

const copyToClipboard = async (content: string) => {
  try {
    await navigator.clipboard.writeText(content)
    showSuccess('Copied to clipboard', 'Section content has been copied to your clipboard')
  } catch (err) {
    showError('Copy failed', 'Failed to copy content to clipboard')
  }
}

const exportSection = (section: WikiSection) => {
  const blob = new Blob([section.content], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${section.title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.md`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
  showSuccess('Section exported', `${section.title} has been downloaded`)
}

onMounted(() => {
  loadWikiData()
})
</script>

<style scoped>
.wiki-content {
  @apply text-gray-900 dark:text-gray-100;
}

.wiki-content h1,
.wiki-content h2,
.wiki-content h3,
.wiki-content h4,
.wiki-content h5,
.wiki-content h6 {
  @apply text-gray-900 dark:text-gray-100 font-semibold;
}

.wiki-content p {
  @apply mb-4 leading-relaxed;
}

.wiki-content ul,
.wiki-content ol {
  @apply mb-4 pl-6;
}

.wiki-content li {
  @apply mb-2;
}

.wiki-content code {
  @apply bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-sm font-mono;
}

.wiki-content pre {
  @apply bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto mb-4;
}

.wiki-content pre code {
  @apply bg-transparent p-0;
}

.wiki-content blockquote {
  @apply border-l-4 border-blue-500 pl-4 italic text-gray-700 dark:text-gray-300 mb-4;
}

.wiki-content table {
  @apply w-full border-collapse border border-gray-300 dark:border-gray-600 mb-4;
}

.wiki-content th,
.wiki-content td {
  @apply border border-gray-300 dark:border-gray-600 px-4 py-2 text-left;
}

.wiki-content th {
  @apply bg-gray-100 dark:bg-gray-700 font-semibold;
}

/* Cross-reference links */
.wiki-content button {
  @apply text-blue-600 dark:text-blue-400 hover:underline cursor-pointer;
}
</style>