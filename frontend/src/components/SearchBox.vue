<template>
  <div ref="searchContainer" :class="cn('relative', className)">
    <!-- Search Input -->
    <div class="relative">
      <input
        ref="searchInput"
        v-model="searchState.query"
        @input="handleInputChange"
        @focus="handleInputFocus"
        @keydown="handleKeyDown"
        type="text"
        placeholder="Search documentation..."
        class="w-full pl-10 pr-10 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
      />
      
      <!-- Search Icon -->
      <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
        <LoadingSpinner v-if="searchState.isSearching" size="small" />
        <Search v-else class="h-5 w-5 text-gray-400" />
      </div>

      <!-- Clear Button -->
      <button
        v-if="searchState.query"
        @click="clearSearch"
        class="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
      >
        <X class="h-5 w-5" />
      </button>
    </div>

    <!-- Search Results Dropdown -->
    <div 
      v-if="searchState.isOpen" 
      class="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg z-50 max-h-96 overflow-y-auto"
    >
      <!-- Error State -->
      <div v-if="searchState.error" class="p-4">
        <ErrorDisplay
          :error="searchState.error"
          title="Search Error"
          :on-retry="() => performSearch(searchState.query)"
          :show-retry="true"
          class="text-left"
        />
      </div>

      <!-- No Results -->
      <div 
        v-else-if="searchState.results.length === 0 && searchState.hasSearched" 
        class="p-4 text-center"
      >
        <div class="text-gray-400 dark:text-gray-600 mb-2">
          <Search class="h-8 w-8 mx-auto" />
        </div>
        <p class="text-sm text-gray-600 dark:text-gray-400">
          No results found for "{{ searchState.query }}"
        </p>
        <p class="text-xs text-gray-500 dark:text-gray-500 mt-1">
          Try different keywords or check your spelling
        </p>
      </div>

      <!-- Results -->
      <div v-else class="py-2">
        <button
          v-for="(result, index) in searchState.results"
          :key="`${result.doc_id}-${index}`"
          @click="handleResultClick(result)"
          class="w-full px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700 border-b border-gray-100 dark:border-gray-700 last:border-b-0 transition-colors focus:outline-none focus:bg-gray-50 dark:focus:bg-gray-700"
        >
          <div class="flex items-start space-x-3">
            <div class="flex-shrink-0 mt-1">
              <FileText class="h-4 w-4 text-gray-400" />
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex items-center space-x-2 mb-1">
                <h4 class="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                  {{ result.title }}
                </h4>
                <span :class="cn('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', getDocTypeColor(result.doc_type))">
                  {{ getDocTypeDisplayName(result.doc_type) }}
                </span>
              </div>
              <p class="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                {{ result.content_snippet }}
              </p>
              <div class="flex items-center justify-between mt-2">
                <span class="text-xs text-gray-500 dark:text-gray-500">
                  Relevance: {{ Math.round(result.relevance_score * 100) }}%
                </span>
                <ExternalLink class="h-3 w-3 text-gray-400" />
              </div>
            </div>
          </div>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { Search, X, FileText, ExternalLink } from 'lucide-vue-next'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import LoadingSpinner from './LoadingSpinner.vue'
import ErrorDisplay from './ErrorDisplay.vue'

interface Props {
  repoId: string
  onDocumentSelect: (docId: string) => void
  className?: string
}

interface SearchResult {
  doc_id: string
  title: string
  content_snippet: string
  relevance_score: number
  doc_type: string
  code_references: any[]
}

const props = withDefaults(defineProps<Props>(), {
  className: ''
})

const emit = defineEmits<{
  documentSelect: [docId: string]
}>()

const searchInput = ref<HTMLInputElement>()
const searchContainer = ref<HTMLDivElement>()
let debounceTimeout: NodeJS.Timeout | null = null

const searchState = reactive({
  query: '',
  results: [] as SearchResult[],
  isSearching: false,
  isOpen: false,
  error: null as string | null,
  hasSearched: false
})

// Cache for search results
const searchCache = new Map<string, SearchResult[]>()

const performSearch = async (query: string) => {
  if (!query.trim()) {
    searchState.results = []
    searchState.isOpen = false
    searchState.hasSearched = false
    searchState.error = null
    return
  }

  // Check cache first
  const cacheKey = `${props.repoId}:${query.toLowerCase()}`
  const cachedResults = searchCache.get(cacheKey)
  
  if (cachedResults) {
    searchState.results = cachedResults
    searchState.isOpen = true
    searchState.hasSearched = true
    searchState.error = null
    return
  }

  searchState.isSearching = true
  searchState.error = null

  try {
    const response = await api.searchDocuments({
      query: query.trim(),
      repo_id: props.repoId,
      limit: 10
    })

    // Cache the results
    searchCache.set(cacheKey, response.results)

    searchState.results = response.results
    searchState.isSearching = false
    searchState.isOpen = true
    searchState.hasSearched = true
    searchState.error = null
  } catch (error) {
    console.error('Search error:', error)
    searchState.isSearching = false
    searchState.isOpen = true
    searchState.hasSearched = true
    searchState.error = error instanceof Error ? error.message : 'Search failed'
  }
}

const handleInputChange = () => {
  // Clear existing timeout
  if (debounceTimeout) {
    clearTimeout(debounceTimeout)
  }

  // Set new timeout for debounced search
  debounceTimeout = setTimeout(() => {
    performSearch(searchState.query)
  }, 300)
}

const handleInputFocus = () => {
  if (searchState.hasSearched && searchState.results.length > 0) {
    searchState.isOpen = true
  }
}

const handleResultClick = (result: SearchResult) => {
  emit('documentSelect', result.doc_id)
  props.onDocumentSelect(result.doc_id)
  searchState.isOpen = false
  searchInput.value?.blur()
}

const clearSearch = () => {
  searchState.query = ''
  searchState.results = []
  searchState.isSearching = false
  searchState.isOpen = false
  searchState.error = null
  searchState.hasSearched = false
  searchInput.value?.focus()
}

const handleKeyDown = (event: KeyboardEvent) => {
  if (event.key === 'Escape') {
    searchState.isOpen = false
    searchInput.value?.blur()
  }
}

const getDocTypeDisplayName = (docType: string): string => {
  switch (docType) {
    case 'system_overview':
      return 'System Overview'
    case 'component_profile':
      return 'Component Profile'
    case 'flow_threat_model':
      return 'Flow Model'
    case 'mitigation':
      return 'Mitigation'
    default:
      return 'Document'
  }
}

const getDocTypeColor = (docType: string): string => {
  switch (docType) {
    case 'system_overview':
      return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
    case 'component_profile':
      return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
    case 'flow_threat_model':
      return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200'
    case 'mitigation':
      return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
    default:
      return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
  }
}

// Handle clicks outside to close search results
const handleClickOutside = (event: MouseEvent) => {
  if (searchContainer.value && !searchContainer.value.contains(event.target as Node)) {
    searchState.isOpen = false
  }
}

onMounted(() => {
  document.addEventListener('mousedown', handleClickOutside)
})

onUnmounted(() => {
  document.removeEventListener('mousedown', handleClickOutside)
  if (debounceTimeout) {
    clearTimeout(debounceTimeout)
  }
})
</script>