'use client';

import { useState, useEffect, useRef } from 'react';
import { Search, X, FileText, ExternalLink } from 'lucide-react';
import { api } from '@/lib/api';
import { SearchResult, ThreatDocType } from '@/lib/types';
import LoadingSpinner from './LoadingSpinner';

interface SearchBoxProps {
  repoId: string;
  onDocumentSelect: (docId: string) => void;
  className?: string;
}

interface SearchState {
  query: string;
  results: SearchResult[];
  isSearching: boolean;
  isOpen: boolean;
  error: string | null;
  hasSearched: boolean;
}

// Cache for search results to avoid repeated API calls
const searchCache = new Map<string, SearchResult[]>();

export default function SearchBox({ repoId, onDocumentSelect, className = '' }: SearchBoxProps) {
  const [searchState, setSearchState] = useState<SearchState>({
    query: '',
    results: [],
    isSearching: false,
    isOpen: false,
    error: null,
    hasSearched: false
  });

  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Handle clicks outside to close search results
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchContainerRef.current && !searchContainerRef.current.contains(event.target as Node)) {
        setSearchState(prev => ({ ...prev, isOpen: false }));
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Debounced search function
  const performSearch = async (query: string) => {
    if (!query.trim()) {
      setSearchState(prev => ({
        ...prev,
        results: [],
        isOpen: false,
        hasSearched: false,
        error: null
      }));
      return;
    }

    // Check cache first
    const cacheKey = `${repoId}:${query.toLowerCase()}`;
    const cachedResults = searchCache.get(cacheKey);
    
    if (cachedResults) {
      setSearchState(prev => ({
        ...prev,
        results: cachedResults,
        isOpen: true,
        hasSearched: true,
        error: null
      }));
      return;
    }

    setSearchState(prev => ({ ...prev, isSearching: true, error: null }));

    try {
      const response = await api.searchDocuments({
        query: query.trim(),
        repo_id: repoId,
        limit: 10
      });

      // Cache the results
      searchCache.set(cacheKey, response.results);

      setSearchState(prev => ({
        ...prev,
        results: response.results,
        isSearching: false,
        isOpen: true,
        hasSearched: true,
        error: null
      }));
    } catch (error) {
      console.error('Search error:', error);
      setSearchState(prev => ({
        ...prev,
        isSearching: false,
        isOpen: true,
        hasSearched: true,
        error: error instanceof Error ? error.message : 'Search failed'
      }));
    }
  };

  // Handle input changes with debouncing
  const handleInputChange = (value: string) => {
    setSearchState(prev => ({ ...prev, query: value }));

    // Clear existing timeout
    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    // Set new timeout for debounced search
    debounceTimeoutRef.current = setTimeout(() => {
      performSearch(value);
    }, 300);
  };

  // Handle search input focus
  const handleInputFocus = () => {
    if (searchState.hasSearched && searchState.results.length > 0) {
      setSearchState(prev => ({ ...prev, isOpen: true }));
    }
  };

  // Handle result selection
  const handleResultClick = (result: SearchResult) => {
    onDocumentSelect(result.doc_id);
    setSearchState(prev => ({ ...prev, isOpen: false }));
    searchInputRef.current?.blur();
  };

  // Clear search
  const clearSearch = () => {
    setSearchState({
      query: '',
      results: [],
      isSearching: false,
      isOpen: false,
      error: null,
      hasSearched: false
    });
    searchInputRef.current?.focus();
  };

  // Handle keyboard navigation
  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Escape') {
      setSearchState(prev => ({ ...prev, isOpen: false }));
      searchInputRef.current?.blur();
    }
  };

  // Get document type display name
  const getDocTypeDisplayName = (docType: ThreatDocType): string => {
    switch (docType) {
      case ThreatDocType.SYSTEM_OVERVIEW:
        return 'System Overview';
      case ThreatDocType.COMPONENT_PROFILE:
        return 'Component Profile';
      case ThreatDocType.FLOW_THREAT_MODEL:
        return 'Flow Model';
      case ThreatDocType.MITIGATION:
        return 'Mitigation';
      default:
        return 'Document';
    }
  };

  // Get document type color
  const getDocTypeColor = (docType: ThreatDocType): string => {
    switch (docType) {
      case ThreatDocType.SYSTEM_OVERVIEW:
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
      case ThreatDocType.COMPONENT_PROFILE:
        return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
      case ThreatDocType.FLOW_THREAT_MODEL:
        return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200';
      case ThreatDocType.MITIGATION:
        return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200';
    }
  };

  // Highlight search terms in text
  const highlightSearchTerms = (text: string, query: string): React.ReactNode => {
    if (!query.trim()) return text;

    const terms = query.toLowerCase().split(/\s+/).filter(term => term.length > 0);
    let highlightedText = text;

    terms.forEach(term => {
      const regex = new RegExp(`(${term})`, 'gi');
      highlightedText = highlightedText.replace(regex, '<mark class="bg-yellow-200 dark:bg-yellow-800 px-0.5 rounded">$1</mark>');
    });

    return <span dangerouslySetInnerHTML={{ __html: highlightedText }} />;
  };

  return (
    <div ref={searchContainerRef} className={`relative ${className}`}>
      {/* Search Input */}
      <div className="relative">
        <input
          ref={searchInputRef}
          type="text"
          value={searchState.query}
          onChange={(e) => handleInputChange(e.target.value)}
          onFocus={handleInputFocus}
          onKeyDown={handleKeyDown}
          placeholder="Search documentation..."
          className="w-full pl-10 pr-10 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors"
        />
        
        {/* Search Icon */}
        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
          {searchState.isSearching ? (
            <LoadingSpinner size="small" />
          ) : (
            <Search className="h-5 w-5 text-gray-400" />
          )}
        </div>

        {/* Clear Button */}
        {searchState.query && (
          <button
            onClick={clearSearch}
            className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        )}
      </div>

      {/* Search Results Dropdown */}
      {searchState.isOpen && (
        <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg z-50 max-h-96 overflow-y-auto">
          {searchState.error ? (
            <div className="p-4 text-center">
              <div className="text-red-600 dark:text-red-400 mb-2">
                <FileText className="h-8 w-8 mx-auto" />
              </div>
              <p className="text-sm text-red-600 dark:text-red-400">
                {searchState.error}
              </p>
            </div>
          ) : searchState.results.length === 0 && searchState.hasSearched ? (
            <div className="p-4 text-center">
              <div className="text-gray-400 dark:text-gray-600 mb-2">
                <Search className="h-8 w-8 mx-auto" />
              </div>
              <p className="text-sm text-gray-600 dark:text-gray-400">
                No results found for "{searchState.query}"
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                Try different keywords or check your spelling
              </p>
            </div>
          ) : (
            <div className="py-2">
              {searchState.results.map((result, index) => (
                <button
                  key={`${result.doc_id}-${index}`}
                  onClick={() => handleResultClick(result)}
                  className="w-full px-4 py-3 text-left hover:bg-gray-50 dark:hover:bg-gray-700 border-b border-gray-100 dark:border-gray-700 last:border-b-0 transition-colors focus:outline-none focus:bg-gray-50 dark:focus:bg-gray-700"
                >
                  <div className="flex items-start space-x-3">
                    <div className="flex-shrink-0 mt-1">
                      <FileText className="h-4 w-4 text-gray-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center space-x-2 mb-1">
                        <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                          {result.title}
                        </h4>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${getDocTypeColor(result.doc_type)}`}>
                          {getDocTypeDisplayName(result.doc_type)}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 line-clamp-2">
                        {highlightSearchTerms(result.content_snippet, searchState.query)}
                      </p>
                      <div className="flex items-center justify-between mt-2">
                        <span className="text-xs text-gray-500 dark:text-gray-500">
                          Relevance: {Math.round(result.relevance_score * 100)}%
                        </span>
                        <ExternalLink className="h-3 w-3 text-gray-400" />
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}