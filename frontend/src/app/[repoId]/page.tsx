'use client';

import { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import { api } from '@/lib/api';
import { ThreatDoc, AnalysisProgress, DocListItem, ThreatDocType } from '@/lib/types';
import RepoNav from '@/components/RepoNav';
import DocViewer from '@/components/DocViewer';
import LoadingSpinner from '@/components/LoadingSpinner';
import ErrorBoundary from '@/components/ErrorBoundary';
import SearchBox from '@/components/SearchBox';

export default function RepositoryPage() {
  const params = useParams();
  const repoId = params.repoId as string;
  
  const [analysisStatus, setAnalysisStatus] = useState<AnalysisProgress | null>(null);
  const [documents, setDocuments] = useState<ThreatDoc[]>([]);
  const [selectedDoc, setSelectedDoc] = useState<ThreatDoc | null>(null);
  const [docNavItems, setDocNavItems] = useState<DocListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingDocId, setLoadingDocId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [documentCache, setDocumentCache] = useState<Map<string, ThreatDoc>>(new Map());

  // Load initial data
  useEffect(() => {
    loadRepositoryData();
  }, [repoId]);

  // Poll for analysis status if still analyzing
  useEffect(() => {
    if (analysisStatus?.status === 'analyzing' || analysisStatus?.status === 'queued') {
      const interval = setInterval(async () => {
        try {
          const status = await api.getAnalysisStatus(repoId);
          setAnalysisStatus(status);
          
          if (status.status === 'completed') {
            // Reload documents when analysis completes
            await loadDocuments();
          }
        } catch (err) {
          console.error('Error polling analysis status:', err);
        }
      }, 3000);

      return () => clearInterval(interval);
    }
  }, [analysisStatus?.status, repoId]);

  const loadRepositoryData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Load analysis status
      const status = await api.getAnalysisStatus(repoId);
      setAnalysisStatus(status);

      // Load documents if analysis is complete
      if (status.status === 'completed') {
        await loadDocuments();
      }
    } catch (err) {
      console.error('Error loading repository data:', err);
      setError(err instanceof Error ? err.message : 'Failed to load repository data');
    } finally {
      setLoading(false);
    }
  };

  const loadDocuments = async () => {
    try {
      const response = await api.getRepositoryDocuments(repoId);
      setDocuments(response.documents);
      
      // Cache all loaded documents
      const newCache = new Map(documentCache);
      response.documents.forEach(doc => {
        newCache.set(doc.id, doc);
      });
      setDocumentCache(newCache);
      
      // Build navigation structure with enhanced categorization
      const navItems = buildDocumentNavigation(response.documents);
      setDocNavItems(navItems);
      
      // Select first document by default
      if (response.documents.length > 0 && !selectedDoc) {
        setSelectedDoc(response.documents[0]);
      }
    } catch (err) {
      console.error('Error loading documents:', err);
      setError(err instanceof Error ? err.message : 'Failed to load documents');
    }
  };

  const buildDocumentNavigation = (docs: ThreatDoc[]): DocListItem[] => {
    const navItems: DocListItem[] = [];
    
    // Group documents by type with enhanced categorization
    const docsByType = docs.reduce((acc, doc) => {
      if (!acc[doc.doc_type]) {
        acc[doc.doc_type] = [];
      }
      acc[doc.doc_type].push(doc);
      return acc;
    }, {} as Record<ThreatDocType, ThreatDoc[]>);

    // System Overview - Always show first
    if (docsByType[ThreatDocType.SYSTEM_OVERVIEW]) {
      docsByType[ThreatDocType.SYSTEM_OVERVIEW].forEach(doc => {
        navItems.push({
          id: doc.id,
          type: doc.doc_type,
          title: doc.title
        });
      });
    }

    // Component Security Profiles - Hierarchical grouping
    if (docsByType[ThreatDocType.COMPONENT_PROFILE]) {
      const componentDocs = docsByType[ThreatDocType.COMPONENT_PROFILE];
      
      // Sort components by name for better organization
      componentDocs.sort((a, b) => a.title.localeCompare(b.title));
      
      navItems.push({
        id: 'component-profiles',
        type: ThreatDocType.COMPONENT_PROFILE,
        title: `Component Security Profiles (${componentDocs.length})`,
        children: componentDocs.map(doc => ({
          id: doc.id,
          type: doc.doc_type,
          title: doc.title.replace(/^Component Profile:\s*/, '') // Clean up title
        }))
      });
    }

    // Flow Threat Models - Hierarchical grouping
    if (docsByType[ThreatDocType.FLOW_THREAT_MODEL]) {
      const flowDocs = docsByType[ThreatDocType.FLOW_THREAT_MODEL];
      
      // Sort flows by name for better organization
      flowDocs.sort((a, b) => a.title.localeCompare(b.title));
      
      navItems.push({
        id: 'flow-models',
        type: ThreatDocType.FLOW_THREAT_MODEL,
        title: `Flow Threat Models (${flowDocs.length})`,
        children: flowDocs.map(doc => ({
          id: doc.id,
          type: doc.doc_type,
          title: doc.title.replace(/^Flow Threat Model:\s*/, '') // Clean up title
        }))
      });
    }

    // Threats & Mitigations - Hierarchical grouping
    if (docsByType[ThreatDocType.MITIGATION]) {
      const mitigationDocs = docsByType[ThreatDocType.MITIGATION];
      
      // Sort mitigations by severity/priority if available in metadata
      mitigationDocs.sort((a, b) => {
        // Try to sort by severity first, then by title
        const severityA = a.metadata?.severity || 'medium';
        const severityB = b.metadata?.severity || 'medium';
        const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3 };
        
        const orderA = severityOrder[severityA as keyof typeof severityOrder] ?? 2;
        const orderB = severityOrder[severityB as keyof typeof severityOrder] ?? 2;
        
        if (orderA !== orderB) {
          return orderA - orderB;
        }
        
        return a.title.localeCompare(b.title);
      });
      
      navItems.push({
        id: 'mitigations',
        type: ThreatDocType.MITIGATION,
        title: `Threats & Mitigations (${mitigationDocs.length})`,
        children: mitigationDocs.map(doc => ({
          id: doc.id,
          type: doc.doc_type,
          title: doc.title.replace(/^(Threat|Mitigation):\s*/, '') // Clean up title
        }))
      });
    }

    return navItems;
  };

  const handleDocumentSelect = async (docId: string) => {
    try {
      setError(null);
      
      // Check cache first
      const cachedDoc = documentCache.get(docId);
      if (cachedDoc) {
        setSelectedDoc(cachedDoc);
        return;
      }

      // Check if document is already in the documents array
      const existingDoc = documents.find(d => d.id === docId);
      if (existingDoc) {
        setSelectedDoc(existingDoc);
        // Cache it for future use
        const newCache = new Map(documentCache);
        newCache.set(docId, existingDoc);
        setDocumentCache(newCache);
        return;
      }

      // Load document from API with loading state
      setLoadingDocId(docId);
      const loadedDoc = await api.getDocument(repoId, docId);
      
      // Cache the loaded document
      const newCache = new Map(documentCache);
      newCache.set(docId, loadedDoc);
      setDocumentCache(newCache);
      
      setSelectedDoc(loadedDoc);
    } catch (err) {
      console.error('Error loading document:', err);
      setError(err instanceof Error ? err.message : 'Failed to load document');
    } finally {
      setLoadingDocId(null);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <LoadingSpinner size="large" message="Loading repository..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="text-red-600 dark:text-red-400 mb-4">
            <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
            Error Loading Repository
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mb-4">{error}</p>
          <button
            onClick={loadRepositoryData}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
        <div className="flex h-screen">
          {/* Sidebar Navigation */}
          <div className="w-80 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex flex-col">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <h1 className="text-xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Repository Analysis
              </h1>
              {analysisStatus && (
                <div className="text-sm">
                  <div className="flex items-center space-x-2">
                    <div className={`w-2 h-2 rounded-full ${
                      analysisStatus.status === 'completed' ? 'bg-green-500' :
                      analysisStatus.status === 'analyzing' ? 'bg-yellow-500 animate-pulse' :
                      analysisStatus.status === 'error' ? 'bg-red-500' :
                      'bg-gray-400'
                    }`} />
                    <span className="text-gray-600 dark:text-gray-400 capitalize">
                      {analysisStatus.status}
                    </span>
                  </div>
                  {analysisStatus.current_stage && (
                    <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
                      {analysisStatus.current_stage}
                    </p>
                  )}
                  {analysisStatus.progress_percentage !== undefined && (
                    <div className="mt-2">
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
                        <div 
                          className="bg-blue-600 h-1.5 rounded-full transition-all duration-300"
                          style={{ width: `${analysisStatus.progress_percentage}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-500 dark:text-gray-500">
                        {analysisStatus.progress_percentage}%
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>
            
            <div className="flex-1 overflow-y-auto">
              <RepoNav
                items={docNavItems}
                selectedDocId={selectedDoc?.id}
                onDocumentSelect={handleDocumentSelect}
                loadingDocId={loadingDocId || undefined}
              />
            </div>
          </div>

          {/* Main Content Area */}
          <div className="flex-1 flex flex-col">
            {/* Top Bar with Search */}
            <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center space-x-4">
                <div className="flex-1">
                  <SearchBox
                    repoId={repoId}
                    onDocumentSelect={handleDocumentSelect}
                  />
                </div>
              </div>
            </div>

            {/* Document Content */}
            <div className="flex-1 overflow-y-auto">
              {analysisStatus?.status === 'analyzing' || analysisStatus?.status === 'queued' ? (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <LoadingSpinner size="large" />
                    <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mt-4 mb-2">
                      Analyzing Repository
                    </h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      {analysisStatus.current_stage || 'Processing your repository...'}
                    </p>
                    {analysisStatus.progress_percentage !== undefined && (
                      <div className="mt-4 w-64 mx-auto">
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div 
                            className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${analysisStatus.progress_percentage}%` }}
                          />
                        </div>
                        <span className="text-sm text-gray-500 dark:text-gray-500 mt-1 block">
                          {analysisStatus.progress_percentage}% complete
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              ) : selectedDoc ? (
                <DocViewer document={selectedDoc} />
              ) : (
                <div className="flex items-center justify-center h-full">
                  <div className="text-center">
                    <div className="text-gray-400 dark:text-gray-600 mb-4">
                      <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                      </svg>
                    </div>
                    <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
                      No Document Selected
                    </h3>
                    <p className="text-gray-600 dark:text-gray-400">
                      Select a document from the navigation to view its content
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </ErrorBoundary>
  );
}