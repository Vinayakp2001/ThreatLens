'use client';

import { useState } from 'react';
import { DocListItem } from '@/lib/types';
import LoadingSpinner from './LoadingSpinner';

interface RepoNavProps {
  items: DocListItem[];
  selectedDocId?: string;
  onDocumentSelect: (docId: string) => void;
  loadingDocId?: string; // Track which document is currently loading
}

interface NavItemProps {
  item: DocListItem;
  selectedDocId?: string;
  onDocumentSelect: (docId: string) => void;
  loadingDocId?: string;
  level?: number;
}

function NavItem({ item, selectedDocId, onDocumentSelect, loadingDocId, level = 0 }: NavItemProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const hasChildren = item.children && item.children.length > 0;
  const isSelected = selectedDocId === item.id;
  const isLoading = loadingDocId === item.id;
  const isParentItem = hasChildren && level === 0;

  const handleClick = () => {
    if (hasChildren) {
      setIsExpanded(!isExpanded);
    } else {
      onDocumentSelect(item.id);
    }
  };

  const getIcon = () => {
    switch (item.type) {
      case 'system_overview':
        return (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
        );
      case 'component_profile':
        return (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
        );
      case 'flow_threat_model':
        return (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
          </svg>
        );
      case 'mitigation':
        return (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        );
      default:
        return (
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        );
    }
  };

  const getCategoryBadge = () => {
    if (!hasChildren) return null;
    
    const childCount = item.children?.length || 0;
    return (
      <span className="ml-2 px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded-full">
        {childCount}
      </span>
    );
  };

  return (
    <div>
      <div
        className={`flex items-center px-3 py-2 text-sm cursor-pointer transition-colors ${
          level > 0 ? 'ml-4' : ''
        } ${
          isSelected
            ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 border-r-2 border-blue-500'
            : 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
        } ${
          isParentItem ? 'font-medium' : ''
        } ${
          isLoading ? 'opacity-75' : ''
        }`}
        onClick={handleClick}
      >
        {hasChildren && (
          <div className="mr-2">
            <svg
              className={`w-4 h-4 transition-transform ${
                isExpanded ? 'transform rotate-90' : ''
              }`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
            </svg>
          </div>
        )}
        
        {!hasChildren && (
          <div className="mr-2 text-gray-400 dark:text-gray-500">
            {isLoading ? (
              <LoadingSpinner size="small" />
            ) : (
              getIcon()
            )}
          </div>
        )}
        
        <span className="flex-1 truncate">{item.title}</span>
        
        {hasChildren && (
          <div className="flex items-center">
            {getCategoryBadge()}
            <div className="ml-2 text-gray-400 dark:text-gray-500">
              {getIcon()}
            </div>
          </div>
        )}
      </div>

      {hasChildren && isExpanded && (
        <div className="border-l border-gray-200 dark:border-gray-700 ml-3">
          {item.children?.map((child) => (
            <NavItem
              key={child.id}
              item={child}
              selectedDocId={selectedDocId}
              onDocumentSelect={onDocumentSelect}
              loadingDocId={loadingDocId}
              level={level + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function RepoNav({ items, selectedDocId, onDocumentSelect, loadingDocId }: RepoNavProps) {
  if (items.length === 0) {
    return (
      <div className="p-4 text-center">
        <div className="text-gray-400 dark:text-gray-600 mb-2">
          <svg className="w-8 h-8 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </div>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          No documents available
        </p>
      </div>
    );
  }

  return (
    <nav className="py-2">
      <div className="px-3 py-2 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
        Documentation
      </div>
      {items.map((item) => (
        <NavItem
          key={item.id}
          item={item}
          selectedDocId={selectedDocId}
          onDocumentSelect={onDocumentSelect}
          loadingDocId={loadingDocId}
        />
      ))}
    </nav>
  );
}