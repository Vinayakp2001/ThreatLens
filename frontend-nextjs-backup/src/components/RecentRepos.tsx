'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { RepoInfo, StoredRepos, AnalysisStatus } from '@/lib/types';
import { api } from '@/lib/api';
import StatusIndicator from './StatusIndicator';

interface RecentReposProps {
  newRepo?: RepoInfo | null;
}

export default function RecentRepos({ newRepo }: RecentReposProps) {
  const [recentRepos, setRecentRepos] = useState<RepoInfo[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Load recent repos from localStorage on component mount
  useEffect(() => {
    loadRecentRepos();
  }, []);

  // Add new repo when prop changes
  useEffect(() => {
    if (newRepo) {
      addRecentRepo(newRepo);
    }
  }, [newRepo]);

  const loadRecentRepos = () => {
    try {
      const stored = localStorage.getItem('threatlens-recent-repos');
      if (stored) {
        const data: StoredRepos = JSON.parse(stored);
        setRecentRepos(data.recent || []);
      }
    } catch (error) {
      console.error('Failed to load recent repos from localStorage:', error);
      setRecentRepos([]);
    } finally {
      setIsLoading(false);
    }
  };

  const saveRecentRepos = (repos: RepoInfo[]) => {
    try {
      const data: StoredRepos = { recent: repos };
      localStorage.setItem('threatlens-recent-repos', JSON.stringify(data));
      setRecentRepos(repos);
    } catch (error) {
      console.error('Failed to save recent repos to localStorage:', error);
    }
  };

  const addRecentRepo = (repo: RepoInfo) => {
    const updatedRepos = [
      repo,
      ...recentRepos.filter(r => r.id !== repo.id) // Remove duplicate if exists
    ].slice(0, 10); // Keep only the 10 most recent

    saveRecentRepos(updatedRepos);
  };

  const removeRepo = (repoId: string) => {
    const updatedRepos = recentRepos.filter(repo => repo.id !== repoId);
    saveRecentRepos(updatedRepos);
  };

  const updateRepoStatus = async (repoId: string) => {
    try {
      const status = await api.getAnalysisStatus(repoId);
      const updatedRepos = recentRepos.map(repo => 
        repo.id === repoId 
          ? { ...repo, status: status.status }
          : repo
      );
      saveRecentRepos(updatedRepos);
    } catch (error) {
      console.error('Failed to update repo status:', error);
    }
  };

  const formatDate = (dateString: string): string => {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return 'Unknown';
    }
  };

  const getRepoTitle = (repo: RepoInfo): string => {
    if (repo.title) return repo.title;
    if (repo.url) {
      // Extract repo name from URL
      const match = repo.url.match(/\/([^\/]+)(?:\.git)?$/);
      return match ? match[1] : repo.url;
    }
    if (repo.local_path) {
      // Extract folder name from path
      const parts = repo.local_path.split(/[\/\\]/);
      return parts[parts.length - 1] || repo.local_path;
    }
    return repo.id;
  };

  // Expose addRecentRepo method to parent component
  useEffect(() => {
    // No longer needed with prop-based approach
  }, []);

  if (isLoading) {
    return (
      <div className="w-full max-w-2xl mx-auto">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded mb-4"></div>
          <div className="space-y-3">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-16 bg-gray-100 dark:bg-gray-800 rounded-lg"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (recentRepos.length === 0) {
    return (
      <div className="w-full max-w-2xl mx-auto">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Recent Analyses
        </h2>
        <div className="text-center py-8 bg-gray-50 dark:bg-gray-800/50 rounded-lg border-2 border-dashed border-gray-300 dark:border-gray-600">
          <p className="text-gray-500 dark:text-gray-400">
            No recent analyses yet. Analyze your first repository above to get started.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-2xl mx-auto">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
        Recent Analyses
      </h2>
      <div className="space-y-3">
        {recentRepos.map((repo) => (
          <div
            key={repo.id}
            className="flex items-center justify-between p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg hover:shadow-md transition-shadow"
          >
            <div className="flex-1 min-w-0">
              <div className="flex items-center space-x-3">
                <div className="flex-1 min-w-0">
                  <h3 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                    {getRepoTitle(repo)}
                  </h3>
                  {repo.url && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate mt-1">
                      {repo.url}
                    </p>
                  )}
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                    {formatDate(repo.analyzedAt)}
                  </p>
                </div>
                <div className="flex items-center space-x-2">
                  <StatusIndicator status={repo.status} size="small" />
                  {repo.status === 'analyzing' && (
                    <button
                      onClick={() => updateRepoStatus(repo.id)}
                      className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                      title="Refresh status"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-2 ml-4">
              {repo.status === 'completed' && (
                <Link
                  href={`/${repo.id}`}
                  className="inline-flex items-center px-3 py-1.5 border border-transparent text-xs font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200 dark:text-blue-400 dark:bg-blue-900/20 dark:hover:bg-blue-900/40 transition-colors"
                >
                  View Results
                </Link>
              )}
              <button
                onClick={() => removeRepo(repo.id)}
                className="text-gray-400 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                title="Remove from recent"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// No longer needed with prop-based approach