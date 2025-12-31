'use client';

import { useState } from 'react';
import { api, formatAPIError } from '@/lib/api';
import { AnalyzeRepoRequest, AnalyzeRepoResponse } from '@/lib/types';

interface RepoFormProps {
  onAnalysisStarted?: (response: AnalyzeRepoResponse, repoUrl: string) => void;
}

export default function RepoForm({ onAnalysisStarted }: RepoFormProps) {
  const [repoUrl, setRepoUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  const validateUrl = (url: string): boolean => {
    if (!url.trim()) {
      setValidationError('Repository URL is required');
      return false;
    }

    // Basic URL validation
    try {
      new URL(url);
    } catch {
      setValidationError('Please enter a valid URL');
      return false;
    }

    // Check if it looks like a git repository URL
    const gitUrlPattern = /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org|git\.)/i;
    if (!gitUrlPattern.test(url)) {
      setValidationError('Please enter a valid Git repository URL (GitHub, GitLab, Bitbucket, etc.)');
      return false;
    }

    setValidationError(null);
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!validateUrl(repoUrl)) {
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      const request: AnalyzeRepoRequest = {
        repo_url: repoUrl.trim()
      };

      // First validate the repository
      const validation = await api.validateRepository(request);
      
      if (!validation.valid) {
        setError(validation.message || 'Repository validation failed');
        return;
      }

      // Start the analysis
      const response = await api.analyzeRepository(request);
      
      // Call the callback if provided
      if (onAnalysisStarted) {
        onAnalysisStarted(response, repoUrl.trim());
      }

      // Clear the form on success
      setRepoUrl('');
      
    } catch (err) {
      setError(formatAPIError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setRepoUrl(value);
    
    // Clear validation error when user starts typing
    if (validationError) {
      setValidationError(null);
    }
    
    // Clear general error when user modifies input
    if (error) {
      setError(null);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label 
            htmlFor="repo-url" 
            className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2"
          >
            Repository URL
          </label>
          <input
            id="repo-url"
            type="url"
            value={repoUrl}
            onChange={handleUrlChange}
            placeholder="https://github.com/username/repository"
            className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors ${
              validationError 
                ? 'border-red-500 bg-red-50 dark:bg-red-900/20' 
                : 'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800'
            } text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400`}
            disabled={isSubmitting}
            required
          />
          {validationError && (
            <p className="mt-2 text-sm text-red-600 dark:text-red-400">
              {validationError}
            </p>
          )}
        </div>

        <button
          type="submit"
          disabled={isSubmitting || !repoUrl.trim()}
          className={`w-full py-3 px-6 rounded-lg font-medium transition-all duration-200 ${
            isSubmitting || !repoUrl.trim()
              ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 dark:text-gray-400 cursor-not-allowed'
              : 'bg-blue-600 hover:bg-blue-700 text-white shadow-lg hover:shadow-xl transform hover:-translate-y-0.5'
          }`}
        >
          {isSubmitting ? (
            <div className="flex items-center justify-center space-x-2">
              <div className="w-4 h-4 border-2 border-gray-400 border-t-transparent rounded-full animate-spin"></div>
              <span>Analyzing Repository...</span>
            </div>
          ) : (
            'Analyze Repository'
          )}
        </button>

        {error && (
          <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
            <p className="text-sm text-red-700 dark:text-red-300">
              <strong>Error:</strong> {error}
            </p>
          </div>
        )}
      </form>
    </div>
  );
}