'use client';

import { useState } from 'react';
import { api, formatAPIError } from '@/lib/api';
import { AnalyzeRepoRequest, AnalyzeRepoResponse } from '@/lib/types';
import FormField, { validationRules } from './FormField';
import ErrorDisplay from './ErrorDisplay';
import StatusDisplay from './StatusDisplay';
import { useSuccessToast, useErrorToast } from './Toast';

interface RepoFormProps {
  onAnalysisStarted?: (response: AnalyzeRepoResponse, repoUrl: string) => void;
}

export default function RepoForm({ onAnalysisStarted }: RepoFormProps) {
  const [repoUrl, setRepoUrl] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  
  const showSuccess = useSuccessToast();
  const showError = useErrorToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!repoUrl.trim()) {
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
        throw new Error(validation.message || 'Repository validation failed');
      }

      // Start the analysis
      const response = await api.analyzeRepository(request);
      
      // Show success toast
      showSuccess(
        'Analysis Started',
        'Repository analysis has been queued successfully!'
      );
      
      // Call the callback if provided
      if (onAnalysisStarted) {
        onAnalysisStarted(response, repoUrl.trim());
      }

      // Clear the form on success
      setRepoUrl('');
      
    } catch (err) {
      const errorObj = err instanceof Error ? err : new Error('An unexpected error occurred');
      setError(errorObj);
      showError(
        'Analysis Failed',
        errorObj.message,
        {
          label: 'Try Again',
          onClick: handleRetry
        }
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRetry = () => {
    setError(null);
    handleSubmit(new Event('submit') as any);
  };

  const dismissError = () => {
    setError(null);
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="space-y-6">
        <FormField
          label="Repository URL"
          type="url"
          value={repoUrl}
          onChange={setRepoUrl}
          placeholder="https://github.com/username/repository"
          required
          disabled={isSubmitting}
          validationRules={[
            validationRules.required('Repository URL'),
            validationRules.url(),
            validationRules.gitUrl()
          ]}
          validateOnChange={true}
          validateOnBlur={true}
          autoComplete="url"
          className="mb-4"
        />

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
            <StatusDisplay
              status="loading"
              message="Analyzing Repository..."
              size="small"
              className="justify-center"
            />
          ) : (
            'Analyze Repository'
          )}
        </button>

        {/* Error Display */}
        {error && (
          <div className="mt-4">
            <ErrorDisplay
              error={error}
              title="Analysis Failed"
              onRetry={handleRetry}
              onDismiss={dismissError}
              showRetry={true}
            />
          </div>
        )}
      </form>
    </div>
  );
}