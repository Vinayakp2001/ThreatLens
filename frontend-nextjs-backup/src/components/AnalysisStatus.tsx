'use client';

import { useState, useEffect, useCallback } from 'react';
import { api, formatAPIError } from '@/lib/api';
import { AnalysisProgress, AnalysisStatus as StatusType } from '@/lib/types';
import LoadingSpinner from './LoadingSpinner';

interface AnalysisStatusProps {
  repoId: string;
  analysisId?: string;
  onStatusChange?: (status: AnalysisProgress) => void;
  onComplete?: (status: AnalysisProgress) => void;
  onError?: (error: string) => void;
  pollInterval?: number;
  className?: string;
}

export default function AnalysisStatus({
  repoId,
  analysisId,
  onStatusChange,
  onComplete,
  onError,
  pollInterval = 2000,
  className = ''
}: AnalysisStatusProps) {
  const [status, setStatus] = useState<AnalysisProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  const fetchStatus = useCallback(async () => {
    try {
      setError(null);
      let statusResponse: AnalysisProgress;
      
      if (analysisId) {
        statusResponse = await api.getAnalysisProgress(analysisId);
      } else {
        statusResponse = await api.getAnalysisStatus(repoId);
      }
      
      setStatus(statusResponse);
      
      // Call status change callback
      if (onStatusChange) {
        onStatusChange(statusResponse);
      }
      
      // Handle completion
      if (statusResponse.status === 'completed') {
        setIsPolling(false);
        if (onComplete) {
          onComplete(statusResponse);
        }
      }
      
      // Handle errors
      if (statusResponse.status === 'error') {
        setIsPolling(false);
        const errorMessage = statusResponse.error_details || statusResponse.message || 'Analysis failed';
        setError(errorMessage);
        if (onError) {
          onError(errorMessage);
        }
      }
      
      return statusResponse;
    } catch (err) {
      const errorMessage = formatAPIError(err);
      setError(errorMessage);
      setIsPolling(false);
      if (onError) {
        onError(errorMessage);
      }
      throw err;
    }
  }, [repoId, analysisId, onStatusChange, onComplete, onError]);

  // Start polling when component mounts or when status indicates ongoing analysis
  useEffect(() => {
    const shouldPoll = !status || status.status === 'queued' || status.status === 'analyzing';
    
    if (shouldPoll && !isPolling) {
      setIsPolling(true);
      fetchStatus();
    }
  }, [status, isPolling, fetchStatus]);

  // Polling effect
  useEffect(() => {
    if (!isPolling) return;

    const interval = setInterval(async () => {
      try {
        const currentStatus = await fetchStatus();
        
        // Stop polling if analysis is complete or failed
        if (currentStatus.status === 'completed' || currentStatus.status === 'error') {
          setIsPolling(false);
        }
      } catch (err) {
        console.error('Error polling analysis status:', err);
        setIsPolling(false);
      }
    }, pollInterval);

    return () => clearInterval(interval);
  }, [isPolling, pollInterval, fetchStatus]);

  const getStatusIcon = (statusType: StatusType) => {
    switch (statusType) {
      case 'queued':
        return (
          <div className="w-4 h-4 border-2 border-gray-400 border-t-blue-600 rounded-full animate-spin" />
        );
      case 'analyzing':
        return (
          <div className="w-4 h-4 border-2 border-gray-400 border-t-yellow-500 rounded-full animate-spin" />
        );
      case 'completed':
        return (
          <svg className="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
        );
      case 'error':
        return (
          <svg className="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        );
      default:
        return (
          <div className="w-4 h-4 bg-gray-400 rounded-full" />
        );
    }
  };

  const getStatusColor = (statusType: StatusType) => {
    switch (statusType) {
      case 'queued':
        return 'text-blue-600 dark:text-blue-400';
      case 'analyzing':
        return 'text-yellow-600 dark:text-yellow-400';
      case 'completed':
        return 'text-green-600 dark:text-green-400';
      case 'error':
        return 'text-red-600 dark:text-red-400';
      default:
        return 'text-gray-600 dark:text-gray-400';
    }
  };

  const getStatusMessage = (status: AnalysisProgress) => {
    switch (status.status) {
      case 'queued':
        return 'Analysis queued for processing...';
      case 'analyzing':
        return status.current_stage || 'Analyzing repository...';
      case 'completed':
        return 'Analysis completed successfully';
      case 'error':
        return status.error_details || status.message || 'Analysis failed';
      default:
        return 'Unknown status';
    }
  };

  const formatDuration = (startTime?: string, endTime?: string) => {
    if (!startTime) return null;
    
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const durationMs = end.getTime() - start.getTime();
    const durationSec = Math.floor(durationMs / 1000);
    
    if (durationSec < 60) {
      return `${durationSec}s`;
    } else if (durationSec < 3600) {
      const minutes = Math.floor(durationSec / 60);
      const seconds = durationSec % 60;
      return `${minutes}m ${seconds}s`;
    } else {
      const hours = Math.floor(durationSec / 3600);
      const minutes = Math.floor((durationSec % 3600) / 60);
      return `${hours}h ${minutes}m`;
    }
  };

  const retryAnalysis = async () => {
    try {
      setError(null);
      setIsPolling(true);
      await fetchStatus();
    } catch (err) {
      console.error('Error retrying analysis:', err);
    }
  };

  if (!status && !error) {
    return (
      <div className={`flex items-center space-x-2 ${className}`}>
        <LoadingSpinner size="small" />
        <span className="text-sm text-gray-600 dark:text-gray-400">
          Loading status...
        </span>
      </div>
    );
  }

  return (
    <div className={`space-y-3 ${className}`}>
      {/* Status Header */}
      {status && (
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getStatusIcon(status.status)}
            <div>
              <div className={`font-medium capitalize ${getStatusColor(status.status)}`}>
                {status.status}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {getStatusMessage(status)}
              </div>
            </div>
          </div>
          
          {/* Duration */}
          {status.started_at && (
            <div className="text-xs text-gray-500 dark:text-gray-500">
              {formatDuration(status.started_at, status.completed_at)}
            </div>
          )}
        </div>
      )}

      {/* Progress Bar */}
      {status && status.progress_percentage !== undefined && (
        <div className="space-y-1">
          <div className="flex justify-between text-xs text-gray-600 dark:text-gray-400">
            <span>Progress</span>
            <span>{status.progress_percentage}%</span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <div 
              className={`h-2 rounded-full transition-all duration-300 ${
                status.status === 'error' ? 'bg-red-500' :
                status.status === 'completed' ? 'bg-green-500' :
                'bg-blue-500'
              }`}
              style={{ width: `${Math.max(0, Math.min(100, status.progress_percentage))}%` }}
            />
          </div>
        </div>
      )}

      {/* Current Stage */}
      {status && status.current_stage && status.status === 'analyzing' && (
        <div className="text-sm text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
          <div className="font-medium mb-1">Current Stage:</div>
          <div>{status.current_stage}</div>
        </div>
      )}

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
          <div className="flex items-start space-x-2">
            <svg className="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
            </svg>
            <div className="flex-1">
              <div className="text-sm font-medium text-red-800 dark:text-red-200">
                Analysis Error
              </div>
              <div className="text-sm text-red-700 dark:text-red-300 mt-1">
                {error}
              </div>
              <button
                onClick={retryAnalysis}
                className="mt-2 text-sm text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-200 underline"
              >
                Retry Analysis
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Success Message */}
      {status && status.status === 'completed' && (
        <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
          <div className="flex items-center space-x-2">
            <svg className="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
            <div className="text-sm font-medium text-green-800 dark:text-green-200">
              Analysis completed successfully!
            </div>
          </div>
          {status.completed_at && (
            <div className="text-xs text-green-700 dark:text-green-300 mt-1">
              Completed at {new Date(status.completed_at).toLocaleString()}
            </div>
          )}
        </div>
      )}
    </div>
  );
}