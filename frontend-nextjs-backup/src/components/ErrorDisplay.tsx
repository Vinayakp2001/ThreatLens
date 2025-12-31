'use client';

import { useState } from 'react';
import { AlertTriangle, RefreshCw, Copy, ChevronDown, ChevronRight } from 'lucide-react';
import { APIError, ValidationError, NetworkError } from '@/lib/types';
import { isAPIError, isValidationError, isNetworkError } from '@/lib/api';

interface ErrorDisplayProps {
  error: Error | string;
  title?: string;
  onRetry?: () => void;
  onDismiss?: () => void;
  showRetry?: boolean;
  className?: string;
}

export default function ErrorDisplay({
  error,
  title = 'An error occurred',
  onRetry,
  onDismiss,
  showRetry = true,
  className = ''
}: ErrorDisplayProps) {
  const [showDetails, setShowDetails] = useState(false);

  const errorObj = typeof error === 'string' ? new Error(error) : error;
  
  const getUserFriendlyMessage = (error: Error): string => {
    if (isNetworkError(error)) {
      return 'Unable to connect to the server. Please check your internet connection and try again.';
    }
    
    if (isValidationError(error)) {
      return `Please check your input: ${error.message}`;
    }
    
    if (isAPIError(error)) {
      switch (error.status) {
        case 400:
          return 'The request was invalid. Please check your input and try again.';
        case 401:
          return 'Authentication required. Please log in and try again.';
        case 403:
          return 'You do not have permission to perform this action.';
        case 404:
          return 'The requested resource was not found.';
        case 409:
          return 'There was a conflict with the current state. Please refresh and try again.';
        case 413:
          return 'The file or request is too large. Please try with a smaller file.';
        case 422:
          return 'The data provided is invalid. Please check your input.';
        case 429:
          return 'Too many requests. Please wait a moment and try again.';
        case 500:
          return 'A server error occurred. Please try again later.';
        case 502:
        case 503:
          return 'The service is temporarily unavailable. Please try again later.';
        case 504:
          return 'The request timed out. Please try again.';
        default:
          return error.message || 'An unexpected error occurred.';
      }
    }
    
    return error.message || 'An unexpected error occurred.';
  };

  const getErrorIcon = (error: Error) => {
    if (isNetworkError(error)) {
      return (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071c3.904-3.905 10.236-3.905 14.141 0M1.394 9.393c5.857-5.857 15.355-5.857 21.213 0" />
        </svg>
      );
    }
    
    if (isValidationError(error)) {
      return (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
        </svg>
      );
    }
    
    return <AlertTriangle className="w-5 h-5" />;
  };

  const getErrorColor = (error: Error) => {
    if (isNetworkError(error)) {
      return {
        bg: 'bg-orange-50 dark:bg-orange-900/20',
        border: 'border-orange-200 dark:border-orange-800',
        icon: 'text-orange-500',
        title: 'text-orange-800 dark:text-orange-200',
        text: 'text-orange-700 dark:text-orange-300'
      };
    }
    
    if (isValidationError(error)) {
      return {
        bg: 'bg-yellow-50 dark:bg-yellow-900/20',
        border: 'border-yellow-200 dark:border-yellow-800',
        icon: 'text-yellow-500',
        title: 'text-yellow-800 dark:text-yellow-200',
        text: 'text-yellow-700 dark:text-yellow-300'
      };
    }
    
    return {
      bg: 'bg-red-50 dark:bg-red-900/20',
      border: 'border-red-200 dark:border-red-800',
      icon: 'text-red-500',
      title: 'text-red-800 dark:text-red-200',
      text: 'text-red-700 dark:text-red-300'
    };
  };

  const copyErrorDetails = () => {
    const details = {
      message: errorObj.message,
      name: errorObj.name,
      stack: errorObj.stack,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href,
      ...(isAPIError(errorObj) && {
        status: errorObj.status,
        code: errorObj.code,
        details: errorObj.details
      })
    };
    
    navigator.clipboard.writeText(JSON.stringify(details, null, 2));
  };

  const colors = getErrorColor(errorObj);

  return (
    <div className={`rounded-lg border ${colors.bg} ${colors.border} p-4 ${className}`}>
      <div className="flex items-start space-x-3">
        <div className={`flex-shrink-0 ${colors.icon} mt-0.5`}>
          {getErrorIcon(errorObj)}
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <h3 className={`text-sm font-medium ${colors.title}`}>
                {title}
              </h3>
              <p className={`mt-1 text-sm ${colors.text}`}>
                {getUserFriendlyMessage(errorObj)}
              </p>
            </div>
            
            {onDismiss && (
              <button
                onClick={onDismiss}
                className={`ml-3 flex-shrink-0 ${colors.icon} hover:opacity-70 transition-opacity`}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            )}
          </div>

          {/* Action Buttons */}
          <div className="mt-3 flex items-center space-x-3">
            {showRetry && onRetry && (
              <button
                onClick={onRetry}
                className={`inline-flex items-center space-x-1 text-sm ${colors.title} hover:opacity-80 transition-opacity`}
              >
                <RefreshCw className="w-4 h-4" />
                <span>Try Again</span>
              </button>
            )}
            
            <button
              onClick={() => setShowDetails(!showDetails)}
              className={`inline-flex items-center space-x-1 text-sm ${colors.title} hover:opacity-80 transition-opacity`}
            >
              {showDetails ? (
                <ChevronDown className="w-4 h-4" />
              ) : (
                <ChevronRight className="w-4 h-4" />
              )}
              <span>{showDetails ? 'Hide' : 'Show'} Details</span>
            </button>
          </div>

          {/* Error Details */}
          {showDetails && (
            <div className="mt-4 p-3 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700">
              <div className="space-y-3">
                <div>
                  <h4 className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                    Error Details
                  </h4>
                  <div className="mt-1 text-xs font-mono text-gray-600 dark:text-gray-400 space-y-1">
                    <div>
                      <span className="text-gray-500">Type:</span> {errorObj.name}
                    </div>
                    <div>
                      <span className="text-gray-500">Message:</span> {errorObj.message}
                    </div>
                    {isAPIError(errorObj) && (
                      <>
                        <div>
                          <span className="text-gray-500">Status:</span> {errorObj.status}
                        </div>
                        {errorObj.code && (
                          <div>
                            <span className="text-gray-500">Code:</span> {errorObj.code}
                          </div>
                        )}
                      </>
                    )}
                    <div>
                      <span className="text-gray-500">Time:</span> {new Date().toLocaleString()}
                    </div>
                  </div>
                </div>

                {errorObj.stack && (
                  <div>
                    <h4 className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                      Stack Trace
                    </h4>
                    <pre className="mt-1 text-xs bg-gray-100 dark:bg-gray-900 p-2 rounded overflow-auto max-h-32 text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {errorObj.stack}
                    </pre>
                  </div>
                )}

                {isAPIError(errorObj) && errorObj.details && (
                  <div>
                    <h4 className="text-xs font-semibold text-gray-900 dark:text-gray-100 uppercase tracking-wide">
                      Additional Details
                    </h4>
                    <pre className="mt-1 text-xs bg-gray-100 dark:bg-gray-900 p-2 rounded overflow-auto max-h-32 text-gray-700 dark:text-gray-300">
                      {JSON.stringify(errorObj.details, null, 2)}
                    </pre>
                  </div>
                )}

                <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                  <button
                    onClick={copyErrorDetails}
                    className="inline-flex items-center space-x-1 text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
                  >
                    <Copy className="w-3 h-3" />
                    <span>Copy Error Details</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Utility component for inline error messages
export function InlineError({ 
  message, 
  className = '' 
}: { 
  message: string; 
  className?: string; 
}) {
  return (
    <div className={`flex items-center space-x-2 text-sm text-red-600 dark:text-red-400 ${className}`}>
      <AlertTriangle className="w-4 h-4 flex-shrink-0" />
      <span>{message}</span>
    </div>
  );
}

// Utility component for success messages
export function SuccessMessage({ 
  message, 
  onDismiss,
  className = '' 
}: { 
  message: string; 
  onDismiss?: () => void;
  className?: string; 
}) {
  return (
    <div className={`flex items-center justify-between bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3 ${className}`}>
      <div className="flex items-center space-x-2">
        <svg className="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
        <span className="text-sm text-green-800 dark:text-green-200">{message}</span>
      </div>
      {onDismiss && (
        <button
          onClick={onDismiss}
          className="text-green-500 hover:text-green-700 dark:hover:text-green-300 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
    </div>
  );
}