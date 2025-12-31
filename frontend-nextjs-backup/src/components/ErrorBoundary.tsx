'use client';

import React, { Component, ReactNode, useState } from 'react';

interface ErrorDetailsToggleProps {
  error: Error;
  errorInfo?: React.ErrorInfo;
}

function ErrorDetailsToggle({ error, errorInfo }: ErrorDetailsToggleProps) {
  const [showDetails, setShowDetails] = useState(false);

  return (
    <div className="mb-6 text-left">
      <button
        onClick={() => setShowDetails(!showDetails)}
        className="flex items-center space-x-2 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
      >
        <svg
          className={`w-4 h-4 transition-transform ${showDetails ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        <span>{showDetails ? 'Hide' : 'Show'} technical details</span>
      </button>
      
      {showDetails && (
        <div className="mt-3 p-4 bg-gray-100 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="space-y-3">
            {/* Error Information */}
            <div>
              <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Error Information
              </h4>
              <div className="text-xs font-mono text-gray-700 dark:text-gray-300 space-y-1">
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Type:</span>{' '}
                  <span className="text-red-600 dark:text-red-400">{error.name}</span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Message:</span>{' '}
                  <span>{error.message}</span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-gray-400">Timestamp:</span>{' '}
                  <span>{new Date().toISOString()}</span>
                </div>
              </div>
            </div>

            {/* Stack Trace */}
            {error.stack && (
              <div>
                <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Stack Trace
                </h4>
                <pre className="text-xs bg-gray-200 dark:bg-gray-800 p-3 rounded overflow-auto max-h-40 text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                  {error.stack}
                </pre>
              </div>
            )}

            {/* Component Stack */}
            {errorInfo?.componentStack && (
              <div>
                <h4 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Component Stack
                </h4>
                <pre className="text-xs bg-gray-200 dark:bg-gray-800 p-3 rounded overflow-auto max-h-32 text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                  {errorInfo.componentStack}
                </pre>
              </div>
            )}

            {/* Copy to Clipboard */}
            <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => {
                  const errorDetails = {
                    error: {
                      name: error.name,
                      message: error.message,
                      stack: error.stack
                    },
                    componentStack: errorInfo?.componentStack,
                    timestamp: new Date().toISOString(),
                    userAgent: navigator.userAgent,
                    url: window.location.href
                  };
                  navigator.clipboard.writeText(JSON.stringify(errorDetails, null, 2));
                }}
                className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 underline"
              >
                Copy error details to clipboard
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
  errorInfo?: React.ErrorInfo;
}

interface ErrorBoundaryProps {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
}

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    this.setState({
      error,
      errorInfo
    });

    // Log error to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('ErrorBoundary caught an error:', error, errorInfo);
    }

    // Call optional error handler
    if (this.props.onError) {
      this.props.onError(error, errorInfo);
    }
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: undefined, errorInfo: undefined });
  };

  render() {
    if (this.state.hasError) {
      // Custom fallback UI
      if (this.props.fallback) {
        return this.props.fallback;
      }

      // Default error UI
      return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
            <div className="text-center">
              {/* Error Icon */}
              <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 dark:bg-red-900/20 mb-4">
                <svg
                  className="h-6 w-6 text-red-600 dark:text-red-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
                  />
                </svg>
              </div>

              {/* Error Title */}
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Something went wrong
              </h2>

              {/* Error Message */}
              <p className="text-gray-600 dark:text-gray-400 mb-6">
                An unexpected error occurred while loading this page. Please try again.
              </p>

              {/* Error Details Toggle */}
              {this.state.error && (
                <ErrorDetailsToggle 
                  error={this.state.error} 
                  errorInfo={this.state.errorInfo}
                />
              )}

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row gap-3">
                <button
                  onClick={this.handleRetry}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors"
                >
                  Try Again
                </button>
                <button
                  onClick={() => window.location.reload()}
                  className="flex-1 px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-gray-100 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 focus:ring-2 focus:ring-gray-500 focus:ring-offset-2 transition-colors"
                >
                  Reload Page
                </button>
              </div>

              {/* Help Text */}
              <p className="mt-4 text-xs text-gray-500 dark:text-gray-400">
                If this problem persists, please contact support.
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// Hook version for functional components
export function useErrorBoundary() {
  const [error, setError] = React.useState<Error | null>(null);

  const resetError = React.useCallback(() => {
    setError(null);
  }, []);

  const captureError = React.useCallback((error: Error) => {
    setError(error);
  }, []);

  React.useEffect(() => {
    if (error) {
      throw error;
    }
  }, [error]);

  return { captureError, resetError };
}