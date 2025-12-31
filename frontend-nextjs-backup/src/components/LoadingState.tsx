'use client';

import { Loader2 } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
  size?: 'small' | 'medium' | 'large';
  fullScreen?: boolean;
  className?: string;
  showSpinner?: boolean;
  children?: React.ReactNode;
}

export default function LoadingState({
  message = 'Loading...',
  size = 'medium',
  fullScreen = false,
  className = '',
  showSpinner = true,
  children
}: LoadingStateProps) {
  const sizeClasses = {
    small: {
      spinner: 'w-4 h-4',
      text: 'text-sm',
      container: 'space-y-2'
    },
    medium: {
      spinner: 'w-8 h-8',
      text: 'text-base',
      container: 'space-y-3'
    },
    large: {
      spinner: 'w-12 h-12',
      text: 'text-lg',
      container: 'space-y-4'
    }
  };

  const containerClasses = fullScreen
    ? 'min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center'
    : 'flex items-center justify-center p-8';

  return (
    <div className={`${containerClasses} ${className}`}>
      <div className={`flex flex-col items-center text-center ${sizeClasses[size].container}`}>
        {showSpinner && (
          <Loader2 className={`${sizeClasses[size].spinner} text-blue-600 dark:text-blue-400 animate-spin`} />
        )}
        
        {message && (
          <p className={`${sizeClasses[size].text} text-gray-600 dark:text-gray-400 font-medium`}>
            {message}
          </p>
        )}
        
        {children && (
          <div className="mt-4">
            {children}
          </div>
        )}
      </div>
    </div>
  );
}

// Skeleton loading component for content placeholders
export function SkeletonLoader({ 
  lines = 3, 
  className = '' 
}: { 
  lines?: number; 
  className?: string; 
}) {
  return (
    <div className={`animate-pulse space-y-3 ${className}`}>
      {Array.from({ length: lines }).map((_, index) => (
        <div
          key={index}
          className={`h-4 bg-gray-200 dark:bg-gray-700 rounded ${
            index === lines - 1 ? 'w-3/4' : 'w-full'
          }`}
        />
      ))}
    </div>
  );
}

// Card skeleton for loading cards
export function CardSkeleton({ className = '' }: { className?: string }) {
  return (
    <div className={`animate-pulse ${className}`}>
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <div className="space-y-4">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/4"></div>
          <div className="space-y-2">
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded"></div>
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-5/6"></div>
          </div>
          <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-1/3"></div>
        </div>
      </div>
    </div>
  );
}

// Button loading state
export function LoadingButton({
  children,
  loading = false,
  disabled = false,
  className = '',
  ...props
}: {
  children: React.ReactNode;
  loading?: boolean;
  disabled?: boolean;
  className?: string;
  [key: string]: any;
}) {
  return (
    <button
      disabled={loading || disabled}
      className={`inline-flex items-center justify-center space-x-2 ${
        loading || disabled
          ? 'opacity-50 cursor-not-allowed'
          : ''
      } ${className}`}
      {...props}
    >
      {loading && (
        <Loader2 className="w-4 h-4 animate-spin" />
      )}
      <span>{children}</span>
    </button>
  );
}