'use client';

import { AnalysisStatus } from '@/lib/types';

interface StatusIndicatorProps {
  status: AnalysisStatus;
  size?: 'small' | 'medium' | 'large';
  showText?: boolean;
  animated?: boolean;
  className?: string;
}

export default function StatusIndicator({
  status,
  size = 'medium',
  showText = true,
  animated = true,
  className = ''
}: StatusIndicatorProps) {
  const getStatusConfig = (status: AnalysisStatus) => {
    switch (status) {
      case 'queued':
        return {
          color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
          dotColor: 'bg-blue-500',
          text: 'Queued',
          icon: (
            <div className={`border-2 border-gray-400 border-t-blue-600 rounded-full ${
              animated ? 'animate-spin' : ''
            } ${
              size === 'small' ? 'w-3 h-3' : size === 'large' ? 'w-5 h-5' : 'w-4 h-4'
            }`} />
          )
        };
      case 'analyzing':
        return {
          color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400',
          dotColor: 'bg-yellow-500',
          text: 'Analyzing',
          icon: (
            <div className={`border-2 border-gray-400 border-t-yellow-500 rounded-full ${
              animated ? 'animate-spin' : ''
            } ${
              size === 'small' ? 'w-3 h-3' : size === 'large' ? 'w-5 h-5' : 'w-4 h-4'
            }`} />
          )
        };
      case 'completed':
        return {
          color: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
          dotColor: 'bg-green-500',
          text: 'Completed',
          icon: (
            <svg className={`text-green-500 ${
              size === 'small' ? 'w-3 h-3' : size === 'large' ? 'w-5 h-5' : 'w-4 h-4'
            }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          )
        };
      case 'error':
        return {
          color: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400',
          dotColor: 'bg-red-500',
          text: 'Error',
          icon: (
            <svg className={`text-red-500 ${
              size === 'small' ? 'w-3 h-3' : size === 'large' ? 'w-5 h-5' : 'w-4 h-4'
            }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          )
        };
      default:
        return {
          color: 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400',
          dotColor: 'bg-gray-400',
          text: 'Unknown',
          icon: (
            <div className={`rounded-full ${
              size === 'small' ? 'w-3 h-3' : size === 'large' ? 'w-5 h-5' : 'w-4 h-4'
            } bg-gray-400`} />
          )
        };
    }
  };

  const config = getStatusConfig(status);
  const sizeClasses = {
    small: 'px-2 py-0.5 text-xs',
    medium: 'px-2.5 py-0.5 text-xs',
    large: 'px-3 py-1 text-sm'
  };

  if (showText) {
    return (
      <span className={`inline-flex items-center space-x-1.5 rounded-full font-medium ${config.color} ${sizeClasses[size]} ${className}`}>
        {config.icon}
        <span>{config.text}</span>
      </span>
    );
  }

  return (
    <div className={`inline-flex items-center ${className}`} title={config.text}>
      {config.icon}
    </div>
  );
}

// Utility function to get just the dot indicator
export function StatusDot({ 
  status, 
  size = 'medium', 
  animated = true, 
  className = '' 
}: {
  status: AnalysisStatus;
  size?: 'small' | 'medium' | 'large';
  animated?: boolean;
  className?: string;
}) {
  const dotSize = {
    small: 'w-2 h-2',
    medium: 'w-3 h-3',
    large: 'w-4 h-4'
  };

  const getColor = (status: AnalysisStatus) => {
    switch (status) {
      case 'queued':
        return 'bg-blue-500';
      case 'analyzing':
        return `bg-yellow-500 ${animated ? 'animate-pulse' : ''}`;
      case 'completed':
        return 'bg-green-500';
      case 'error':
        return 'bg-red-500';
      default:
        return 'bg-gray-400';
    }
  };

  return (
    <div 
      className={`rounded-full ${dotSize[size]} ${getColor(status)} ${className}`}
      title={status.charAt(0).toUpperCase() + status.slice(1)}
    />
  );
}