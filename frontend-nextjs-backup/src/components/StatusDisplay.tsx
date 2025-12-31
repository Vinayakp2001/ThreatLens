'use client';

import { CheckCircle, AlertCircle, Clock, Loader2, XCircle, Info } from 'lucide-react';

export type StatusType = 'idle' | 'loading' | 'success' | 'error' | 'warning' | 'info';

interface StatusDisplayProps {
  status: StatusType;
  message?: string;
  size?: 'small' | 'medium' | 'large';
  showIcon?: boolean;
  showMessage?: boolean;
  className?: string;
  animate?: boolean;
}

export default function StatusDisplay({
  status,
  message,
  size = 'medium',
  showIcon = true,
  showMessage = true,
  className = '',
  animate = true
}: StatusDisplayProps) {
  const sizeClasses = {
    small: {
      icon: 'w-4 h-4',
      text: 'text-sm',
      container: 'space-x-1'
    },
    medium: {
      icon: 'w-5 h-5',
      text: 'text-base',
      container: 'space-x-2'
    },
    large: {
      icon: 'w-6 h-6',
      text: 'text-lg',
      container: 'space-x-3'
    }
  };

  const getStatusConfig = (status: StatusType) => {
    switch (status) {
      case 'loading':
        return {
          icon: Loader2,
          color: 'text-blue-600 dark:text-blue-400',
          bgColor: 'bg-blue-50 dark:bg-blue-900/20',
          borderColor: 'border-blue-200 dark:border-blue-800',
          animate: animate,
          defaultMessage: 'Loading...'
        };
      case 'success':
        return {
          icon: CheckCircle,
          color: 'text-green-600 dark:text-green-400',
          bgColor: 'bg-green-50 dark:bg-green-900/20',
          borderColor: 'border-green-200 dark:border-green-800',
          animate: false,
          defaultMessage: 'Success'
        };
      case 'error':
        return {
          icon: XCircle,
          color: 'text-red-600 dark:text-red-400',
          bgColor: 'bg-red-50 dark:bg-red-900/20',
          borderColor: 'border-red-200 dark:border-red-800',
          animate: false,
          defaultMessage: 'Error'
        };
      case 'warning':
        return {
          icon: AlertCircle,
          color: 'text-yellow-600 dark:text-yellow-400',
          bgColor: 'bg-yellow-50 dark:bg-yellow-900/20',
          borderColor: 'border-yellow-200 dark:border-yellow-800',
          animate: false,
          defaultMessage: 'Warning'
        };
      case 'info':
        return {
          icon: Info,
          color: 'text-blue-600 dark:text-blue-400',
          bgColor: 'bg-blue-50 dark:bg-blue-900/20',
          borderColor: 'border-blue-200 dark:border-blue-800',
          animate: false,
          defaultMessage: 'Information'
        };
      case 'idle':
      default:
        return {
          icon: Clock,
          color: 'text-gray-600 dark:text-gray-400',
          bgColor: 'bg-gray-50 dark:bg-gray-900/20',
          borderColor: 'border-gray-200 dark:border-gray-800',
          animate: false,
          defaultMessage: 'Ready'
        };
    }
  };

  const config = getStatusConfig(status);
  const Icon = config.icon;
  const displayMessage = message || config.defaultMessage;

  return (
    <div className={`inline-flex items-center ${sizeClasses[size].container} ${className}`}>
      {showIcon && (
        <Icon 
          className={`${sizeClasses[size].icon} ${config.color} ${
            config.animate ? 'animate-spin' : ''
          }`}
        />
      )}
      {showMessage && displayMessage && (
        <span className={`${sizeClasses[size].text} ${config.color} font-medium`}>
          {displayMessage}
        </span>
      )}
    </div>
  );
}

// Badge variant for compact status display
export function StatusBadge({
  status,
  message,
  size = 'small',
  className = ''
}: Omit<StatusDisplayProps, 'showIcon' | 'showMessage'>) {
  const getStatusConfig = (status: StatusType) => {
    switch (status) {
      case 'loading':
        return {
          color: 'text-blue-600 dark:text-blue-400',
          bgColor: 'bg-blue-50 dark:bg-blue-900/20',
          borderColor: 'border-blue-200 dark:border-blue-800',
          defaultMessage: 'Loading...'
        };
      case 'success':
        return {
          color: 'text-green-600 dark:text-green-400',
          bgColor: 'bg-green-50 dark:bg-green-900/20',
          borderColor: 'border-green-200 dark:border-green-800',
          defaultMessage: 'Success'
        };
      case 'error':
        return {
          color: 'text-red-600 dark:text-red-400',
          bgColor: 'bg-red-50 dark:bg-red-900/20',
          borderColor: 'border-red-200 dark:border-red-800',
          defaultMessage: 'Error'
        };
      case 'warning':
        return {
          color: 'text-yellow-600 dark:text-yellow-400',
          bgColor: 'bg-yellow-50 dark:bg-yellow-900/20',
          borderColor: 'border-yellow-200 dark:border-yellow-800',
          defaultMessage: 'Warning'
        };
      case 'info':
        return {
          color: 'text-blue-600 dark:text-blue-400',
          bgColor: 'bg-blue-50 dark:bg-blue-900/20',
          borderColor: 'border-blue-200 dark:border-blue-800',
          defaultMessage: 'Information'
        };
      case 'idle':
      default:
        return {
          color: 'text-gray-600 dark:text-gray-400',
          bgColor: 'bg-gray-50 dark:bg-gray-900/20',
          borderColor: 'border-gray-200 dark:border-gray-800',
          defaultMessage: 'Ready'
        };
    }
  };

  const config = getStatusConfig(status);
  const displayMessage = message || config.defaultMessage;

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.bgColor} ${config.color} ${config.borderColor} border ${className}`}>
      {displayMessage}
    </span>
  );
}

// Pulse variant for loading states
export function StatusPulse({
  status,
  message,
  size = 'medium',
  className = ''
}: StatusDisplayProps) {
  const getStatusConfig = (status: StatusType) => {
    switch (status) {
      case 'loading':
        return {
          color: 'text-blue-600 dark:text-blue-400',
          bgColor: 'bg-blue-600',
          defaultMessage: 'Loading...'
        };
      case 'success':
        return {
          color: 'text-green-600 dark:text-green-400',
          bgColor: 'bg-green-600',
          defaultMessage: 'Success'
        };
      case 'error':
        return {
          color: 'text-red-600 dark:text-red-400',
          bgColor: 'bg-red-600',
          defaultMessage: 'Error'
        };
      case 'warning':
        return {
          color: 'text-yellow-600 dark:text-yellow-400',
          bgColor: 'bg-yellow-600',
          defaultMessage: 'Warning'
        };
      case 'info':
        return {
          color: 'text-blue-600 dark:text-blue-400',
          bgColor: 'bg-blue-600',
          defaultMessage: 'Information'
        };
      case 'idle':
      default:
        return {
          color: 'text-gray-600 dark:text-gray-400',
          bgColor: 'bg-gray-600',
          defaultMessage: 'Ready'
        };
    }
  };

  const config = getStatusConfig(status);
  const sizeClasses = {
    small: 'w-2 h-2',
    medium: 'w-3 h-3',
    large: 'w-4 h-4'
  };

  return (
    <div className={`inline-flex items-center space-x-2 ${className}`}>
      <div className={`${sizeClasses[size]} rounded-full ${config.bgColor} ${status === 'loading' ? 'animate-pulse' : ''}`} />
      {message && (
        <span className={`text-sm ${config.color}`}>
          {message}
        </span>
      )}
    </div>
  );
}