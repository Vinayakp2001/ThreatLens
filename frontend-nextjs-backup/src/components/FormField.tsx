'use client';

import { useState, useEffect } from 'react';
import { AlertCircle, CheckCircle, Eye, EyeOff } from 'lucide-react';

interface ValidationRule {
  test: (value: string) => boolean;
  message: string;
}

interface FormFieldProps {
  label: string;
  type?: 'text' | 'email' | 'url' | 'password' | 'textarea';
  value: string;
  onChange: (value: string) => void;
  onBlur?: () => void;
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  error?: string;
  success?: string;
  validationRules?: ValidationRule[];
  validateOnChange?: boolean;
  validateOnBlur?: boolean;
  showValidation?: boolean;
  className?: string;
  inputClassName?: string;
  rows?: number;
  maxLength?: number;
  autoComplete?: string;
  id?: string;
}

export default function FormField({
  label,
  type = 'text',
  value,
  onChange,
  onBlur,
  placeholder,
  required = false,
  disabled = false,
  error,
  success,
  validationRules = [],
  validateOnChange = false,
  validateOnBlur = true,
  showValidation = true,
  className = '',
  inputClassName = '',
  rows = 3,
  maxLength,
  autoComplete,
  id
}: FormFieldProps) {
  const [internalError, setInternalError] = useState<string>('');
  const [touched, setTouched] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const fieldId = id || `field-${label.toLowerCase().replace(/\s+/g, '-')}`;
  
  // Validate field value
  const validateField = (fieldValue: string): string => {
    // Required validation
    if (required && !fieldValue.trim()) {
      return `${label} is required`;
    }

    // Custom validation rules
    for (const rule of validationRules) {
      if (fieldValue && !rule.test(fieldValue)) {
        return rule.message;
      }
    }

    // Built-in type validation
    if (fieldValue) {
      switch (type) {
        case 'email':
          const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
          if (!emailRegex.test(fieldValue)) {
            return 'Please enter a valid email address';
          }
          break;
        case 'url':
          try {
            new URL(fieldValue);
          } catch {
            return 'Please enter a valid URL';
          }
          break;
      }
    }

    return '';
  };

  // Handle value changes
  const handleChange = (newValue: string) => {
    onChange(newValue);
    
    if (validateOnChange && touched) {
      const validationError = validateField(newValue);
      setInternalError(validationError);
    }
  };

  // Handle blur events
  const handleBlur = () => {
    setTouched(true);
    
    if (validateOnBlur) {
      const validationError = validateField(value);
      setInternalError(validationError);
    }
    
    if (onBlur) {
      onBlur();
    }
  };

  // Clear internal error when external error is provided
  useEffect(() => {
    if (error) {
      setInternalError('');
    }
  }, [error]);

  const displayError = error || internalError;
  const hasError = Boolean(displayError && touched);
  const hasSuccess = Boolean(success && !hasError && value && touched);

  const getFieldClasses = () => {
    const baseClasses = 'w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors';
    
    if (hasError) {
      return `${baseClasses} border-red-500 bg-red-50 dark:bg-red-900/20 text-red-900 dark:text-red-100 placeholder-red-400`;
    }
    
    if (hasSuccess) {
      return `${baseClasses} border-green-500 bg-green-50 dark:bg-green-900/20 text-green-900 dark:text-green-100`;
    }
    
    return `${baseClasses} border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400`;
  };

  const renderInput = () => {
    const commonProps = {
      id: fieldId,
      value,
      onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => handleChange(e.target.value),
      onBlur: handleBlur,
      placeholder,
      disabled,
      required,
      maxLength,
      autoComplete,
      className: `${getFieldClasses()} ${inputClassName}`,
      'aria-invalid': hasError,
      'aria-describedby': hasError ? `${fieldId}-error` : hasSuccess ? `${fieldId}-success` : undefined
    };

    if (type === 'textarea') {
      return (
        <textarea
          {...commonProps}
          rows={rows}
        />
      );
    }

    if (type === 'password') {
      return (
        <div className="relative">
          <input
            {...commonProps}
            type={showPassword ? 'text' : 'password'}
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            tabIndex={-1}
          >
            {showPassword ? (
              <EyeOff className="w-4 h-4" />
            ) : (
              <Eye className="w-4 h-4" />
            )}
          </button>
        </div>
      );
    }

    return (
      <input
        {...commonProps}
        type={type}
      />
    );
  };

  return (
    <div className={`space-y-1 ${className}`}>
      {/* Label */}
      <label 
        htmlFor={fieldId}
        className="block text-sm font-medium text-gray-700 dark:text-gray-300"
      >
        {label}
        {required && (
          <span className="text-red-500 ml-1" aria-label="required">*</span>
        )}
      </label>

      {/* Input Field */}
      <div className="relative">
        {renderInput()}
        
        {/* Status Icon */}
        {showValidation && (hasError || hasSuccess) && (
          <div className="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none">
            {hasError ? (
              <AlertCircle className="w-4 h-4 text-red-500" />
            ) : hasSuccess ? (
              <CheckCircle className="w-4 h-4 text-green-500" />
            ) : null}
          </div>
        )}
      </div>

      {/* Character Count */}
      {maxLength && (
        <div className="text-xs text-gray-500 dark:text-gray-400 text-right">
          {value.length}/{maxLength}
        </div>
      )}

      {/* Error Message */}
      {hasError && showValidation && (
        <div 
          id={`${fieldId}-error`}
          className="flex items-start space-x-1 text-sm text-red-600 dark:text-red-400"
          role="alert"
        >
          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{displayError}</span>
        </div>
      )}

      {/* Success Message */}
      {hasSuccess && showValidation && (
        <div 
          id={`${fieldId}-success`}
          className="flex items-start space-x-1 text-sm text-green-600 dark:text-green-400"
        >
          <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>{success}</span>
        </div>
      )}
    </div>
  );
}

// Utility function to create common validation rules
export const validationRules = {
  required: (fieldName: string): ValidationRule => ({
    test: (value: string) => value.trim().length > 0,
    message: `${fieldName} is required`
  }),

  minLength: (min: number): ValidationRule => ({
    test: (value: string) => value.length >= min,
    message: `Must be at least ${min} characters long`
  }),

  maxLength: (max: number): ValidationRule => ({
    test: (value: string) => value.length <= max,
    message: `Must be no more than ${max} characters long`
  }),

  email: (): ValidationRule => ({
    test: (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
    message: 'Please enter a valid email address'
  }),

  url: (): ValidationRule => ({
    test: (value: string) => {
      try {
        new URL(value);
        return true;
      } catch {
        return false;
      }
    },
    message: 'Please enter a valid URL'
  }),

  gitUrl: (): ValidationRule => ({
    test: (value: string) => {
      try {
        const url = new URL(value);
        return /^https?:\/\/(github\.com|gitlab\.com|bitbucket\.org|git\.)/.test(value);
      } catch {
        return false;
      }
    },
    message: 'Please enter a valid Git repository URL (GitHub, GitLab, Bitbucket, etc.)'
  }),

  pattern: (regex: RegExp, message: string): ValidationRule => ({
    test: (value: string) => regex.test(value),
    message
  }),

  custom: (testFn: (value: string) => boolean, message: string): ValidationRule => ({
    test: testFn,
    message
  })
};