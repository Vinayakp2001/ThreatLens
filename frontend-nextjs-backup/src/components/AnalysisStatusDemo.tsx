'use client';

import { useState } from 'react';
import AnalysisStatus from './AnalysisStatus';
import StatusIndicator from './StatusIndicator';
import { AnalysisStatus as StatusType, AnalysisProgress } from '@/lib/types';

/**
 * Demo component to showcase AnalysisStatus functionality
 * This component demonstrates all the different states and features
 */
export default function AnalysisStatusDemo() {
  const [selectedStatus, setSelectedStatus] = useState<StatusType>('queued');
  const [showDemo, setShowDemo] = useState(false);

  const demoStatuses: { status: StatusType; label: string }[] = [
    { status: 'queued', label: 'Queued' },
    { status: 'analyzing', label: 'Analyzing' },
    { status: 'completed', label: 'Completed' },
    { status: 'error', label: 'Error' }
  ];

  const mockProgress: AnalysisProgress = {
    analysis_id: 'demo-analysis-123',
    repo_id: 'demo-repo-456',
    status: selectedStatus,
    current_stage: selectedStatus === 'analyzing' ? 'Analyzing code structure and dependencies...' : undefined,
    progress_percentage: selectedStatus === 'analyzing' ? 65 : selectedStatus === 'completed' ? 100 : undefined,
    message: selectedStatus === 'error' ? 'Repository analysis failed' : undefined,
    error_details: selectedStatus === 'error' ? 'Unable to access repository. Please check the URL and try again.' : undefined,
    started_at: new Date(Date.now() - 120000).toISOString(), // 2 minutes ago
    completed_at: selectedStatus === 'completed' ? new Date().toISOString() : undefined
  };

  const handleStatusChange = (status: AnalysisProgress) => {
    console.log('Status changed:', status);
  };

  const handleComplete = (status: AnalysisProgress) => {
    console.log('Analysis completed:', status);
  };

  const handleError = (error: string) => {
    console.log('Analysis error:', error);
  };

  if (!showDemo) {
    return (
      <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border-2 border-dashed border-gray-300 dark:border-gray-600">
        <div className="text-center">
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-2">
            AnalysisStatus Component Demo
          </h3>
          <p className="text-gray-600 dark:text-gray-400 mb-4">
            Click to see the AnalysisStatus component in action with different states
          </p>
          <button
            onClick={() => setShowDemo(true)}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            Show Demo
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
          AnalysisStatus Component Demo
        </h3>
        <button
          onClick={() => setShowDemo(false)}
          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Status Selector */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Select Status to Demo:
        </label>
        <div className="flex flex-wrap gap-2">
          {demoStatuses.map(({ status, label }) => (
            <button
              key={status}
              onClick={() => setSelectedStatus(status)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                selectedStatus === status
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Status Indicators Row */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Status Indicators:
        </label>
        <div className="flex items-center space-x-4">
          <StatusIndicator status={selectedStatus} size="small" />
          <StatusIndicator status={selectedStatus} size="medium" />
          <StatusIndicator status={selectedStatus} size="large" />
          <StatusIndicator status={selectedStatus} showText={false} />
        </div>
      </div>

      {/* Main AnalysisStatus Component */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Full AnalysisStatus Component:
        </label>
        <div className="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg">
          {/* Mock the AnalysisStatus component with static data */}
          <div className="space-y-3">
            {/* Status Header */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <StatusIndicator status={selectedStatus} showText={false} />
                <div>
                  <div className={`font-medium capitalize ${
                    selectedStatus === 'completed' ? 'text-green-600 dark:text-green-400' :
                    selectedStatus === 'analyzing' ? 'text-yellow-600 dark:text-yellow-400' :
                    selectedStatus === 'error' ? 'text-red-600 dark:text-red-400' :
                    'text-blue-600 dark:text-blue-400'
                  }`}>
                    {selectedStatus}
                  </div>
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    {selectedStatus === 'queued' && 'Analysis queued for processing...'}
                    {selectedStatus === 'analyzing' && 'Analyzing code structure and dependencies...'}
                    {selectedStatus === 'completed' && 'Analysis completed successfully'}
                    {selectedStatus === 'error' && 'Repository analysis failed'}
                  </div>
                </div>
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-500">
                2m 0s
              </div>
            </div>

            {/* Progress Bar */}
            {(selectedStatus === 'analyzing' || selectedStatus === 'completed') && (
              <div className="space-y-1">
                <div className="flex justify-between text-xs text-gray-600 dark:text-gray-400">
                  <span>Progress</span>
                  <span>{selectedStatus === 'analyzing' ? '65%' : '100%'}</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full transition-all duration-300 ${
                      selectedStatus === 'completed' ? 'bg-green-500' : 'bg-blue-500'
                    }`}
                    style={{ width: selectedStatus === 'analyzing' ? '65%' : '100%' }}
                  />
                </div>
              </div>
            )}

            {/* Current Stage */}
            {selectedStatus === 'analyzing' && (
              <div className="text-sm text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 rounded-lg p-3">
                <div className="font-medium mb-1">Current Stage:</div>
                <div>Analyzing code structure and dependencies...</div>
              </div>
            )}

            {/* Error Display */}
            {selectedStatus === 'error' && (
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
                      Unable to access repository. Please check the URL and try again.
                    </div>
                    <button className="mt-2 text-sm text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-200 underline">
                      Retry Analysis
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Success Message */}
            {selectedStatus === 'completed' && (
              <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3">
                <div className="flex items-center space-x-2">
                  <svg className="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                  </svg>
                  <div className="text-sm font-medium text-green-800 dark:text-green-200">
                    Analysis completed successfully!
                  </div>
                </div>
                <div className="text-xs text-green-700 dark:text-green-300 mt-1">
                  Completed at {new Date().toLocaleString()}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Feature List */}
      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Features Implemented:
        </label>
        <ul className="text-sm text-gray-600 dark:text-gray-400 space-y-1">
          <li>✅ Real-time status polling with configurable intervals</li>
          <li>✅ Progress indicators with percentage and current stage</li>
          <li>✅ Status icons and color-coded indicators</li>
          <li>✅ Error handling with retry functionality</li>
          <li>✅ Duration tracking and display</li>
          <li>✅ Callback functions for status changes, completion, and errors</li>
          <li>✅ Responsive design with dark mode support</li>
          <li>✅ Accessible with proper ARIA labels and semantic HTML</li>
        </ul>
      </div>
    </div>
  );
}