'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import RepoForm from '@/components/RepoForm';
import RecentRepos from '@/components/RecentRepos';
import AnalysisStatus from '@/components/AnalysisStatus';
import { AnalyzeRepoResponse, RepoInfo, AnalysisProgress } from '@/lib/types';

export default function Home() {
  const router = useRouter();
  const [analysisStarted, setAnalysisStarted] = useState<AnalyzeRepoResponse | null>(null);
  const [newRepo, setNewRepo] = useState<RepoInfo | null>(null);
  const [showAnalysisStatus, setShowAnalysisStatus] = useState(false);

  const handleAnalysisStarted = (response: AnalyzeRepoResponse, repoUrl: string) => {
    setAnalysisStarted(response);
    
    // Create repo info for recent repos
    const repoInfo: RepoInfo = {
      id: response.repo_id,
      url: repoUrl,
      analyzedAt: new Date().toISOString(),
      status: 'analyzing',
      title: undefined
    };
    
    setNewRepo(repoInfo);
    setShowAnalysisStatus(true);
    
    // Navigate to the repository page after a short delay to show the status
    setTimeout(() => {
      router.push(`/${response.repo_id}`);
    }, 2000);
  };

  const handleAnalysisComplete = (status: AnalysisProgress) => {
    // Navigate to repository page when analysis completes
    router.push(`/${status.repo_id}`);
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="container mx-auto px-4 py-12">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100 mb-4">
            ThreatLens
          </h1>
          <p className="text-xl text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
            GPU-powered threat modeling documentation generator. 
            Analyze your code repositories to identify security threats and generate comprehensive threat models.
          </p>
        </div>

        {/* Main Content */}
        <div className="space-y-12">
          {/* Repository Analysis Form */}
          <section>
            <div className="text-center mb-8">
              <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-2">
                Analyze Repository
              </h2>
              <p className="text-gray-600 dark:text-gray-400">
                Enter a Git repository URL to start threat modeling analysis
              </p>
            </div>
            <RepoForm onAnalysisStarted={handleAnalysisStarted} />
            
            {/* Show analysis status after starting */}
            {showAnalysisStatus && analysisStarted && (
              <div className="mt-8 max-w-2xl mx-auto">
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
                  <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-4">
                    Analysis Started
                  </h3>
                  <AnalysisStatus
                    repoId={analysisStarted.repo_id}
                    analysisId={analysisStarted.analysis_id}
                    onComplete={handleAnalysisComplete}
                  />
                  <div className="mt-4 text-sm text-gray-600 dark:text-gray-400">
                    You will be redirected to the repository page when analysis completes, or you can{' '}
                    <button
                      onClick={() => router.push(`/${analysisStarted.repo_id}`)}
                      className="text-blue-600 dark:text-blue-400 hover:underline"
                    >
                      view progress now
                    </button>
                    .
                  </div>
                </div>
              </div>
            )}
          </section>

          {/* Recent Repositories */}
          <section>
            <RecentRepos newRepo={newRepo} />
          </section>

          {/* Features Overview */}
          <section className="mt-16">
            <div className="text-center mb-8">
              <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-4">
                What ThreatLens Does
              </h2>
            </div>
            <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
              <div className="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
                <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <svg className="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Code Analysis
                </h3>
                <p className="text-gray-600 dark:text-gray-400 text-sm">
                  Automatically analyzes your codebase to identify components, data flows, and security patterns
                </p>
              </div>
              
              <div className="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
                <div className="w-12 h-12 bg-red-100 dark:bg-red-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <svg className="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Threat Identification
                </h3>
                <p className="text-gray-600 dark:text-gray-400 text-sm">
                  Uses STRIDE methodology to identify potential security threats and vulnerabilities
                </p>
              </div>
              
              <div className="text-center p-6 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
                <div className="w-12 h-12 bg-green-100 dark:bg-green-900/20 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <svg className="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  Documentation
                </h3>
                <p className="text-gray-600 dark:text-gray-400 text-sm">
                  Generates comprehensive threat modeling documentation with mitigation strategies
                </p>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
