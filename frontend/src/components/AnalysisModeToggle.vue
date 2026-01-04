<template>
  <div class="flex items-center justify-center mb-8">
    <div class="bg-white dark:bg-gray-800 rounded-lg p-1 shadow-sm border border-gray-200 dark:border-gray-700">
      <div class="flex">
        <button
          @click="$emit('update:modelValue', 'repository')"
          :class="cn(
            'px-6 py-2 rounded-md text-sm font-medium transition-all duration-200',
            modelValue === 'repository'
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100'
          )"
        >
          <div class="flex items-center space-x-2">
            <GitBranch class="w-4 h-4" />
            <span>Full Repository</span>
          </div>
        </button>
        <button
          @click="$emit('update:modelValue', 'pr')"
          :class="cn(
            'px-6 py-2 rounded-md text-sm font-medium transition-all duration-200',
            modelValue === 'pr'
              ? 'bg-purple-600 text-white shadow-sm'
              : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100'
          )"
        >
          <div class="flex items-center space-x-2">
            <GitPullRequest class="w-4 h-4" />
            <span>Pull Request</span>
          </div>
        </button>
      </div>
    </div>
  </div>
  
  <!-- Mode Description -->
  <div class="text-center mb-6">
    <p v-if="modelValue === 'repository'" class="text-gray-600 dark:text-gray-400">
      Analyze the entire repository to generate comprehensive security documentation
    </p>
    <p v-else class="text-gray-600 dark:text-gray-400">
      Analyze only the changes in a specific pull request for quick security review
    </p>
  </div>
</template>

<script setup lang="ts">
import { GitBranch, GitPullRequest } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

interface Props {
  modelValue: 'repository' | 'pr'
}

interface Emits {
  (e: 'update:modelValue', value: 'repository' | 'pr'): void
}

defineProps<Props>()
defineEmits<Emits>()
</script>