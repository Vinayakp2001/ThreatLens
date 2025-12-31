<template>
  <div :class="cn('flex flex-col items-center justify-center', className)">
    <div class="relative">
      <div :class="sizeClasses[size] + ' animate-spin'">
        <svg
          class="w-full h-full text-blue-600"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            class="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            stroke-width="4"
          />
          <path
            class="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      </div>
    </div>
    
    <p 
      v-if="message" 
      :class="cn('mt-3 text-gray-600 dark:text-gray-400 text-center', textSizeClasses[size])"
    >
      {{ message }}
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { cn } from '@/lib/utils'

interface Props {
  size?: 'small' | 'medium' | 'large'
  message?: string
  className?: string
}

const props = withDefaults(defineProps<Props>(), {
  size: 'medium',
  className: ''
})

const sizeClasses = {
  small: 'w-4 h-4',
  medium: 'w-8 h-8',
  large: 'w-12 h-12'
}

const textSizeClasses = {
  small: 'text-sm',
  medium: 'text-base',
  large: 'text-lg'
}
</script>