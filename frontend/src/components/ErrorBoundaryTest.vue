<template>
  <div class="p-4 space-y-4">
    <h3 class="text-lg font-semibold">Error Boundary Test Component</h3>
    
    <div class="space-x-2">
      <button
        @click="triggerError"
        class="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600"
      >
        Trigger Error
      </button>
      
      <button
        @click="triggerAsyncError"
        class="px-4 py-2 bg-orange-500 text-white rounded hover:bg-orange-600"
      >
        Trigger Async Error
      </button>
      
      <button
        @click="triggerNetworkError"
        class="px-4 py-2 bg-yellow-500 text-white rounded hover:bg-yellow-600"
      >
        Trigger Network Error
      </button>
    </div>
    
    <div v-if="showNullAccess" class="p-4 bg-gray-100 rounded">
      <!-- This will trigger an error if showNullAccess is true -->
      {{ nullObject.nonExistentProperty.toUpperCase() }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { NetworkError } from '@/lib/types'

const showNullAccess = ref(false)
const nullObject = ref(null)

const triggerError = () => {
  // This will cause a null reference error
  showNullAccess.value = true
}

const triggerAsyncError = async () => {
  // Simulate an async error
  throw new Error('Simulated async error for testing error boundaries')
}

const triggerNetworkError = () => {
  // Simulate a network error
  throw new NetworkError('Simulated network connection failure')
}
</script>