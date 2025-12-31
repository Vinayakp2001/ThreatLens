<template>
  <Teleport to="body">
    <div 
      v-if="toasts.length > 0"
      class="fixed top-4 right-4 z-50 space-y-2 max-w-sm w-full"
    >
      <ToastItem
        v-for="toast in toasts"
        :key="toast.id"
        :toast="toast"
        @remove="removeToast"
      />
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useToastStore } from '@/composables/useToast'
import ToastItem from './ToastItem.vue'

const store = useToastStore()
const { toasts } = storeToRefs(store)
const { removeToast } = store
</script>