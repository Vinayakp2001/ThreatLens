<template>
  <div
    :class="cn(
      'transform transition-all duration-300 ease-in-out',
      isVisible && !isLeaving 
        ? 'translate-x-0 opacity-100' 
        : 'translate-x-full opacity-0'
    )"
  >
    <div :class="cn(
      'rounded-lg border shadow-lg p-4',
      config.bgColor,
      config.borderColor
    )">
      <div class="flex items-start space-x-3">
        <component 
          :is="config.icon" 
          :class="cn('w-5 h-5 mt-0.5 flex-shrink-0', config.iconColor)" 
        />
        
        <div class="flex-1 min-w-0">
          <h4 :class="cn('text-sm font-medium', config.titleColor)">
            {{ toast.title }}
          </h4>
          
          <p 
            v-if="toast.message" 
            :class="cn('mt-1 text-sm', config.messageColor)"
          >
            {{ toast.message }}
          </p>
          
          <div v-if="toast.action" class="mt-3">
            <button
              @click="toast.action.onClick"
              :class="cn('text-sm font-medium hover:opacity-80 transition-opacity', config.titleColor)"
            >
              {{ toast.action.label }}
            </button>
          </div>
        </div>
        
        <button
          @click="handleRemove"
          :class="cn('flex-shrink-0 hover:opacity-70 transition-opacity', config.iconColor)"
        >
          <X class="w-4 h-4" />
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { CheckCircle, AlertCircle, XCircle, Info, X } from 'lucide-vue-next'
import type { Toast, ToastType } from '@/composables/useToast'
import { cn } from '@/lib/utils'

interface Props {
  toast: Toast
}

const props = defineProps<Props>()
const emit = defineEmits<{
  remove: [id: string]
}>()

const isVisible = ref(false)
const isLeaving = ref(false)

onMounted(() => {
  // Trigger entrance animation
  setTimeout(() => {
    isVisible.value = true
  }, 10)
})

const handleRemove = () => {
  isLeaving.value = true
  setTimeout(() => {
    emit('remove', props.toast.id)
  }, 150)
}

const getToastConfig = (type: ToastType) => {
  switch (type) {
    case 'success':
      return {
        icon: CheckCircle,
        bgColor: 'bg-green-50 dark:bg-green-900/20',
        borderColor: 'border-green-200 dark:border-green-800',
        iconColor: 'text-green-500',
        titleColor: 'text-green-800 dark:text-green-200',
        messageColor: 'text-green-700 dark:text-green-300'
      }
    case 'error':
      return {
        icon: XCircle,
        bgColor: 'bg-red-50 dark:bg-red-900/20',
        borderColor: 'border-red-200 dark:border-red-800',
        iconColor: 'text-red-500',
        titleColor: 'text-red-800 dark:text-red-200',
        messageColor: 'text-red-700 dark:text-red-300'
      }
    case 'warning':
      return {
        icon: AlertCircle,
        bgColor: 'bg-yellow-50 dark:bg-yellow-900/20',
        borderColor: 'border-yellow-200 dark:border-yellow-800',
        iconColor: 'text-yellow-500',
        titleColor: 'text-yellow-800 dark:text-yellow-200',
        messageColor: 'text-yellow-700 dark:text-yellow-300'
      }
    case 'info':
      return {
        icon: Info,
        bgColor: 'bg-blue-50 dark:bg-blue-900/20',
        borderColor: 'border-blue-200 dark:border-blue-800',
        iconColor: 'text-blue-500',
        titleColor: 'text-blue-800 dark:text-blue-200',
        messageColor: 'text-blue-700 dark:text-blue-300'
      }
  }
}

const config = computed(() => getToastConfig(props.toast.type))
</script>