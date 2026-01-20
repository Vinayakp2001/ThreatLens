<!--
Kiro-style Resizable Layout Component
Drag-and-drop resizing like in Kiro IDE
-->
<template>
  <div class="flex h-full relative">
    <!-- Left Panel (Wiki Navigation) -->
    <div 
      class="flex-shrink-0 transition-all duration-200 ease-out"
      :style="{ width: `${leftWidth}px` }"
    >
      <slot name="left" />
    </div>

    <!-- Left Resize Handle -->
    <div
      class="w-1 bg-gray-200 dark:bg-gray-700 hover:bg-blue-500 cursor-col-resize flex-shrink-0 relative group transition-colors duration-150"
      @mousedown="startResize('left', $event)"
    >
      <div class="absolute inset-y-0 -left-1 -right-1 flex items-center justify-center">
        <div class="w-0.5 h-8 bg-gray-400 dark:bg-gray-500 group-hover:bg-blue-500 rounded-full transition-colors duration-150"></div>
      </div>
    </div>

    <!-- Center Panel (Wiki Content) -->
    <div class="flex-1 min-w-0 transition-all duration-200 ease-out">
      <slot name="center" />
    </div>

    <!-- Right Resize Handle (only if chat is shown) -->
    <div
      v-if="showRight"
      class="w-1 bg-gray-200 dark:bg-gray-700 hover:bg-blue-500 cursor-col-resize flex-shrink-0 relative group transition-colors duration-150"
      @mousedown="startResize('right', $event)"
    >
      <div class="absolute inset-y-0 -left-1 -right-1 flex items-center justify-center">
        <div class="w-0.5 h-8 bg-gray-400 dark:bg-gray-500 group-hover:bg-blue-500 rounded-full transition-colors duration-150"></div>
      </div>
    </div>

    <!-- Right Panel (Chat) -->
    <div 
      v-if="showRight"
      class="flex-shrink-0 transition-all duration-200 ease-out"
      :style="{ width: `${rightWidth}px` }"
    >
      <slot name="right" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'

interface Props {
  showRight?: boolean
  defaultLeftWidth?: number
  defaultRightWidth?: number
  minLeftWidth?: number
  minRightWidth?: number
  maxLeftWidth?: number
  maxRightWidth?: number
}

const props = withDefaults(defineProps<Props>(), {
  showRight: false,
  defaultLeftWidth: 280,
  defaultRightWidth: 400,
  minLeftWidth: 200,
  minRightWidth: 300,
  maxLeftWidth: 500,
  maxRightWidth: 600
})

// Reactive state
const leftWidth = ref(props.defaultLeftWidth)
const rightWidth = ref(props.defaultRightWidth)
const isResizing = ref(false)
const resizeType = ref<'left' | 'right' | null>(null)

// Resize functionality
const startResize = (type: 'left' | 'right', e: MouseEvent) => {
  e.preventDefault()
  isResizing.value = true
  resizeType.value = type
  
  document.addEventListener('mousemove', handleResize)
  document.addEventListener('mouseup', stopResize)
  document.body.style.cursor = 'col-resize'
  document.body.style.userSelect = 'none'
  
  // Add visual feedback
  document.body.classList.add('resizing')
}

const handleResize = (e: MouseEvent) => {
  if (!isResizing.value || !resizeType.value) return
  
  const container = document.querySelector('.flex.h-full.relative') as HTMLElement
  if (!container) return
  
  const containerRect = container.getBoundingClientRect()
  const mouseX = e.clientX - containerRect.left
  
  if (resizeType.value === 'left') {
    // Resize left panel
    const newWidth = Math.max(
      props.minLeftWidth,
      Math.min(props.maxLeftWidth, mouseX)
    )
    leftWidth.value = newWidth
  } else if (resizeType.value === 'right') {
    // Resize right panel
    const newWidth = Math.max(
      props.minRightWidth,
      Math.min(props.maxRightWidth, containerRect.width - mouseX)
    )
    rightWidth.value = newWidth
  }
}

const stopResize = () => {
  isResizing.value = false
  resizeType.value = null
  
  document.removeEventListener('mousemove', handleResize)
  document.removeEventListener('mouseup', stopResize)
  document.body.style.cursor = ''
  document.body.style.userSelect = ''
  document.body.classList.remove('resizing')
  
  // Save preferences
  localStorage.setItem('threatlens_left_width', leftWidth.value.toString())
  localStorage.setItem('threatlens_right_width', rightWidth.value.toString())
}

// Load saved preferences
onMounted(() => {
  const savedLeft = localStorage.getItem('threatlens_left_width')
  const savedRight = localStorage.getItem('threatlens_right_width')
  
  if (savedLeft) leftWidth.value = parseInt(savedLeft)
  if (savedRight) rightWidth.value = parseInt(savedRight)
})

onUnmounted(() => {
  document.removeEventListener('mousemove', handleResize)
  document.removeEventListener('mouseup', stopResize)
})
</script>

<style scoped>
/* Smooth transitions */
.transition-all {
  transition-property: width, background-color;
}

/* Global styles for resizing state */
:global(body.resizing) {
  cursor: col-resize !important;
  user-select: none !important;
}

:global(body.resizing *) {
  cursor: col-resize !important;
  user-select: none !important;
}
</style>