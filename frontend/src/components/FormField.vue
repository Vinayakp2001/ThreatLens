<template>
  <div :class="cn('space-y-1', className)">
    <!-- Label -->
    <label 
      :for="fieldId"
      class="block text-sm font-medium text-gray-700 dark:text-gray-300"
    >
      {{ label }}
      <span v-if="required" class="text-red-500 ml-1" aria-label="required">*</span>
    </label>

    <!-- Input Field -->
    <div class="relative">
      <textarea
        v-if="type === 'textarea'"
        :id="fieldId"
        :value="modelValue"
        @input="handleInput"
        @blur="handleBlur"
        :placeholder="placeholder"
        :disabled="disabled"
        :required="required"
        :maxlength="maxLength"
        :autocomplete="autoComplete"
        :rows="rows"
        :class="getFieldClasses()"
        :aria-invalid="hasError"
        :aria-describedby="hasError ? `${fieldId}-error` : hasSuccess ? `${fieldId}-success` : undefined"
      />
      
      <div v-else-if="type === 'password'" class="relative">
        <input
          :id="fieldId"
          :type="showPassword ? 'text' : 'password'"
          :value="modelValue"
          @input="handleInput"
          @blur="handleBlur"
          :placeholder="placeholder"
          :disabled="disabled"
          :required="required"
          :maxlength="maxLength"
          :autocomplete="autoComplete"
          :class="getFieldClasses()"
          :aria-invalid="hasError"
          :aria-describedby="hasError ? `${fieldId}-error` : hasSuccess ? `${fieldId}-success` : undefined"
        />
        <button
          type="button"
          @click="showPassword = !showPassword"
          class="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
          tabindex="-1"
        >
          <EyeOff v-if="showPassword" class="w-4 h-4" />
          <Eye v-else class="w-4 h-4" />
        </button>
      </div>
      
      <input
        v-else
        :id="fieldId"
        :type="type"
        :value="modelValue"
        @input="handleInput"
        @blur="handleBlur"
        :placeholder="placeholder"
        :disabled="disabled"
        :required="required"
        :maxlength="maxLength"
        :autocomplete="autoComplete"
        :class="getFieldClasses()"
        :aria-invalid="hasError"
        :aria-describedby="hasError ? `${fieldId}-error` : hasSuccess ? `${fieldId}-success` : undefined"
      />
      
      <!-- Status Icon -->
      <div 
        v-if="showValidation && (hasError || hasSuccess)" 
        class="absolute inset-y-0 right-0 pr-3 flex items-center pointer-events-none"
      >
        <AlertCircle v-if="hasError" class="w-4 h-4 text-red-500" />
        <CheckCircle v-else-if="hasSuccess" class="w-4 h-4 text-green-500" />
      </div>
    </div>

    <!-- Character Count -->
    <div 
      v-if="maxLength" 
      class="text-xs text-gray-500 dark:text-gray-400 text-right"
    >
      {{ modelValue.length }}/{{ maxLength }}
    </div>

    <!-- Error Message -->
    <div 
      v-if="hasError && showValidation"
      :id="`${fieldId}-error`"
      class="flex items-start space-x-1 text-sm text-red-600 dark:text-red-400"
      role="alert"
    >
      <AlertCircle class="w-4 h-4 mt-0.5 flex-shrink-0" />
      <span>{{ displayError }}</span>
    </div>

    <!-- Success Message -->
    <div 
      v-if="hasSuccess && showValidation"
      :id="`${fieldId}-success`"
      class="flex items-start space-x-1 text-sm text-green-600 dark:text-green-400"
    >
      <CheckCircle class="w-4 h-4 mt-0.5 flex-shrink-0" />
      <span>{{ success }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { AlertCircle, CheckCircle, Eye, EyeOff } from 'lucide-vue-next'
import { cn } from '@/lib/utils'

interface ValidationRule {
  test: (value: string) => boolean
  message: string
}

interface Props {
  label: string
  type?: 'text' | 'email' | 'url' | 'password' | 'textarea'
  modelValue: string
  placeholder?: string
  required?: boolean
  disabled?: boolean
  error?: string
  success?: string
  validationRules?: ValidationRule[]
  validateOnChange?: boolean
  validateOnBlur?: boolean
  showValidation?: boolean
  className?: string
  inputClassName?: string
  rows?: number
  maxLength?: number
  autoComplete?: string
  id?: string
}

const props = withDefaults(defineProps<Props>(), {
  type: 'text',
  required: false,
  disabled: false,
  validateOnChange: false,
  validateOnBlur: true,
  showValidation: true,
  className: '',
  inputClassName: '',
  rows: 3,
  validationRules: () => []
})

const emit = defineEmits<{
  'update:modelValue': [value: string]
  blur: []
}>()

const internalError = ref('')
const touched = ref(false)
const showPassword = ref(false)

const fieldId = computed(() => props.id || `field-${props.label.toLowerCase().replace(/\s+/g, '-')}`)

// Validate field value
const validateField = (fieldValue: string): string => {
  // Required validation
  if (props.required && !fieldValue.trim()) {
    return `${props.label} is required`
  }

  // Custom validation rules
  for (const rule of props.validationRules) {
    if (fieldValue && !rule.test(fieldValue)) {
      return rule.message
    }
  }

  // Built-in type validation
  if (fieldValue) {
    switch (props.type) {
      case 'email':
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        if (!emailRegex.test(fieldValue)) {
          return 'Please enter a valid email address'
        }
        break
      case 'url':
        try {
          new URL(fieldValue)
        } catch {
          return 'Please enter a valid URL'
        }
        break
    }
  }

  return ''
}

const handleInput = (event: Event) => {
  const target = event.target as HTMLInputElement | HTMLTextAreaElement
  const newValue = target.value
  
  emit('update:modelValue', newValue)
  
  if (props.validateOnChange && touched.value) {
    const validationError = validateField(newValue)
    internalError.value = validationError
  }
}

const handleBlur = () => {
  touched.value = true
  
  if (props.validateOnBlur) {
    const validationError = validateField(props.modelValue)
    internalError.value = validationError
  }
  
  emit('blur')
}

// Clear internal error when external error is provided
watch(() => props.error, (newError) => {
  if (newError) {
    internalError.value = ''
  }
})

const displayError = computed(() => props.error || internalError.value)
const hasError = computed(() => Boolean(displayError.value && touched.value))
const hasSuccess = computed(() => Boolean(props.success && !hasError.value && props.modelValue && touched.value))

const getFieldClasses = () => {
  const baseClasses = cn(
    'w-full px-3 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors',
    props.inputClassName
  )
  
  if (hasError.value) {
    return cn(baseClasses, 'border-red-500 bg-red-50 dark:bg-red-900/20 text-red-900 dark:text-red-100 placeholder-red-400')
  }
  
  if (hasSuccess.value) {
    return cn(baseClasses, 'border-green-500 bg-green-50 dark:bg-green-900/20 text-green-900 dark:text-green-100')
  }
  
  return cn(baseClasses, 'border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400')
}
</script>