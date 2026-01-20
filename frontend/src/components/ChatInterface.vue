<template>
  <div class="flex flex-col h-full bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
    <!-- Chat Header -->
    <div class="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
      <div class="flex items-center space-x-3">
        <div class="flex-shrink-0">
          <MessageCircle class="w-6 h-6 text-blue-500" />
        </div>
        <div>
          <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Security Chat
          </h3>
          <p class="text-sm text-gray-500 dark:text-gray-400">
            {{ repositoryName || 'Ask questions about this repository\'s security' }}
          </p>
        </div>
      </div>
      
      <!-- Chat Actions -->
      <div class="flex items-center space-x-2">
        <button
          v-if="sessionId"
          @click="clearChat"
          class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          title="Clear chat"
        >
          <Trash2 class="w-4 h-4" />
        </button>
        <button
          @click="$emit('close')"
          class="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          title="Close chat"
        >
          <X class="w-4 h-4" />
        </button>
      </div>
    </div>

    <!-- Chat Messages -->
    <div 
      ref="messagesContainer"
      class="flex-1 overflow-y-auto p-4 space-y-4 min-h-0"
    >
      <!-- Loading State -->
      <div v-if="isInitializing" class="flex items-center justify-center py-8">
        <LoadingSpinner size="large" message="Initializing chat..." />
      </div>

      <!-- Error State -->
      <div v-else-if="error" class="p-4">
        <ErrorDisplay
          :error="error"
          title="Chat Error"
          :on-retry="initializeChat"
          :show-retry="true"
        />
      </div>

      <!-- Messages -->
      <div v-else class="space-y-4">
        <div
          v-for="(message, index) in messages"
          :key="index"
          :class="cn(
            'flex',
            message.role === 'user' ? 'justify-end' : 'justify-start'
          )"
        >
          <div
            :class="cn(
              'max-w-[80%] rounded-lg px-4 py-3',
              message.role === 'user'
                ? 'bg-blue-500 text-white'
                : 'bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-gray-100'
            )"
          >
            <!-- Message Content -->
            <div class="prose prose-sm max-w-none" :class="message.role === 'user' ? 'prose-invert' : 'dark:prose-invert'">
              <div v-html="renderMarkdown(message.content)"></div>
            </div>

            <!-- Message Sources (for AI responses) -->
            <div v-if="message.role === 'assistant' && message.sources && message.sources.length > 0" class="mt-3 pt-3 border-t border-gray-200 dark:border-gray-600">
              <div class="text-xs text-gray-500 dark:text-gray-400 mb-2">
                <Database class="w-3 h-3 inline mr-1" />
                Sources ({{ message.sources.length }})
              </div>
              <div class="space-y-1">
                <button
                  v-for="(source, sourceIndex) in message.sources.slice(0, 3)"
                  :key="sourceIndex"
                  @click="handleSourceClick(source)"
                  class="block w-full text-left text-xs p-2 rounded bg-gray-50 dark:bg-gray-600 hover:bg-gray-100 dark:hover:bg-gray-500 transition-colors"
                >
                  <div class="font-medium text-gray-700 dark:text-gray-200">
                    {{ source.title || 'Security Section' }}
                  </div>
                  <div class="text-gray-500 dark:text-gray-400 truncate">
                    {{ source.content_snippet || 'Security analysis data' }}
                  </div>
                </button>
              </div>
            </div>

            <!-- Timestamp -->
            <div class="text-xs mt-2 opacity-70">
              {{ formatTime(message.timestamp) }}
            </div>
          </div>
        </div>

        <!-- Typing Indicator -->
        <div v-if="isTyping" class="flex justify-start">
          <div class="bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-3 max-w-[80%]">
            <div class="flex items-center space-x-1">
              <div class="flex space-x-1">
                <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></div>
                <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0.1s"></div>
                <div class="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style="animation-delay: 0.2s"></div>
              </div>
              <span class="text-sm text-gray-500 dark:text-gray-400 ml-2">ThreatLens is thinking...</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Chat Input -->
    <div class="border-t border-gray-200 dark:border-gray-700 p-4">
      <!-- Quick Questions -->
      <div v-if="messages.length <= 1" class="mb-4">
        <div class="text-xs text-gray-500 dark:text-gray-400 mb-2">Quick questions:</div>
        <div class="flex flex-wrap gap-2">
          <button
            v-for="question in quickQuestions"
            :key="question"
            @click="sendMessage(question)"
            :disabled="isTyping"
            class="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors disabled:opacity-50"
          >
            {{ question }}
          </button>
        </div>
      </div>

      <!-- Message Input -->
      <div class="flex items-end space-x-3">
        <div class="flex-1">
          <textarea
            ref="messageInput"
            v-model="currentMessage"
            @keydown="handleKeyDown"
            :disabled="isTyping || !sessionId"
            placeholder="Ask about security vulnerabilities, OWASP compliance, threats..."
            class="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none transition-colors disabled:opacity-50"
            rows="1"
            style="min-height: 44px; max-height: 120px;"
          ></textarea>
        </div>
        <button
          @click="sendCurrentMessage"
          :disabled="!currentMessage.trim() || isTyping || !sessionId"
          class="p-3 bg-blue-500 text-white rounded-lg hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          <Send class="w-4 h-4" />
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, nextTick, watch } from 'vue'
import { 
  MessageCircle, 
  Send, 
  X, 
  Trash2, 
  Database,
  ExternalLink 
} from 'lucide-vue-next'
import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import LoadingSpinner from './LoadingSpinner.vue'
import ErrorDisplay from './ErrorDisplay.vue'
import { useToast } from '@/composables/useToast'

interface Props {
  repoId: string
  repositoryName?: string
}

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  timestamp: string
  sources?: any[]
}

const props = defineProps<Props>()
const emit = defineEmits<{
  close: []
  sectionSelect: [sectionId: string]
}>()

const { showSuccess, showError } = useToast()

// Refs
const messagesContainer = ref<HTMLDivElement>()
const messageInput = ref<HTMLTextAreaElement>()

// State
const sessionId = ref<string | null>(null)
const messages = ref<ChatMessage[]>([])
const currentMessage = ref('')
const isInitializing = ref(true)
const isTyping = ref(false)
const error = ref<string | null>(null)

// Quick questions for new chats
const quickQuestions = [
  "What are the main security vulnerabilities?",
  "How secure is the authentication system?", 
  "What OWASP guidelines apply here?",
  "Show me the risk assessment summary",
  "Are there any critical security issues?"
]

// Initialize chat when component mounts
onMounted(async () => {
  await initializeChat()
})

// Auto-resize textarea
watch(currentMessage, () => {
  nextTick(() => {
    if (messageInput.value) {
      messageInput.value.style.height = 'auto'
      messageInput.value.style.height = messageInput.value.scrollHeight + 'px'
    }
  })
})

const initializeChat = async () => {
  try {
    console.log('🟢 STEP 2: ChatInterface.vue - initializeChat() called')
    console.log('🟢 STEP 2: props.repoId =', props.repoId)
    console.log('🟢 STEP 2: props.repositoryName =', props.repositoryName)
    
    isInitializing.value = true
    error.value = null

    console.log('🟢 STEP 3: About to call api.startChatSession()')
    // Start new chat session
    const response = await api.startChatSession(props.repoId)
    
    console.log('🟢 STEP 3: api.startChatSession() response =', response)
    
    sessionId.value = response.session_id
    
    // Add welcome message
    messages.value = [{
      role: 'assistant',
      content: response.welcome_message,
      timestamp: new Date().toISOString(),
      sources: []
    }]

    console.log('🟢 STEP 3: Welcome message added =', response.welcome_message)

    // Scroll to bottom
    await nextTick()
    scrollToBottom()

  } catch (err) {
    console.error('🔴 STEP 3: Failed to initialize chat:', err)
    error.value = err instanceof Error ? err.message : 'Failed to initialize chat'
  } finally {
    isInitializing.value = false
  }
}

const sendMessage = async (message: string) => {
  if (!message.trim() || !sessionId.value || isTyping.value) return

  try {
    // Add user message
    messages.value.push({
      role: 'user',
      content: message,
      timestamp: new Date().toISOString()
    })

    // Clear input
    currentMessage.value = ''

    // Show typing indicator
    isTyping.value = true

    // Scroll to bottom
    await nextTick()
    scrollToBottom()

    // Send to API
    const response = await api.sendChatMessage(sessionId.value, message)

    // Add AI response
    messages.value.push({
      role: 'assistant',
      content: response.message,
      timestamp: response.timestamp,
      sources: response.sources || []
    })

    // Scroll to bottom
    await nextTick()
    scrollToBottom()

  } catch (err) {
    console.error('Failed to send message:', err)
    showError('Message failed', 'Failed to send message. Please try again.')
    
    // Add error message
    messages.value.push({
      role: 'assistant',
      content: 'I apologize, but I encountered an error processing your message. Please try again.',
      timestamp: new Date().toISOString(),
      sources: []
    })
  } finally {
    isTyping.value = false
  }
}

const sendCurrentMessage = () => {
  sendMessage(currentMessage.value)
}

const handleKeyDown = (event: KeyboardEvent) => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault()
    sendCurrentMessage()
  }
}

const clearChat = async () => {
  try {
    if (sessionId.value) {
      await api.deleteChatSession(sessionId.value)
    }
    
    // Reset state
    sessionId.value = null
    messages.value = []
    currentMessage.value = ''
    
    // Reinitialize
    await initializeChat()
    
    showSuccess('Chat cleared', 'Started a new conversation')
  } catch (err) {
    console.error('Failed to clear chat:', err)
    showError('Clear failed', 'Failed to clear chat')
  }
}

const handleSourceClick = (source: any) => {
  if (source.section_id) {
    emit('sectionSelect', source.section_id)
  }
}

const scrollToBottom = () => {
  if (messagesContainer.value) {
    messagesContainer.value.scrollTop = messagesContainer.value.scrollHeight
  }
}

const formatTime = (timestamp: string) => {
  return new Date(timestamp).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit'
  })
}

const renderMarkdown = (content: string) => {
  // Simple markdown rendering
  return content
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/`(.*?)`/g, '<code class="bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded text-sm">$1</code>')
    .replace(/^### (.*$)/gim, '<h3 class="text-lg font-semibold mt-4 mb-2">$1</h3>')
    .replace(/^## (.*$)/gim, '<h2 class="text-xl font-semibold mt-4 mb-2">$1</h2>')
    .replace(/^# (.*$)/gim, '<h1 class="text-2xl font-bold mt-4 mb-2">$1</h1>')
    .replace(/^\• (.*$)/gim, '<li class="ml-4">$1</li>')
    .replace(/^\- (.*$)/gim, '<li class="ml-4">$1</li>')
    .replace(/\n\n/g, '</p><p class="mb-2">')
    .replace(/^(.*)$/gm, '<p class="mb-2">$1</p>')
    .replace(/^<p class="mb-2"><\/p>$/gm, '')
}
</script>

<style scoped>
/* Custom scrollbar for messages */
.overflow-y-auto::-webkit-scrollbar {
  width: 6px;
}

.overflow-y-auto::-webkit-scrollbar-track {
  background: transparent;
}

.overflow-y-auto::-webkit-scrollbar-thumb {
  background-color: rgba(156, 163, 175, 0.5);
  border-radius: 3px;
}

.overflow-y-auto::-webkit-scrollbar-thumb:hover {
  background-color: rgba(156, 163, 175, 0.7);
}

/* Typing animation */
@keyframes bounce {
  0%, 60%, 100% {
    transform: translateY(0);
  }
  30% {
    transform: translateY(-10px);
  }
}

.animate-bounce {
  animation: bounce 1.4s infinite;
}
</style>