#!/bin/bash

# ThreatLens Deployment Script
# Updated for backend v2.0.0

set -e

echo "🚀 ThreatLens Deployment Script v2.0.0"
echo "======================================="

# Configuration
COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env"
STORAGE_DIR="./storage"
CONFIG_DIR="./config"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Create necessary directories
create_directories() {
    log_info "Creating storage directories..."
    
    mkdir -p "$STORAGE_DIR"/{repos,docs,embeddings,cache,backups,temp,logs}
    mkdir -p "$CONFIG_DIR"
    
    # Set proper permissions
    chmod -R 755 "$STORAGE_DIR"
    
    log_success "Storage directories created"
}

# Create default environment file if it doesn't exist
create_env_file() {
    if [ ! -f "$ENV_FILE" ]; then
        log_info "Creating default .env file..."
        
        cat > "$ENV_FILE" << EOF
# ThreatLens Backend Configuration v2.0.0
# Copy this file and customize for your environment

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false
LOG_LEVEL=INFO

# Storage Configuration
STORAGE_BASE_PATH=./storage
DATABASE_PATH=./storage/threat_modeling.db

# Analysis Configuration
MAX_CONCURRENT_ANALYSES=5
ANALYSIS_TIMEOUT_MINUTES=10
MAX_REPO_SIZE_MB=100

# LLM Configuration (REQUIRED - Choose one provider)
# OpenAI Configuration
LLM_PROVIDER=openai
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4

# Alternative: Anthropic Configuration
# LLM_PROVIDER=anthropic
# ANTHROPIC_API_KEY=your-anthropic-api-key-here
# ANTHROPIC_MODEL=claude-3-sonnet-20240229

# Alternative: Google Gemini Configuration
# LLM_PROVIDER=google
# GOOGLE_API_KEY=your-google-api-key-here
# GOOGLE_MODEL=gemini-1.5-pro

# GitHub Integration (Optional - for PR analysis)
# GITHUB_TOKEN=your-github-token-here
# GITHUB_REQUESTS_PER_HOUR=5000

# GPU Configuration (Optional)
ENABLE_GPU_ACCELERATION=false
USE_GPU_FOR_FAISS=false

# Security Configuration
ENABLE_LOCAL_REPOS=true
ALLOWED_REPO_HOSTS=github.com,gitlab.com,bitbucket.org

# Monitoring
ENABLE_METRICS=true
HEALTH_CHECK_INTERVAL_SECONDS=60
EOF
        
        log_warning "Created default .env file. Please edit it with your configuration!"
        log_warning "You MUST set your LLM API key before deployment will work."
    else
        log_info ".env file already exists"
    fi
}

# Validate configuration
validate_config() {
    log_info "Validating configuration..."
    
    if [ ! -f "$ENV_FILE" ]; then
        log_error ".env file not found. Run with --setup first."
        exit 1
    fi
    
    # Source the env file to check variables
    set -a
    source "$ENV_FILE"
    set +a
    
    # Check for required LLM configuration
    if [ -z "$LLM_PROVIDER" ]; then
        log_error "LLM_PROVIDER not set in .env file"
        exit 1
    fi
    
    case "$LLM_PROVIDER" in
        "openai")
            if [ -z "$OPENAI_API_KEY" ] || [ "$OPENAI_API_KEY" = "your-openai-api-key-here" ]; then
                log_error "OPENAI_API_KEY not properly configured in .env file"
                exit 1
            fi
            ;;
        "anthropic")
            if [ -z "$ANTHROPIC_API_KEY" ] || [ "$ANTHROPIC_API_KEY" = "your-anthropic-api-key-here" ]; then
                log_error "ANTHROPIC_API_KEY not properly configured in .env file"
                exit 1
            fi
            ;;
        "google")
            if [ -z "$GOOGLE_API_KEY" ] || [ "$GOOGLE_API_KEY" = "your-google-api-key-here" ]; then
                log_error "GOOGLE_API_KEY not properly configured in .env file"
                exit 1
            fi
            ;;
        *)
            log_error "Invalid LLM_PROVIDER: $LLM_PROVIDER"
            exit 1
            ;;
    esac
    
    log_success "Configuration validation passed"
}

# Build and deploy
deploy() {
    log_info "Building and deploying ThreatLens..."
    
    # Pull latest images and build
    docker-compose -f "$COMPOSE_FILE" pull
    docker-compose -f "$COMPOSE_FILE" build --no-cache
    
    # Start services
    docker-compose -f "$COMPOSE_FILE" up -d
    
    log_success "ThreatLens deployed successfully!"
    
    # Wait for health check
    log_info "Waiting for services to be healthy..."
    sleep 10
    
    # Check health
    if curl -f http://localhost:8000/health &> /dev/null; then
        log_success "ThreatLens is running and healthy!"
        log_info "Access the API at: http://localhost:8000"
        log_info "API documentation at: http://localhost:8000/docs"
    else
        log_warning "Service may still be starting up. Check logs with: docker-compose logs -f"
    fi
}

# Stop services
stop() {
    log_info "Stopping ThreatLens services..."
    docker-compose -f "$COMPOSE_FILE" down
    log_success "Services stopped"
}

# Show logs
logs() {
    docker-compose -f "$COMPOSE_FILE" logs -f
}

# Show status
status() {
    log_info "ThreatLens Service Status:"
    docker-compose -f "$COMPOSE_FILE" ps
    
    echo ""
    log_info "Health Check:"
    if curl -f http://localhost:8000/health 2>/dev/null; then
        log_success "API is healthy"
    else
        log_warning "API is not responding"
    fi
}

# Cleanup
cleanup() {
    log_info "Cleaning up ThreatLens..."
    docker-compose -f "$COMPOSE_FILE" down -v --remove-orphans
    docker system prune -f
    log_success "Cleanup completed"
}

# Show help
show_help() {
    echo "ThreatLens Deployment Script v2.0.0"
    echo ""
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup     - Create directories and default configuration"
    echo "  deploy    - Build and deploy ThreatLens"
    echo "  stop      - Stop all services"
    echo "  restart   - Restart all services"
    echo "  logs      - Show service logs"
    echo "  status    - Show service status"
    echo "  cleanup   - Stop services and clean up"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup     # First time setup"
    echo "  $0 deploy    # Deploy the application"
    echo "  $0 logs      # View logs"
    echo "  $0 status    # Check status"
}

# Main script logic
case "${1:-help}" in
    "setup")
        check_prerequisites
        create_directories
        create_env_file
        log_success "Setup completed! Edit .env file with your configuration, then run: $0 deploy"
        ;;
    "deploy")
        check_prerequisites
        create_directories
        validate_config
        deploy
        ;;
    "stop")
        stop
        ;;
    "restart")
        stop
        sleep 2
        check_prerequisites
        validate_config
        deploy
        ;;
    "logs")
        logs
        ;;
    "status")
        status
        ;;
    "cleanup")
        cleanup
        ;;
    "help"|*)
        show_help
        ;;
esac