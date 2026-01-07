@echo off
REM ThreatLens Deployment Script for Windows
REM Updated for backend v2.0.0

setlocal enabledelayedexpansion

echo 🚀 ThreatLens Deployment Script v2.0.0 (Windows)
echo ===============================================

REM Configuration
set COMPOSE_FILE=docker-compose.yml
set ENV_FILE=.env
set STORAGE_DIR=.\storage
set CONFIG_DIR=.\config

REM Check prerequisites
:check_prerequisites
echo [INFO] Checking prerequisites...

where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    exit /b 1
)

where docker-compose >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Docker Compose is not installed. Please install Docker Compose first.
    exit /b 1
)

echo [SUCCESS] Prerequisites check passed
goto :eof

REM Create necessary directories
:create_directories
echo [INFO] Creating storage directories...

if not exist "%STORAGE_DIR%" mkdir "%STORAGE_DIR%"
if not exist "%STORAGE_DIR%\repos" mkdir "%STORAGE_DIR%\repos"
if not exist "%STORAGE_DIR%\docs" mkdir "%STORAGE_DIR%\docs"
if not exist "%STORAGE_DIR%\embeddings" mkdir "%STORAGE_DIR%\embeddings"
if not exist "%STORAGE_DIR%\cache" mkdir "%STORAGE_DIR%\cache"
if not exist "%STORAGE_DIR%\backups" mkdir "%STORAGE_DIR%\backups"
if not exist "%STORAGE_DIR%\temp" mkdir "%STORAGE_DIR%\temp"
if not exist "%STORAGE_DIR%\logs" mkdir "%STORAGE_DIR%\logs"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%"

echo [SUCCESS] Storage directories created
goto :eof

REM Create default environment file
:create_env_file
if not exist "%ENV_FILE%" (
    echo [INFO] Creating default .env file...
    
    (
        echo # ThreatLens Backend Configuration v2.0.0
        echo # Copy this file and customize for your environment
        echo.
        echo # API Configuration
        echo API_HOST=0.0.0.0
        echo API_PORT=8000
        echo DEBUG=false
        echo LOG_LEVEL=INFO
        echo.
        echo # Storage Configuration
        echo STORAGE_BASE_PATH=./storage
        echo DATABASE_PATH=./storage/threat_modeling.db
        echo.
        echo # Analysis Configuration
        echo MAX_CONCURRENT_ANALYSES=5
        echo ANALYSIS_TIMEOUT_MINUTES=10
        echo MAX_REPO_SIZE_MB=100
        echo.
        echo # LLM Configuration ^(REQUIRED - Choose one provider^)
        echo # OpenAI Configuration
        echo LLM_PROVIDER=openai
        echo OPENAI_API_KEY=your-openai-api-key-here
        echo OPENAI_MODEL=gpt-4
        echo.
        echo # Alternative: Anthropic Configuration
        echo # LLM_PROVIDER=anthropic
        echo # ANTHROPIC_API_KEY=your-anthropic-api-key-here
        echo # ANTHROPIC_MODEL=claude-3-sonnet-20240229
        echo.
        echo # Alternative: Google Gemini Configuration
        echo # LLM_PROVIDER=google
        echo # GOOGLE_API_KEY=your-google-api-key-here
        echo # GOOGLE_MODEL=gemini-1.5-pro
        echo.
        echo # GitHub Integration ^(Optional - for PR analysis^)
        echo # GITHUB_TOKEN=your-github-token-here
        echo # GITHUB_REQUESTS_PER_HOUR=5000
        echo.
        echo # GPU Configuration ^(Optional^)
        echo ENABLE_GPU_ACCELERATION=false
        echo USE_GPU_FOR_FAISS=false
        echo.
        echo # Security Configuration
        echo ENABLE_LOCAL_REPOS=true
        echo ALLOWED_REPO_HOSTS=github.com,gitlab.com,bitbucket.org
        echo.
        echo # Monitoring
        echo ENABLE_METRICS=true
        echo HEALTH_CHECK_INTERVAL_SECONDS=60
    ) > "%ENV_FILE%"
    
    echo [WARNING] Created default .env file. Please edit it with your configuration!
    echo [WARNING] You MUST set your LLM API key before deployment will work.
) else (
    echo [INFO] .env file already exists
)
goto :eof

REM Validate configuration
:validate_config
echo [INFO] Validating configuration...

if not exist "%ENV_FILE%" (
    echo [ERROR] .env file not found. Run with setup first.
    exit /b 1
)

REM Basic validation - check if API key is set
findstr /C:"your-openai-api-key-here" "%ENV_FILE%" >nul
if %errorlevel% equ 0 (
    echo [WARNING] Default API key detected. Please update your .env file with real API keys.
)

echo [SUCCESS] Configuration validation passed
goto :eof

REM Build and deploy
:deploy
echo [INFO] Building and deploying ThreatLens...

REM Pull latest images and build
docker-compose -f "%COMPOSE_FILE%" pull
docker-compose -f "%COMPOSE_FILE%" build --no-cache

REM Start services
docker-compose -f "%COMPOSE_FILE%" up -d

echo [SUCCESS] ThreatLens deployed successfully!

REM Wait for health check
echo [INFO] Waiting for services to be healthy...
timeout /t 10 /nobreak >nul

REM Check health
curl -f http://localhost:8000/health >nul 2>nul
if %errorlevel% equ 0 (
    echo [SUCCESS] ThreatLens is running and healthy!
    echo [INFO] Access the API at: http://localhost:8000
    echo [INFO] API documentation at: http://localhost:8000/docs
) else (
    echo [WARNING] Service may still be starting up. Check logs with: docker-compose logs -f
)
goto :eof

REM Stop services
:stop
echo [INFO] Stopping ThreatLens services...
docker-compose -f "%COMPOSE_FILE%" down
echo [SUCCESS] Services stopped
goto :eof

REM Show logs
:logs
docker-compose -f "%COMPOSE_FILE%" logs -f
goto :eof

REM Show status
:status
echo [INFO] ThreatLens Service Status:
docker-compose -f "%COMPOSE_FILE%" ps

echo.
echo [INFO] Health Check:
curl -f http://localhost:8000/health >nul 2>nul
if %errorlevel% equ 0 (
    echo [SUCCESS] API is healthy
) else (
    echo [WARNING] API is not responding
)
goto :eof

REM Cleanup
:cleanup
echo [INFO] Cleaning up ThreatLens...
docker-compose -f "%COMPOSE_FILE%" down -v --remove-orphans
docker system prune -f
echo [SUCCESS] Cleanup completed
goto :eof

REM Show help
:show_help
echo ThreatLens Deployment Script v2.0.0 (Windows)
echo.
echo Usage: %0 [COMMAND]
echo.
echo Commands:
echo   setup     - Create directories and default configuration
echo   deploy    - Build and deploy ThreatLens
echo   stop      - Stop all services
echo   restart   - Restart all services
echo   logs      - Show service logs
echo   status    - Show service status
echo   cleanup   - Stop services and clean up
echo   help      - Show this help message
echo.
echo Examples:
echo   %0 setup     # First time setup
echo   %0 deploy    # Deploy the application
echo   %0 logs      # View logs
echo   %0 status    # Check status
goto :eof

REM Main script logic
if "%1"=="setup" (
    call :check_prerequisites
    call :create_directories
    call :create_env_file
    echo [SUCCESS] Setup completed! Edit .env file with your configuration, then run: %0 deploy
) else if "%1"=="deploy" (
    call :check_prerequisites
    call :create_directories
    call :validate_config
    call :deploy
) else if "%1"=="stop" (
    call :stop
) else if "%1"=="restart" (
    call :stop
    timeout /t 2 /nobreak >nul
    call :check_prerequisites
    call :validate_config
    call :deploy
) else if "%1"=="logs" (
    call :logs
) else if "%1"=="status" (
    call :status
) else if "%1"=="cleanup" (
    call :cleanup
) else (
    call :show_help
)