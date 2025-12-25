# Configuration Guide

This document provides comprehensive information about configuring the Threat Modeling Documentation Generator.

## Configuration Methods

The application supports multiple configuration methods in order of precedence:

1. **Environment Variables** (highest priority)
2. **Configuration Files** (.env, config.json)
3. **Default Values** (lowest priority)

## Environment Variables

All configuration options can be set using environment variables. The variable names are the uppercase version of the configuration keys.

### Example
```bash
export API_HOST=0.0.0.0
export API_PORT=8000
export DEBUG=false
export LLM_PROVIDER=openai
export OPENAI_API_KEY=sk-your-api-key-here
```

## Configuration Files

### .env File

Create a `.env` file in the project root:

```env
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
DEBUG=false
LOG_LEVEL=INFO

# LLM Configuration
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-4

# Storage Configuration
STORAGE_BASE_PATH=./storage
MAX_REPO_SIZE_MB=100
MAX_CONCURRENT_ANALYSES=5

# Security Configuration
ENABLE_LOCAL_REPOS=true
ALLOWED_REPO_HOSTS=["github.com", "gitlab.com", "bitbucket.org"]
```

### JSON Configuration

Create a `config/config.json` file:

```json
{
  "api_host": "0.0.0.0",
  "api_port": 8000,
  "debug": false,
  "llm_provider": "openai",
  "openai_api_key": "sk-your-api-key-here",
  "storage_base_path": "./storage",
  "max_concurrent_analyses": 5
}
```

## Configuration Sections

### API Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `api_host` | string | "0.0.0.0" | API server host address |
| `api_port` | integer | 8000 | API server port (1-65535) |
| `debug` | boolean | false | Enable debug mode |
| `log_level` | string | "INFO" | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |

### LLM Configuration

#### OpenAI Provider
| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `llm_provider` | string | "openai" | LLM provider (openai, azure, anthropic) |
| `openai_api_key` | string | None | OpenAI API key (required) |
| `openai_model` | string | "gpt-4" | OpenAI model name |
| `openai_base_url` | string | None | Custom OpenAI-compatible API base URL |

#### Azure OpenAI Provider
| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `llm_provider` | string | "azure" | Set to "azure" for Azure OpenAI |
| `azure_openai_endpoint` | string | None | Azure OpenAI endpoint URL (required) |
| `azure_openai_api_key` | string | None | Azure OpenAI API key (required) |
| `azure_openai_deployment_name` | string | None | Azure deployment name (required) |
| `azure_openai_api_version` | string | "2023-12-01-preview" | Azure API version |

### Embedding Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `embedding_provider` | string | "openai" | Embedding provider (openai, sentence-transformers) |
| `embedding_model` | string | "text-embedding-ada-002" | Embedding model name |
| `sentence_transformer_model` | string | "all-MiniLM-L6-v2" | Sentence transformer model |

### Storage Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `storage_base_path` | string | "./storage" | Base storage directory |
| `repos_storage_path` | string | "./storage/repos" | Repository storage directory |
| `docs_storage_path` | string | "./storage/docs" | Documents storage directory |
| `embeddings_storage_path` | string | "./storage/embeddings" | Embeddings storage directory |
| `database_path` | string | "./storage/threat_modeling.db" | Database file path |

### Storage Management

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_storage_quotas` | boolean | true | Enable storage quota management |
| `auto_cleanup_enabled` | boolean | true | Enable automatic cleanup |
| `backup_retention_days` | integer | 180 | Backup retention period in days |
| `temp_file_retention_hours` | integer | 24 | Temporary file retention in hours |
| `maintenance_interval_hours` | integer | 24 | Maintenance interval in hours |

### Repository Analysis

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `max_repo_size_mb` | integer | 100 | Maximum repository size in MB (1-10000) |
| `analysis_timeout_minutes` | integer | 10 | Analysis timeout in minutes (1-120) |
| `max_concurrent_analyses` | integer | 5 | Maximum concurrent analyses (1-50) |

### FAISS Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `faiss_index_type` | string | "IndexFlatIP" | FAISS index type |
| `embedding_dimension` | integer | 1536 | Embedding vector dimension |
| `use_gpu_for_faiss` | boolean | false | Use GPU for FAISS operations |
| `faiss_gpu_device` | integer | 0 | GPU device ID for FAISS |

### Performance Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_gpu_acceleration` | boolean | true | Enable GPU acceleration when available |
| `llm_requests_per_minute` | integer | 60 | LLM requests per minute limit |
| `max_tokens_per_request` | integer | 4000 | Maximum tokens per LLM request |

### Security Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `allowed_repo_hosts` | array | ["github.com", "gitlab.com", "bitbucket.org"] | Allowed repository hosts |
| `enable_local_repos` | boolean | true | Enable local repository access |
| `api_key_header` | string | "X-API-Key" | API key header name |
| `cors_origins` | array | ["*"] | CORS allowed origins |

### Monitoring Configuration

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_metrics` | boolean | true | Enable metrics collection |
| `metrics_retention_days` | integer | 30 | Metrics retention period |
| `health_check_interval_seconds` | integer | 60 | Health check interval |

## Configuration Validation

The application performs comprehensive configuration validation on startup and when configuration changes are detected.

### Validation Checks

1. **LLM Configuration**: Validates API keys, endpoints, and provider-specific settings
2. **Storage Configuration**: Checks path accessibility and write permissions
3. **Security Configuration**: Validates security settings and provides warnings
4. **Performance Configuration**: Checks resource limits and provides optimization suggestions

### Validation Errors

If configuration validation fails, the application will:
1. Log detailed error messages
2. Refuse to start (for critical errors)
3. Revert to previous configuration (for hot-reload scenarios)

## Hot Configuration Reloading

The application supports hot configuration reloading when `enable_config_hot_reload` is set to `true` (default).

### Monitored Files
- `.env` files in the project root
- `config/*.json` files
- `config/*.yaml` files

### Reload Behavior
1. File changes are detected automatically
2. Configuration is revalidated
3. If validation passes, new configuration is applied
4. If validation fails, previous configuration is retained
5. Registered callbacks are notified of configuration changes

## Environment-Specific Configuration

### Development
```env
DEBUG=true
LOG_LEVEL=DEBUG
ENABLE_CONFIG_HOT_RELOAD=true
MAX_CONCURRENT_ANALYSES=2
```

### Production
```env
DEBUG=false
LOG_LEVEL=INFO
ENABLE_CONFIG_HOT_RELOAD=false
MAX_CONCURRENT_ANALYSES=10
CORS_ORIGINS=["https://yourdomain.com"]
```

### Docker
```env
API_HOST=0.0.0.0
STORAGE_BASE_PATH=/app/storage
DATABASE_PATH=/app/storage/threat_modeling.db
```

## Troubleshooting

### Common Issues

1. **API Key Errors**
   - Ensure API keys are properly set
   - Check for extra spaces or newlines
   - Verify key permissions and quotas

2. **Storage Errors**
   - Check directory permissions
   - Ensure sufficient disk space
   - Verify path accessibility

3. **Performance Issues**
   - Adjust concurrent analysis limits
   - Check GPU availability settings
   - Monitor resource usage

### Configuration Validation Endpoint

Use the `/config/validate` endpoint to check configuration status:

```bash
curl http://localhost:8000/config/validate
```

### Configuration Summary Endpoint

Get current configuration summary:

```bash
curl http://localhost:8000/config/summary
```

## Security Considerations

1. **API Keys**: Store API keys securely using environment variables or secret management systems
2. **File Permissions**: Ensure configuration files have appropriate permissions (600 or 644)
3. **Network Security**: Configure CORS origins appropriately for production
4. **Local Repository Access**: Disable local repository access in production if not needed
5. **Debug Mode**: Never enable debug mode in production environments

## Best Practices

1. **Environment Variables**: Use environment variables for sensitive configuration
2. **Configuration Files**: Use configuration files for non-sensitive settings
3. **Validation**: Always validate configuration before deployment
4. **Monitoring**: Monitor configuration changes in production
5. **Backup**: Keep backup copies of working configurations
6. **Documentation**: Document any custom configuration changes