# ThreatLens

An AI-powered tool that automatically generates comprehensive threat modeling documentation from code repositories using OWASP methodologies and Large Language Models (LLMs).

## 🚀 Features

- **Automated Repository Analysis**: Analyzes code repositories to identify components, data flows, and security patterns
- **AI-Powered Documentation**: Uses LLMs to generate OWASP-compliant threat modeling documents
- **STRIDE Methodology**: Implements STRIDE threat modeling framework for comprehensive security analysis
- **RAG-Enhanced Context**: Uses Retrieval-Augmented Generation for improved document quality
- **Multiple LLM Providers**: Supports OpenAI, Azure OpenAI, and other compatible providers
- **REST API**: Complete FastAPI-based REST API for integration
- **Real-time Monitoring**: Comprehensive monitoring, metrics, and alerting system
- **Scalable Architecture**: Built for production with error recovery and concurrency control

## 📋 Generated Documents

The system generates four types of threat modeling documents:

1. **System Security Overview**: High-level security architecture and components
2. **Component Security Profiles**: Detailed security analysis for each component
3. **Flow Threat Models**: STRIDE-based threat analysis for data flows
4. **Mitigations & Requirements**: Security recommendations and implementation guidance

## 🛠️ Installation

### Prerequisites

- Python 3.8+
- Git
- OpenAI API key (or compatible LLM provider)

### Quick Start

1. **Clone the repository**:
```bash
git clone https://github.com/Vinayakp2001/ThreatLens.git
cd ThreatLens
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Configure the application**:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Start the application**:
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

5. **Access the API**:
- API Documentation: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

## ⚙️ Configuration

The application uses environment variables for configuration. See [Configuration Guide](config/README.md) for detailed information.

### Essential Configuration

```env
# LLM Configuration
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-4

# Storage Configuration
STORAGE_BASE_PATH=./storage
MAX_REPO_SIZE_MB=100
MAX_CONCURRENT_ANALYSES=5

# Security Configuration
ALLOWED_REPO_HOSTS=["github.com", "gitlab.com", "bitbucket.org"]
ENABLE_LOCAL_REPOS=true
```

## 🔧 Usage

### API Endpoints

#### Repository Analysis
```bash
# Analyze a GitHub repository
curl -X POST "http://localhost:8000/analyze_repo" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo.git"}'

# Analyze a local repository
curl -X POST "http://localhost:8000/analyze_repo" \
  -H "Content-Type: application/json" \
  -d '{"local_path": "/path/to/repo"}'
```

#### Document Retrieval
```bash
# Get all documents for a repository
curl "http://localhost:8000/repos/{repo_id}/documents"

# Get a specific document
curl "http://localhost:8000/repos/{repo_id}/documents/{doc_id}"

# Search documents
curl -X POST "http://localhost:8000/search_docs" \
  -H "Content-Type: application/json" \
  -d '{"query": "authentication vulnerabilities", "limit": 10}'
```

#### System Monitoring
```bash
# Get system health
curl "http://localhost:8000/health/comprehensive"

# Get metrics
curl "http://localhost:8000/metrics"

# Get system diagnostics
curl "http://localhost:8000/diagnostics"
```

### Python SDK Example

```python
import httpx

# Initialize client
client = httpx.Client(base_url="http://localhost:8000")

# Analyze repository
response = client.post("/analyze_repo", json={
    "repo_url": "https://github.com/user/repo.git"
})
analysis = response.json()

# Get generated documents
docs_response = client.get(f"/repos/{analysis['repo_id']}/documents")
documents = docs_response.json()

print(f"Generated {len(documents['documents'])} threat modeling documents")
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │   Repository    │    │   Security      │
│   REST API      │───▶│   Ingestor      │───▶│   Model Builder │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Document      │    │   RAG System    │    │   LLM Client    │
│   Generator     │◀───│   (FAISS)       │◀───│   (OpenAI)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SQLite        │    │   Storage       │    │   Monitoring    │
│   Database      │    │   Manager       │    │   & Metrics     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 📊 Monitoring & Operations

The system includes comprehensive monitoring and operational features:

- **Real-time Metrics**: System and application metrics collection
- **Health Checks**: Automated health monitoring for all components
- **Alerting**: Configurable alerts for system issues
- **Performance Tracking**: Request timing, throughput, and error rates
- **Storage Management**: Automated cleanup and quota management
- **Configuration Management**: Hot-reloadable configuration with validation

Access monitoring endpoints:
- Metrics: `/metrics`
- Health: `/health/comprehensive`
- Diagnostics: `/diagnostics`
- Alerts: `/alerts`

## 🔒 Security Considerations

- **API Keys**: Store API keys securely using environment variables
- **Repository Access**: Configure allowed repository hosts
- **Local Repository Access**: Disable in production if not needed
- **CORS Configuration**: Set appropriate CORS origins for production
- **Debug Mode**: Never enable debug mode in production

## 🚀 Deployment

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Production Configuration

```env
DEBUG=false
LOG_LEVEL=INFO
ENABLE_CONFIG_HOT_RELOAD=false
MAX_CONCURRENT_ANALYSES=10
CORS_ORIGINS=["https://yourdomain.com"]
```

## 🧪 Development

### Running Tests

```bash
# Install development dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/
```

### Code Quality

```bash
# Format code
black api/

# Lint code
flake8 api/

# Type checking
mypy api/
```

## 📚 Documentation

- [Configuration Guide](config/README.md) - Comprehensive configuration documentation
- [API Documentation](http://localhost:8000/docs) - Interactive API documentation
- [Architecture Design](.kiro/specs/threat-modeling-generator/design.md) - System architecture and design
- [Requirements](.kiro/specs/threat-modeling-generator/requirements.md) - System requirements and specifications

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling) - Methodology and best practices
- [STRIDE Framework](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) - Threat categorization
- [FastAPI](https://fastapi.tiangolo.com/) - Modern web framework for APIs
- [OpenAI](https://openai.com/) - Large Language Model capabilities

## 📞 Support

- Create an [Issue](https://github.com/Vinayakp2001/ThreatLens/issues) for bug reports or feature requests
- Check the [Documentation](config/README.md) for configuration help
- Review [API Documentation](http://localhost:8000/docs) for usage examples

---

**ThreatLens - Built with ❤️ for the security community**