# ThreatLens - Security Wiki Generator

<div align="center">

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)
![Vue.js](https://img.shields.io/badge/Vue.js-3.0+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)
![AI](https://img.shields.io/badge/AI-powered-orange.svg)

**An AI-powered security documentation platform that automatically generates comprehensive security analysis from code repositories**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [API Documentation](#api-documentation) • [Contributing](#contributing)

</div>

---

## Overview

ThreatLens transforms code repositories into comprehensive security documentation using advanced AI analysis. Built for security professionals, it provides DeepWiki-style documentation generation specifically focused on security assessment and vulnerability analysis.

The platform offers dual analysis modes: complete repository security assessment and context-aware pull request security reviews, powered by retrieval-augmented generation (RAG) for intelligent, contextual analysis.

## Features

### Core Capabilities

**Comprehensive Security Analysis**
- Authentication and authorization mechanism assessment
- Data flow security and privacy analysis
- API security evaluation based on OWASP guidelines
- Automated vulnerability identification and risk assessment
- Actionable security recommendations and remediation guidance

**AI-Powered Intelligence**
- Support for multiple LLM providers (OpenAI, Azure OpenAI, compatible APIs)
- Advanced RAG system with FAISS vector search
- Context-aware analysis using existing repository knowledge
- Intelligent resource management with GPU/CPU optimization

**Dual Analysis Modes**
- **Repository Analysis**: Complete security assessment with knowledge base creation
- **PR Security Review**: Context-aware security analysis of pull requests
- Smart routing between analysis modes based on available context
- Integration with GitHub API for seamless PR analysis

**Production-Ready Architecture**
- RESTful API built with FastAPI
- Modern Vue.js frontend with responsive design
- SQLite database with comprehensive migration system
- Docker containerization support
- Comprehensive monitoring and metrics collection

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Vue.js        │    │   FastAPI       │    │   Security      │
│   Frontend      │───▶│   REST API      │───▶│   Wiki Gen      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PR Analysis   │    │   Repository    │    │   Knowledge     │
│   Interface     │◀───│   Analyzer      │───▶│   Base Manager  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   RAG System    │    │   FAISS Vector  │    │   LLM Client    │
│   (Embeddings)  │◀───│   Search        │◀───│   (OpenAI)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Installation

### Prerequisites

- Python 3.8 or higher
- Node.js 16.0 or higher
- OpenAI API key or compatible LLM provider
- Git

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/Vinayakp2001/ThreatLens.git
cd ThreatLens
```

2. **Backend setup**
```bash
pip install -r requirements.txt
cp .env.example .env
# Configure your API keys and settings in .env
```

3. **Frontend setup**
```bash
cd frontend
npm install
npm run build
cd ..
```

4. **Start the application**
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

5. **Access the application**
- Frontend: http://localhost:5173
- API Documentation: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

## Configuration

### Environment Variables

```env
# LLM Configuration
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-4

# GitHub Integration
GITHUB_TOKEN=ghp_your-github-token

# Storage Configuration
STORAGE_BASE_PATH=./storage
DATABASE_PATH=./data/threatlens.db

# Security Configuration
ALLOWED_REPO_HOSTS=["github.com", "gitlab.com", "bitbucket.org"]
ENABLE_LOCAL_REPOS=true
```

For detailed configuration options, see the [Configuration Guide](config/README.md).

## Usage

### Web Interface

**Repository Analysis**
1. Navigate to the main interface
2. Enter repository URL or local path
3. Click "Analyze Repository"
4. Review generated security documentation

**PR Security Review**
1. Switch to "PR Analysis" mode
2. Enter PR URL (e.g., `https://github.com/user/repo/pull/123`)
3. Receive context-aware security assessment
4. Review security impact and recommendations

### API Endpoints

#### Repository Analysis
```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/user/repo.git"}'
```

#### PR Security Analysis
```bash
curl -X POST "http://localhost:8000/analyze_pr" \
  -H "Content-Type: application/json" \
  -d '{"pr_url": "https://github.com/user/repo/pull/123"}'
```

#### Repository Status Check
```bash
curl "http://localhost:8000/repo_status/user-repo"
```

#### Security Knowledge Search
```bash
curl -X POST "http://localhost:8000/search_docs" \
  -H "Content-Type: application/json" \
  -d '{"query": "authentication vulnerabilities", "repo_id": "user-repo"}'
```

## Security Analysis Features

### Comprehensive Assessment
- **OWASP Top 10 Analysis**: Automated detection of common vulnerabilities
- **Authentication Review**: In-depth analysis of authentication mechanisms
- **Authorization Assessment**: Access control and privilege evaluation
- **Data Flow Security**: Data protection and privacy compliance analysis
- **API Security**: RESTful API security evaluation

### Context-Aware PR Analysis
- **Change Impact Assessment**: Security implications of code modifications
- **Risk Evaluation**: Automated risk scoring for pull request changes
- **Contextual Recommendations**: Security guidance based on repository knowledge
- **Integration Analysis**: Impact assessment on existing security controls

## Docker Deployment

### Using Docker Compose
```bash
docker-compose up -d
```

### Manual Docker Build
```bash
docker build -t threatlens .
docker run -p 8000:8000 -e OPENAI_API_KEY=your-key threatlens
```

## API Documentation

Interactive API documentation is available at `/docs` when the application is running. The API provides comprehensive endpoints for:

- Repository analysis and management
- PR security assessment
- Security knowledge search and retrieval
- System health and monitoring
- Configuration management

## Development

### Running Tests
```bash
# Backend tests
pytest api/tests/

# Frontend tests
cd frontend && npm test
```

### Code Quality
```bash
# Python code formatting
black api/

# Python linting
flake8 api/

# Frontend formatting
cd frontend && npm run format
```

## Contributing

We welcome contributions from the security and development community. Please read our contributing guidelines before submitting pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/security-enhancement`)
3. Commit your changes (`git commit -m 'Add security enhancement'`)
4. Push to the branch (`git push origin feature/security-enhancement`)
5. Open a Pull Request

## Documentation

- **[API Documentation](http://localhost:8000/docs)** - Interactive API reference
- **[Configuration Guide](config/README.md)** - Comprehensive configuration documentation
- **[GitHub Integration](config/github_setup.md)** - GitHub API setup and configuration

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **[DeepWiki](https://github.com/deepwiki/deepwiki)** - Inspiration for comprehensive documentation generation
- **[OWASP](https://owasp.org/)** - Security methodologies and best practices
- **[FastAPI](https://fastapi.tiangolo.com/)** - Modern Python web framework
- **[Vue.js](https://vuejs.org/)** - Progressive JavaScript framework

## Support

- **Issues**: [GitHub Issues](https://github.com/Vinayakp2001/ThreatLens/issues)
- **Documentation**: [Configuration Guide](config/README.md)
- **API Reference**: [Interactive Documentation](http://localhost:8000/docs)

---

**ThreatLens - Security Documentation Made Intelligent**