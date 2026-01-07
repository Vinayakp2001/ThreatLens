"""Repository parser for detecting components, routes, data stores, and infrastructure."""

import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from ..models.system_model import ComponentType, DataStoreType


class InfrastructureType(Enum):
    """Types of infrastructure configurations."""
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    ANSIBLE = "ansible"
    GITHUB_ACTIONS = "github_actions"
    JENKINS = "jenkins"
    GITLAB_CI = "gitlab_ci"


@dataclass
class ParsedComponent:
    """Represents a detected component in the repository."""
    name: str
    type: ComponentType
    file_path: str
    endpoints: List[str]
    dependencies: List[str]
    security_annotations: List[str]
    authentication_required: bool
    authorization_patterns: List[str]


@dataclass
class ParsedDataStore:
    """Represents a detected data store."""
    name: str
    type: DataStoreType
    connection_string_pattern: Optional[str]
    encryption_enabled: bool
    access_patterns: List[str]
    file_paths: List[str]


@dataclass
class ParsedInfrastructure:
    """Represents detected infrastructure configuration."""
    type: InfrastructureType
    file_path: str
    services: List[str]
    security_configurations: Dict[str, any]
    network_configurations: Dict[str, any]


@dataclass
class ThirdPartyIntegration:
    """Represents a third-party service integration."""
    name: str
    type: str  # API, SDK, Library
    endpoints: List[str]
    authentication_method: Optional[str]
    data_shared: List[str]
    file_paths: List[str]


class RepositoryParser:
    """Parser for analyzing repository structure and extracting security-relevant information."""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.components: List[ParsedComponent] = []
        self.data_stores: List[ParsedDataStore] = []
        self.infrastructure: List[ParsedInfrastructure] = []
        self.third_party_integrations: List[ThirdPartyIntegration] = []
        
        # Patterns for different technologies
        self.web_framework_patterns = {
            'flask': [r'@app\.route\([\'"]([^\'"]+)[\'"]', r'Flask\(__name__\)'],
            'django': [r'path\([\'"]([^\'"]+)[\'"]', r'django\.urls'],
            'fastapi': [r'@app\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]', r'from fastapi'],
            'express': [r'app\.(get|post|put|delete)\([\'"]([^\'"]+)[\'"]', r'express\(\)'],
            'spring': [r'@RequestMapping\([\'"]([^\'"]+)[\'"]', r'@RestController'],
            'asp_net': [r'\[Route\([\'"]([^\'"]+)[\'"]\]', r'ApiController']
        }
        
        self.database_patterns = {
            'postgresql': [r'postgresql://', r'psycopg2', r'asyncpg'],
            'mysql': [r'mysql://', r'pymysql', r'mysql-connector'],
            'mongodb': [r'mongodb://', r'pymongo', r'mongoose'],
            'redis': [r'redis://', r'redis-py', r'ioredis'],
            'sqlite': [r'sqlite://', r'sqlite3', r'\.db$'],
            'elasticsearch': [r'elasticsearch://', r'elasticsearch-py']
        }
        
        self.cloud_service_patterns = {
            'aws': [r'aws-', r'boto3', r'\.amazonaws\.com'],
            'azure': [r'azure-', r'\.azure\.com', r'@azure/'],
            'gcp': [r'google-cloud-', r'\.googleapis\.com', r'gcloud'],
            'firebase': [r'firebase', r'\.firebaseapp\.com']
        }

    def parse_repository(self) -> Dict[str, any]:
        """Parse the entire repository and extract security-relevant information."""
        self._scan_files()
        self._detect_components()
        self._detect_data_stores()
        self._detect_infrastructure()
        self._detect_third_party_integrations()
        
        return {
            'components': self.components,
            'data_stores': self.data_stores,
            'infrastructure': self.infrastructure,
            'third_party_integrations': self.third_party_integrations
        }

    def _scan_files(self) -> None:
        """Scan all files in the repository."""
        self.file_contents = {}
        
        # Skip common directories that don't contain application code
        skip_dirs = {'.git', 'node_modules', '__pycache__', '.pytest_cache', 
                    'venv', '.venv', 'env', '.env', 'build', 'dist', 'target'}
        
        for root, dirs, files in os.walk(self.repo_path):
            # Remove skip directories from dirs list to avoid traversing them
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                file_path = Path(root) / file
                relative_path = file_path.relative_to(self.repo_path)
                
                # Only process text files
                if self._is_text_file(file_path):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            self.file_contents[str(relative_path)] = f.read()
                    except Exception:
                        continue

    def _is_text_file(self, file_path: Path) -> bool:
        """Check if a file is a text file worth analyzing."""
        text_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cs', '.php', '.rb', '.go',
            '.rs', '.cpp', '.c', '.h', '.hpp', '.scala', '.kt', '.swift',
            '.yml', '.yaml', '.json', '.xml', '.toml', '.ini', '.cfg', '.conf',
            '.dockerfile', '.md', '.txt', '.sql', '.sh', '.bash', '.ps1',
            '.tf', '.hcl', '.bicep', '.arm'
        }
        
        return (file_path.suffix.lower() in text_extensions or 
                file_path.name.lower() in {'dockerfile', 'makefile', 'jenkinsfile'})

    def _detect_components(self) -> None:
        """Detect application components like web services, APIs, etc."""
        for file_path, content in self.file_contents.items():
            # Detect web framework components
            for framework, patterns in self.web_framework_patterns.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                    component = self._create_web_component(file_path, content, framework)
                    if component:
                        self.components.append(component)
            
            # Detect microservices
            if self._is_microservice_file(file_path, content):
                component = self._create_microservice_component(file_path, content)
                if component:
                    self.components.append(component)
            
            # Detect background services/workers
            if self._is_background_service(file_path, content):
                component = self._create_background_service_component(file_path, content)
                if component:
                    self.components.append(component)

    def _create_web_component(self, file_path: str, content: str, framework: str) -> Optional[ParsedComponent]:
        """Create a web component from detected framework usage."""
        endpoints = self._extract_endpoints(content, framework)
        dependencies = self._extract_dependencies(content)
        security_annotations = self._extract_security_annotations(content)
        auth_required = self._detect_authentication_requirements(content)
        auth_patterns = self._extract_authorization_patterns(content)
        
        component_name = self._derive_component_name(file_path, framework)
        
        return ParsedComponent(
            name=component_name,
            type=ComponentType.WEB_SERVICE,
            file_path=file_path,
            endpoints=endpoints,
            dependencies=dependencies,
            security_annotations=security_annotations,
            authentication_required=auth_required,
            authorization_patterns=auth_patterns
        )

    def _extract_endpoints(self, content: str, framework: str) -> List[str]:
        """Extract API endpoints from code content."""
        endpoints = []
        
        if framework == 'flask':
            matches = re.findall(r'@app\.route\([\'"]([^\'"]+)[\'"]', content)
            endpoints.extend(matches)
        elif framework == 'django':
            matches = re.findall(r'path\([\'"]([^\'"]+)[\'"]', content)
            endpoints.extend(matches)
        elif framework == 'fastapi':
            matches = re.findall(r'@app\.\w+\([\'"]([^\'"]+)[\'"]', content)
            endpoints.extend(matches)
        elif framework == 'express':
            matches = re.findall(r'app\.\w+\([\'"]([^\'"]+)[\'"]', content)
            endpoints.extend(matches)
        elif framework == 'spring':
            matches = re.findall(r'@RequestMapping\([\'"]([^\'"]+)[\'"]', content)
            matches.extend(re.findall(r'@GetMapping\([\'"]([^\'"]+)[\'"]', content))
            matches.extend(re.findall(r'@PostMapping\([\'"]([^\'"]+)[\'"]', content))
            endpoints.extend(matches)
        
        return list(set(endpoints))

    def _extract_dependencies(self, content: str) -> List[str]:
        """Extract external dependencies and imports."""
        dependencies = []
        
        # Python imports
        python_imports = re.findall(r'(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_]*)', content)
        dependencies.extend(python_imports)
        
        # JavaScript/TypeScript imports
        js_imports = re.findall(r'import.*from\s+[\'"]([^\'"]+)[\'"]', content)
        dependencies.extend(js_imports)
        
        # Java imports
        java_imports = re.findall(r'import\s+([a-zA-Z_][a-zA-Z0-9_.]*)', content)
        dependencies.extend(java_imports)
        
        return list(set(dependencies))

    def _extract_security_annotations(self, content: str) -> List[str]:
        """Extract security-related annotations and decorators."""
        annotations = []
        
        # Common security annotations
        security_patterns = [
            r'@Secured\([\'"]([^\'"]+)[\'"]',
            r'@PreAuthorize\([\'"]([^\'"]+)[\'"]',
            r'@RolesAllowed\([\'"]([^\'"]+)[\'"]',
            r'@login_required',
            r'@require_auth',
            r'@authenticated',
            r'@permission_required\([\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in security_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            annotations.extend(matches if matches else [pattern.split('(')[0].replace('@', '')])
        
        return list(set(annotations))

    def _detect_authentication_requirements(self, content: str) -> bool:
        """Detect if authentication is required."""
        auth_indicators = [
            'login_required', 'authenticate', 'auth_required', 'jwt', 'token',
            'session', 'oauth', 'saml', 'ldap', 'password', 'credential'
        ]
        
        return any(indicator in content.lower() for indicator in auth_indicators)

    def _extract_authorization_patterns(self, content: str) -> List[str]:
        """Extract authorization patterns like RBAC, ABAC."""
        patterns = []
        
        if re.search(r'role|permission|privilege', content, re.IGNORECASE):
            patterns.append('RBAC')
        
        if re.search(r'policy|attribute|context', content, re.IGNORECASE):
            patterns.append('ABAC')
        
        if re.search(r'scope|claim', content, re.IGNORECASE):
            patterns.append('OAuth_Scopes')
        
        return patterns

    def _derive_component_name(self, file_path: str, framework: str) -> str:
        """Derive a meaningful component name from file path and framework."""
        path_parts = Path(file_path).parts
        
        # Use directory name or file name
        if len(path_parts) > 1:
            return f"{path_parts[-2]}_{framework}_service"
        else:
            return f"{Path(file_path).stem}_{framework}_service"

    def _is_microservice_file(self, file_path: str, content: str) -> bool:
        """Check if file represents a microservice."""
        microservice_indicators = [
            'microservice', 'service', 'grpc', 'protobuf', 'consul', 'eureka'
        ]
        
        return any(indicator in content.lower() for indicator in microservice_indicators)

    def _create_microservice_component(self, file_path: str, content: str) -> Optional[ParsedComponent]:
        """Create a microservice component."""
        return ParsedComponent(
            name=f"microservice_{Path(file_path).stem}",
            type=ComponentType.MICROSERVICE,
            file_path=file_path,
            endpoints=self._extract_service_endpoints(content),
            dependencies=self._extract_dependencies(content),
            security_annotations=self._extract_security_annotations(content),
            authentication_required=self._detect_authentication_requirements(content),
            authorization_patterns=self._extract_authorization_patterns(content)
        )

    def _extract_service_endpoints(self, content: str) -> List[str]:
        """Extract service endpoints from microservice code."""
        endpoints = []
        
        # gRPC service definitions
        grpc_services = re.findall(r'service\s+(\w+)', content)
        endpoints.extend([f"grpc://{service}" for service in grpc_services])
        
        # REST endpoints
        rest_endpoints = re.findall(r'[\'"]/([\w/]+)[\'"]', content)
        endpoints.extend(rest_endpoints)
        
        return list(set(endpoints))

    def _is_background_service(self, file_path: str, content: str) -> bool:
        """Check if file represents a background service or worker."""
        background_indicators = [
            'celery', 'worker', 'queue', 'job', 'task', 'scheduler', 'cron'
        ]
        
        return any(indicator in content.lower() for indicator in background_indicators)

    def _create_background_service_component(self, file_path: str, content: str) -> Optional[ParsedComponent]:
        """Create a background service component."""
        return ParsedComponent(
            name=f"background_{Path(file_path).stem}",
            type=ComponentType.BACKGROUND_SERVICE,
            file_path=file_path,
            endpoints=[],
            dependencies=self._extract_dependencies(content),
            security_annotations=self._extract_security_annotations(content),
            authentication_required=False,
            authorization_patterns=[]
        )

    def _detect_data_stores(self) -> None:
        """Detect data stores like databases, caches, file systems."""
        for file_path, content in self.file_contents.items():
            # Check for database connections
            for db_type, patterns in self.database_patterns.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                    data_store = self._create_data_store(file_path, content, db_type)
                    if data_store:
                        self.data_stores.append(data_store)
            
            # Check for file storage patterns
            if self._has_file_storage_patterns(content):
                data_store = self._create_file_storage(file_path, content)
                if data_store:
                    self.data_stores.append(data_store)

    def _create_data_store(self, file_path: str, content: str, db_type: str) -> Optional[ParsedDataStore]:
        """Create a data store from detected database usage."""
        connection_patterns = self._extract_connection_patterns(content, db_type)
        encryption_enabled = self._detect_encryption(content)
        access_patterns = self._extract_data_access_patterns(content)
        
        return ParsedDataStore(
            name=f"{db_type}_store",
            type=self._map_db_type_to_enum(db_type),
            connection_string_pattern=connection_patterns[0] if connection_patterns else None,
            encryption_enabled=encryption_enabled,
            access_patterns=access_patterns,
            file_paths=[file_path]
        )

    def _map_db_type_to_enum(self, db_type: str) -> DataStoreType:
        """Map database type string to enum."""
        mapping = {
            'postgresql': DataStoreType.RELATIONAL_DB,
            'mysql': DataStoreType.RELATIONAL_DB,
            'sqlite': DataStoreType.RELATIONAL_DB,
            'mongodb': DataStoreType.DOCUMENT_DB,
            'redis': DataStoreType.CACHE,
            'elasticsearch': DataStoreType.SEARCH_ENGINE
        }
        return mapping.get(db_type, DataStoreType.RELATIONAL_DB)

    def _extract_connection_patterns(self, content: str, db_type: str) -> List[str]:
        """Extract database connection string patterns."""
        patterns = []
        
        # Look for connection strings
        connection_regex = [
            r'[\'"]([a-zA-Z]+://[^\'"]+)[\'"]',
            r'DATABASE_URL\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'connection\s*=\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for regex in connection_regex:
            matches = re.findall(regex, content)
            patterns.extend(matches)
        
        return patterns

    def _detect_encryption(self, content: str) -> bool:
        """Detect if encryption is configured."""
        encryption_indicators = [
            'encrypt', 'ssl', 'tls', 'cipher', 'crypto', 'aes', 'rsa'
        ]
        
        return any(indicator in content.lower() for indicator in encryption_indicators)

    def _extract_data_access_patterns(self, content: str) -> List[str]:
        """Extract data access patterns."""
        patterns = []
        
        if re.search(r'select|insert|update|delete', content, re.IGNORECASE):
            patterns.append('SQL')
        
        if re.search(r'find|aggregate|update|insert', content, re.IGNORECASE):
            patterns.append('NoSQL')
        
        if re.search(r'get|set|hget|hset', content, re.IGNORECASE):
            patterns.append('Key-Value')
        
        return patterns

    def _has_file_storage_patterns(self, content: str) -> bool:
        """Check for file storage patterns."""
        file_patterns = [
            r'open\s*\(', r'file\s*=', r'with\s+open', r'FileWriter', r'FileReader',
            r'fs\.', r'path\.', r'os\.path', r'pathlib'
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in file_patterns)

    def _create_file_storage(self, file_path: str, content: str) -> Optional[ParsedDataStore]:
        """Create a file storage data store."""
        return ParsedDataStore(
            name="file_storage",
            type=DataStoreType.FILE_SYSTEM,
            connection_string_pattern=None,
            encryption_enabled=self._detect_encryption(content),
            access_patterns=['File_IO'],
            file_paths=[file_path]
        )

    def _detect_infrastructure(self) -> None:
        """Detect infrastructure as code and CI/CD configurations."""
        for file_path, content in self.file_contents.items():
            # Docker
            if 'dockerfile' in file_path.lower() or file_path.endswith('.dockerfile'):
                infra = self._parse_dockerfile(file_path, content)
                if infra:
                    self.infrastructure.append(infra)
            
            # Kubernetes
            if any(k8s_indicator in content.lower() for k8s_indicator in ['apiversion:', 'kind:', 'metadata:']):
                infra = self._parse_kubernetes(file_path, content)
                if infra:
                    self.infrastructure.append(infra)
            
            # Terraform
            if file_path.endswith('.tf') or file_path.endswith('.hcl'):
                infra = self._parse_terraform(file_path, content)
                if infra:
                    self.infrastructure.append(infra)
            
            # CI/CD
            if self._is_cicd_file(file_path):
                infra = self._parse_cicd(file_path, content)
                if infra:
                    self.infrastructure.append(infra)

    def _parse_dockerfile(self, file_path: str, content: str) -> Optional[ParsedInfrastructure]:
        """Parse Dockerfile for security configurations."""
        services = []
        security_configs = {}
        
        # Extract base images
        base_images = re.findall(r'FROM\s+([^\s]+)', content, re.IGNORECASE)
        services.extend(base_images)
        
        # Check for security practices
        if 'USER ' in content.upper():
            security_configs['non_root_user'] = True
        
        if '--no-cache' in content:
            security_configs['cache_disabled'] = True
        
        return ParsedInfrastructure(
            type=InfrastructureType.DOCKER,
            file_path=file_path,
            services=services,
            security_configurations=security_configs,
            network_configurations={}
        )

    def _parse_kubernetes(self, file_path: str, content: str) -> Optional[ParsedInfrastructure]:
        """Parse Kubernetes manifests."""
        try:
            docs = yaml.safe_load_all(content)
            services = []
            security_configs = {}
            network_configs = {}
            
            for doc in docs:
                if not doc:
                    continue
                
                kind = doc.get('kind', '')
                services.append(kind)
                
                # Check security contexts
                if 'securityContext' in str(doc):
                    security_configs['security_context'] = True
                
                # Check network policies
                if kind == 'NetworkPolicy':
                    network_configs['network_policy'] = True
            
            return ParsedInfrastructure(
                type=InfrastructureType.KUBERNETES,
                file_path=file_path,
                services=services,
                security_configurations=security_configs,
                network_configurations=network_configs
            )
        except Exception:
            return None

    def _parse_terraform(self, file_path: str, content: str) -> Optional[ParsedInfrastructure]:
        """Parse Terraform configurations."""
        services = []
        security_configs = {}
        
        # Extract resource types
        resources = re.findall(r'resource\s+"([^"]+)"', content)
        services.extend(resources)
        
        # Check for security groups
        if 'aws_security_group' in content:
            security_configs['security_groups'] = True
        
        # Check for encryption
        if 'encryption' in content.lower():
            security_configs['encryption_configured'] = True
        
        return ParsedInfrastructure(
            type=InfrastructureType.TERRAFORM,
            file_path=file_path,
            services=services,
            security_configurations=security_configs,
            network_configurations={}
        )

    def _is_cicd_file(self, file_path: str) -> bool:
        """Check if file is a CI/CD configuration."""
        cicd_patterns = [
            '.github/workflows/', 'jenkinsfile', '.gitlab-ci.yml', 
            'azure-pipelines.yml', '.circleci/', 'buildspec.yml'
        ]
        
        return any(pattern in file_path.lower() for pattern in cicd_patterns)

    def _parse_cicd(self, file_path: str, content: str) -> Optional[ParsedInfrastructure]:
        """Parse CI/CD configurations."""
        if '.github/workflows/' in file_path:
            return self._parse_github_actions(file_path, content)
        elif 'jenkinsfile' in file_path.lower():
            return self._parse_jenkins(file_path, content)
        elif '.gitlab-ci.yml' in file_path:
            return self._parse_gitlab_ci(file_path, content)
        
        return None

    def _parse_github_actions(self, file_path: str, content: str) -> Optional[ParsedInfrastructure]:
        """Parse GitHub Actions workflow."""
        try:
            workflow = yaml.safe_load(content)
            services = []
            security_configs = {}
            
            if 'jobs' in workflow:
                for job_name, job_config in workflow['jobs'].items():
                    services.append(f"job_{job_name}")
                    
                    # Check for security scanning
                    if 'uses' in str(job_config) and any(sec in str(job_config).lower() 
                                                        for sec in ['security', 'scan', 'sast']):
                        security_configs['security_scanning'] = True
            
            return ParsedInfrastructure(
                type=InfrastructureType.GITHUB_ACTIONS,
                file_path=file_path,
                services=services,
                security_configurations=security_configs,
                network_configurations={}
            )
        except Exception:
            return None

    def _parse_jenkins(self, file_path: str, content: str) -> Optional[ParsedInfrastructure]:
        """Parse Jenkins pipeline."""
        services = ['jenkins_pipeline']
        security_configs = {}
        
        if 'credentials' in content.lower():
            security_configs['credentials_used'] = True
        
        return ParsedInfrastructure(
            type=InfrastructureType.JENKINS,
            file_path=file_path,
            services=services,
            security_configurations=security_configs,
            network_configurations={}
        )

    def _parse_gitlab_ci(self, file_path: str, content: str) -> Optional[ParsedInfrastructure]:
        """Parse GitLab CI configuration."""
        try:
            config = yaml.safe_load(content)
            services = []
            security_configs = {}
            
            # Extract stages and jobs
            if isinstance(config, dict):
                for key, value in config.items():
                    if isinstance(value, dict) and 'script' in value:
                        services.append(f"job_{key}")
            
            return ParsedInfrastructure(
                type=InfrastructureType.GITLAB_CI,
                file_path=file_path,
                services=services,
                security_configurations=security_configs,
                network_configurations={}
            )
        except Exception:
            return None

    def _detect_third_party_integrations(self) -> None:
        """Detect third-party service integrations."""
        for file_path, content in self.file_contents.items():
            # Cloud service integrations
            for cloud, patterns in self.cloud_service_patterns.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                    integration = self._create_cloud_integration(file_path, content, cloud)
                    if integration:
                        self.third_party_integrations.append(integration)
            
            # API integrations
            api_integrations = self._detect_api_integrations(file_path, content)
            self.third_party_integrations.extend(api_integrations)

    def _create_cloud_integration(self, file_path: str, content: str, cloud: str) -> Optional[ThirdPartyIntegration]:
        """Create a cloud service integration."""
        endpoints = self._extract_cloud_endpoints(content, cloud)
        auth_method = self._detect_cloud_auth_method(content, cloud)
        data_shared = self._extract_data_shared_with_cloud(content)
        
        return ThirdPartyIntegration(
            name=f"{cloud}_integration",
            type="Cloud_Service",
            endpoints=endpoints,
            authentication_method=auth_method,
            data_shared=data_shared,
            file_paths=[file_path]
        )

    def _extract_cloud_endpoints(self, content: str, cloud: str) -> List[str]:
        """Extract cloud service endpoints."""
        endpoints = []
        
        if cloud == 'aws':
            aws_services = re.findall(r'([a-z0-9-]+)\.amazonaws\.com', content)
            endpoints.extend([f"https://{service}.amazonaws.com" for service in aws_services])
        elif cloud == 'azure':
            azure_services = re.findall(r'([a-z0-9-]+)\.azure\.com', content)
            endpoints.extend([f"https://{service}.azure.com" for service in azure_services])
        elif cloud == 'gcp':
            gcp_services = re.findall(r'([a-z0-9-]+)\.googleapis\.com', content)
            endpoints.extend([f"https://{service}.googleapis.com" for service in gcp_services])
        
        return list(set(endpoints))

    def _detect_cloud_auth_method(self, content: str, cloud: str) -> Optional[str]:
        """Detect cloud authentication method."""
        if 'api_key' in content.lower() or 'apikey' in content.lower():
            return 'API_Key'
        elif 'oauth' in content.lower():
            return 'OAuth'
        elif 'iam' in content.lower():
            return 'IAM'
        elif 'service_account' in content.lower():
            return 'Service_Account'
        
        return None

    def _extract_data_shared_with_cloud(self, content: str) -> List[str]:
        """Extract types of data shared with cloud services."""
        data_types = []
        
        if re.search(r'user|customer|personal', content, re.IGNORECASE):
            data_types.append('User_Data')
        
        if re.search(r'payment|credit|financial', content, re.IGNORECASE):
            data_types.append('Financial_Data')
        
        if re.search(r'health|medical|hipaa', content, re.IGNORECASE):
            data_types.append('Health_Data')
        
        if re.search(r'log|audit|monitoring', content, re.IGNORECASE):
            data_types.append('Log_Data')
        
        return data_types

    def _detect_api_integrations(self, file_path: str, content: str) -> List[ThirdPartyIntegration]:
        """Detect third-party API integrations."""
        integrations = []
        
        # Look for HTTP client usage and external URLs
        http_patterns = [
            r'requests\.(?:get|post|put|delete)\([\'"]([^\'"]+)[\'"]',
            r'fetch\([\'"]([^\'"]+)[\'"]',
            r'axios\.(?:get|post|put|delete)\([\'"]([^\'"]+)[\'"]',
            r'http://([^/\s\'\"]+)',
            r'https://([^/\s\'\"]+)'
        ]
        
        external_urls = []
        for pattern in http_patterns:
            matches = re.findall(pattern, content)
            external_urls.extend(matches)
        
        # Filter out localhost and internal URLs
        external_urls = [url for url in external_urls 
                        if not any(internal in url.lower() 
                                 for internal in ['localhost', '127.0.0.1', '0.0.0.0', 'internal'])]
        
        if external_urls:
            integration = ThirdPartyIntegration(
                name="external_api_integration",
                type="API",
                endpoints=list(set(external_urls)),
                authentication_method=self._detect_api_auth_method(content),
                data_shared=self._extract_api_data_shared(content),
                file_paths=[file_path]
            )
            integrations.append(integration)
        
        return integrations

    def _detect_api_auth_method(self, content: str) -> Optional[str]:
        """Detect API authentication method."""
        if re.search(r'bearer|jwt|token', content, re.IGNORECASE):
            return 'Bearer_Token'
        elif re.search(r'basic.*auth', content, re.IGNORECASE):
            return 'Basic_Auth'
        elif re.search(r'api.*key', content, re.IGNORECASE):
            return 'API_Key'
        elif re.search(r'oauth', content, re.IGNORECASE):
            return 'OAuth'
        
        return None

    def _extract_api_data_shared(self, content: str) -> List[str]:
        """Extract data types shared with external APIs."""
        data_types = []
        
        if re.search(r'json|payload|data', content, re.IGNORECASE):
            data_types.append('JSON_Data')
        
        if re.search(r'form|multipart', content, re.IGNORECASE):
            data_types.append('Form_Data')
        
        if re.search(r'file|upload|binary', content, re.IGNORECASE):
            data_types.append('File_Data')
        
        return data_types