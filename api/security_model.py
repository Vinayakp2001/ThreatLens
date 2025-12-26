"""
Security model building system for threat modeling
"""
import os
import re
import ast
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
import logging

from .models import (
    Component, ComponentType, Endpoint, SecurityModel, 
    RepoContext, DataStore, DataStoreType, SecurityPatterns,
    TrustBoundary, Flow, FlowStep, FlowType, DataSensitivityLevel
)
from .repo_ingest import StructureAnalyzer

logger = logging.getLogger(__name__)


class SecurityModelBuilder:
    """Builds comprehensive security models from repository analysis"""
    
    def __init__(self):
        self.structure_analyzer = StructureAnalyzer()
        self.component_patterns = self._initialize_security_patterns()
        
    def build_security_model(self, repo_context: RepoContext) -> SecurityModel:
        """
        Build a comprehensive security model from repository context
        
        Args:
            repo_context: Repository context with analysis data
            
        Returns:
            SecurityModel with detailed security analysis
        """
        logger.info(f"Building security model for repository {repo_context.repo_id}")
        
        # Get basic structure analysis
        component_analysis = repo_context.structure_summary.get('component_analysis', {})
        
        # Build enhanced component detection
        components = self._detect_security_components(repo_context, component_analysis)
        
        # Detect data stores
        data_stores = self._detect_data_stores(repo_context, components)
        
        # Build dependency mapping
        self._build_dependency_mapping(components, repo_context)
        
        # Detect security patterns across the codebase
        security_patterns = self._detect_security_patterns(repo_context, components)
        
        # Identify trust boundaries
        trust_boundaries = self._identify_trust_boundaries(repo_context, components, data_stores)
        
        # Build data flow analysis
        flows = self._build_data_flow_analysis(repo_context, components, data_stores, trust_boundaries)
        
        # Create security model
        security_model = SecurityModel(
            repo_id=repo_context.repo_id,
            components=components,
            data_stores=data_stores,
            flows=flows,
            security_patterns=security_patterns,
            trust_boundaries=trust_boundaries
        )
        
        logger.info(f"Security model built: {len(components)} components, {len(data_stores)} data stores, {len(flows)} flows, {len(trust_boundaries)} trust boundaries")
        return security_model
    
    def _detect_security_components(self, repo_context: RepoContext, component_analysis: Dict) -> List[Component]:
        """Detect and classify security-relevant components"""
        components = []
        repo_path = Path(repo_context.local_path)
        
        # Process each file type from basic analysis
        for component_type, file_list in component_analysis.get('components', {}).items():
            for file_info in file_list:
                component = self._analyze_security_component(
                    file_info, repo_path, component_type
                )
                if component:
                    components.append(component)
        
        # Additional security-focused scanning
        additional_components = self._scan_for_security_components(repo_path, repo_context)
        components.extend(additional_components)
        
        return components
    
    def _analyze_security_component(self, file_info: Dict, repo_path: Path, component_type: str) -> Optional[Component]:
        """Analyze a single file for security-relevant information"""
        file_path = repo_path / file_info['file_path']
        
        try:
            content = self._read_file_safely(str(file_path))
            if not content:
                return None
            
            # Extract detailed security information
            endpoints = self._extract_detailed_endpoints(content, file_info.get('language', ''))
            auth_mechanisms = self._detect_auth_mechanisms(content)
            external_deps = self._detect_external_dependencies(content, file_info.get('language', ''))
            sensitive_data_handling = self._detect_sensitive_data_patterns(content)
            
            # Map component type
            comp_type = self._map_component_type(component_type, content)
            
            # Create safe ID by replacing path separators
            safe_path = file_info['file_path'].replace('/', '_').replace('\\', '_')
            
            # Create component
            component = Component(
                id=f"{repo_path.name}_{safe_path}",
                name=Path(file_info['file_path']).stem,
                type=comp_type,
                file_path=file_info['file_path'],
                endpoints=endpoints,
                dependencies=external_deps,
                handles_sensitive_data=sensitive_data_handling,
                auth_mechanisms=auth_mechanisms,
                description=self._generate_component_description(file_info, content)
            )
            
            return component
            
        except Exception as e:
            logger.warning(f"Error analyzing component {file_info['file_path']}: {e}")
            return None
    
    def _extract_detailed_endpoints(self, content: str, language: str) -> List[Endpoint]:
        """Extract detailed API endpoint information"""
        endpoints = []
        
        if language in ['Python', 'JavaScript', 'TypeScript']:
            endpoints.extend(self._extract_python_js_endpoints(content))
        elif language == 'Java':
            endpoints.extend(self._extract_java_endpoints(content))
        elif language == 'Go':
            endpoints.extend(self._extract_go_endpoints(content))
        
        return endpoints
    
    def _extract_python_js_endpoints(self, content: str) -> List[Endpoint]:
        """Extract endpoints from Python/JavaScript/TypeScript code"""
        endpoints = []
        
        # Flask/FastAPI patterns
        flask_patterns = [
            r'@app\.route\([\'"]([^\'"]+)[\'"].*?methods\s*=\s*\[[\'"]([^\'"]+)[\'"]',
            r'@router\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            r'app\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]'
        ]
        
        # Express.js patterns
        express_patterns = [
            r'router\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
            r'app\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]'
        ]
        
        all_patterns = flask_patterns + express_patterns
        
        for pattern in all_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                groups = match.groups()
                if len(groups) >= 2:
                    if len(groups) == 2 and 'methods' in pattern:
                        # Flask route with methods
                        path, method = groups
                    else:
                        # Method first, then path
                        method, path = groups[0], groups[1]
                    
                    # Check for authentication requirements
                    line_start = content.rfind('\n', 0, match.start()) + 1
                    line_end = content.find('\n', match.end())
                    if line_end == -1:
                        line_end = len(content)
                    
                    context_lines = content[max(0, line_start - 200):line_end + 200]
                    requires_auth = self._check_auth_requirement(context_lines)
                    sensitive_data = self._check_sensitive_data_endpoint(context_lines, path)
                    
                    # Extract handler function name
                    handler_match = re.search(r'def\s+(\w+)|function\s+(\w+)|const\s+(\w+)\s*=', 
                                            content[match.end():match.end() + 100])
                    handler_function = None
                    if handler_match:
                        handler_function = next(g for g in handler_match.groups() if g)
                    
                    endpoint = Endpoint(
                        path=path,
                        method=method.upper(),
                        handler_function=handler_function,
                        requires_auth=requires_auth,
                        sensitive_data=sensitive_data
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_java_endpoints(self, content: str) -> List[Endpoint]:
        """Extract endpoints from Java Spring Boot code"""
        endpoints = []
        
        # Spring Boot mapping patterns
        patterns = [
            r'@(Get|Post|Put|Delete|Patch)Mapping\([\'"]([^\'"]+)[\'"]',
            r'@RequestMapping\([^)]*value\s*=\s*[\'"]([^\'"]+)[\'"][^)]*method\s*=\s*RequestMethod\.(\w+)',
            r'@RequestMapping\([^)]*method\s*=\s*RequestMethod\.(\w+)[^)]*value\s*=\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                groups = match.groups()
                if len(groups) >= 2:
                    if 'RequestMapping' in pattern:
                        if groups[0].startswith('/'):
                            path, method = groups[0], groups[1]
                        else:
                            method, path = groups[0], groups[1]
                    else:
                        method, path = groups[0], groups[1]
                    
                    # Check for Spring Security annotations
                    context = content[max(0, match.start() - 300):match.end() + 100]
                    requires_auth = bool(re.search(r'@PreAuthorize|@Secured|@RolesAllowed', context))
                    sensitive_data = self._check_sensitive_data_endpoint(context, path)
                    
                    endpoint = Endpoint(
                        path=path,
                        method=method.upper(),
                        requires_auth=requires_auth,
                        sensitive_data=sensitive_data
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_go_endpoints(self, content: str) -> List[Endpoint]:
        """Extract endpoints from Go HTTP handlers"""
        endpoints = []
        
        # Go HTTP patterns
        patterns = [
            r'http\.HandleFunc\([\'"]([^\'"]+)[\'"]',
            r'router\.(GET|POST|PUT|DELETE|PATCH)\([\'"]([^\'"]+)[\'"]',
            r'mux\.HandleFunc\([\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                groups = match.groups()
                if len(groups) >= 1:
                    if len(groups) == 2:
                        method, path = groups[0], groups[1]
                    else:
                        path = groups[0]
                        method = 'HTTP'  # Generic HTTP handler
                    
                    context = content[match.start():match.end() + 200]
                    requires_auth = 'auth' in context.lower()
                    sensitive_data = self._check_sensitive_data_endpoint(context, path)
                    
                    endpoint = Endpoint(
                        path=path,
                        method=method.upper(),
                        requires_auth=requires_auth,
                        sensitive_data=sensitive_data
                    )
                    endpoints.append(endpoint)
        
        return endpoints
    
    def _detect_auth_mechanisms(self, content: str) -> List[str]:
        """Detect authentication mechanisms in code"""
        auth_mechanisms = []
        
        auth_patterns = {
            'JWT': [r'jwt|JWT|jsonwebtoken', r'token.*verify|verify.*token'],
            'Session': [r'session|Session', r'flask_session|express-session'],
            'OAuth': [r'oauth|OAuth|passport', r'google.*auth|github.*auth'],
            'Basic Auth': [r'basic.*auth|BasicAuth', r'Authorization.*Basic'],
            'API Key': [r'api.*key|apikey|x-api-key', r'Authorization.*Bearer'],
            'Cookie Auth': [r'cookie.*auth|secure.*cookie', r'@login_required'],
            'LDAP': [r'ldap|LDAP', r'ActiveDirectory'],
            'SAML': [r'saml|SAML', r'SingleSignOn']
        }
        
        for mechanism, patterns in auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    auth_mechanisms.append(mechanism)
                    break
        
        return list(set(auth_mechanisms))
    
    def _detect_external_dependencies(self, content: str, language: str) -> List[str]:
        """Detect external service dependencies"""
        dependencies = []
        
        # Database connections
        db_patterns = [
            r'mysql|MySQL|postgresql|PostgreSQL|sqlite|SQLite',
            r'mongodb|MongoDB|redis|Redis|elasticsearch|Elasticsearch',
            r'oracle|Oracle|sqlserver|SQL.*Server'
        ]
        
        for pattern in db_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                dependencies.append(f"Database: {pattern.split('|')[0]}")
        
        # External APIs
        api_patterns = [
            r'requests\.get|requests\.post|fetch\(|axios\.',
            r'http\.Get|http\.Post|HttpClient',
            r'RestTemplate|WebClient'
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, content):
                dependencies.append("External API")
                break
        
        # Message queues
        queue_patterns = [
            r'rabbitmq|RabbitMQ|kafka|Kafka|sqs|SQS',
            r'celery|Celery|sidekiq|Sidekiq'
        ]
        
        for pattern in queue_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                dependencies.append(f"Message Queue: {pattern.split('|')[0]}")
        
        # Cloud services
        cloud_patterns = [
            r'aws|AWS|s3|S3|ec2|EC2',
            r'azure|Azure|gcp|GCP|google.*cloud'
        ]
        
        for pattern in cloud_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                dependencies.append(f"Cloud Service: {pattern.split('|')[0]}")
        
        return list(set(dependencies))
    
    def _detect_sensitive_data_patterns(self, content: str) -> bool:
        """Detect if component handles sensitive data"""
        sensitive_patterns = [
            r'password|secret|key|token|credential',
            r'ssn|social.*security|credit.*card|payment',
            r'email|phone|address|personal.*data|pii|PII',
            r'encrypt|decrypt|hash|bcrypt|scrypt',
            r'private.*key|public.*key|certificate'
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _check_auth_requirement(self, context: str) -> bool:
        """Check if endpoint requires authentication"""
        auth_indicators = [
            r'@login_required|@auth_required|@authenticated',
            r'@PreAuthorize|@Secured|@RolesAllowed',
            r'requireAuth|authenticate|authorize',
            r'jwt.*required|token.*required'
        ]
        
        for pattern in auth_indicators:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _check_sensitive_data_endpoint(self, context: str, path: str) -> bool:
        """Check if endpoint handles sensitive data"""
        # Check path for sensitive indicators
        sensitive_paths = [
            r'/auth|/login|/password|/payment|/admin',
            r'/user|/profile|/account|/personal'
        ]
        
        for pattern in sensitive_paths:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        # Check context for sensitive data handling
        return self._detect_sensitive_data_patterns(context)
    
    def _map_component_type(self, basic_type: str, content: str) -> ComponentType:
        """Map basic component type to security-focused ComponentType"""
        type_mapping = {
            'controller': ComponentType.CONTROLLER,
            'service': ComponentType.SERVICE,
            'model': ComponentType.MODEL,
            'middleware': ComponentType.MIDDLEWARE,
            'utility': ComponentType.UTILITY
        }
        
        # Check for worker/background job patterns
        if basic_type == 'service' and re.search(r'celery|sidekiq|job|worker|task', content, re.IGNORECASE):
            return ComponentType.WORKER
        
        return type_mapping.get(basic_type, ComponentType.UTILITY)
    
    def _generate_component_description(self, file_info: Dict, content: str) -> str:
        """Generate a description for the component"""
        descriptions = []
        
        # Add basic info
        descriptions.append(f"{file_info.get('language', 'Unknown')} {file_info.get('type', 'component')}")
        
        # Add endpoint count
        endpoint_count = len(file_info.get('endpoints', []))
        if endpoint_count > 0:
            descriptions.append(f"{endpoint_count} API endpoints")
        
        # Add auth info
        if file_info.get('has_auth_logic'):
            descriptions.append("handles authentication")
        
        # Add sensitive data info
        if file_info.get('handles_sensitive_data'):
            descriptions.append("processes sensitive data")
        
        return ", ".join(descriptions) if descriptions else "Application component"
    
    def _scan_for_security_components(self, repo_path: Path, repo_context: RepoContext) -> List[Component]:
        """Scan for additional security-relevant components"""
        additional_components = []
        
        # Look for configuration files with security implications
        config_files = self._find_security_config_files(repo_path)
        for config_file in config_files:
            component = self._analyze_config_component(config_file, repo_path)
            if component:
                additional_components.append(component)
        
        # Look for middleware files
        middleware_files = self._find_middleware_files(repo_path)
        for middleware_file in middleware_files:
            component = self._analyze_middleware_component(middleware_file, repo_path)
            if component:
                additional_components.append(component)
        
        return additional_components
    
    def _find_security_config_files(self, repo_path: Path) -> List[Path]:
        """Find configuration files with security implications"""
        config_files = []
        
        security_config_patterns = [
            '**/security.py', '**/auth.py', '**/config/security.*',
            '**/middleware/auth.*', '**/guards/*', '**/filters/*',
            '**/.env*', '**/config.json', '**/appsettings.json'
        ]
        
        for pattern in security_config_patterns:
            config_files.extend(repo_path.glob(pattern))
        
        return config_files
    
    def _find_middleware_files(self, repo_path: Path) -> List[Path]:
        """Find middleware files"""
        middleware_files = []
        
        middleware_patterns = [
            '**/middleware/*', '**/middlewares/*',
            '**/interceptors/*', '**/filters/*',
            '**/guards/*', '**/decorators/*'
        ]
        
        for pattern in middleware_patterns:
            middleware_files.extend(repo_path.glob(pattern))
        
        return [f for f in middleware_files if f.is_file() and not f.name.startswith('.')]
    
    def _analyze_config_component(self, config_file: Path, repo_path: Path) -> Optional[Component]:
        """Analyze configuration file for security component"""
        try:
            content = self._read_file_safely(str(config_file))
            if not content:
                return None
            
            rel_path = str(config_file.relative_to(repo_path))
            
            # Check for security-related configuration
            has_security_config = bool(re.search(
                r'secret|password|key|token|auth|security|ssl|tls|cors',
                content, re.IGNORECASE
            ))
            
            if has_security_config:
                # Create safe path for ID
                safe_path = rel_path.replace('/', '_').replace('\\', '_')
                
                component = Component(
                    id=f"{repo_path.name}_{safe_path}",
                    name=config_file.stem,
                    type=ComponentType.MIDDLEWARE,  # Config files act as middleware
                    file_path=rel_path,
                    handles_sensitive_data=True,
                    description="Security configuration file"
                )
                return component
                
        except Exception as e:
            logger.warning(f"Error analyzing config file {config_file}: {e}")
        
        return None
    
    def _analyze_middleware_component(self, middleware_file: Path, repo_path: Path) -> Optional[Component]:
        """Analyze middleware file for security component"""
        try:
            content = self._read_file_safely(str(middleware_file))
            if not content:
                return None
            
            rel_path = str(middleware_file.relative_to(repo_path))
            
            # Extract middleware information
            auth_mechanisms = self._detect_auth_mechanisms(content)
            handles_sensitive = self._detect_sensitive_data_patterns(content)
            
            # Create safe path for ID
            safe_path = rel_path.replace('/', '_').replace('\\', '_')
            
            component = Component(
                id=f"{repo_path.name}_{safe_path}",
                name=middleware_file.stem,
                type=ComponentType.MIDDLEWARE,
                file_path=rel_path,
                auth_mechanisms=auth_mechanisms,
                handles_sensitive_data=handles_sensitive,
                description=f"Middleware component with {len(auth_mechanisms)} auth mechanisms"
            )
            return component
            
        except Exception as e:
            logger.warning(f"Error analyzing middleware file {middleware_file}: {e}")
        
        return None
    
    def _detect_data_stores(self, repo_context: RepoContext, components: List[Component]) -> List[DataStore]:
        """Detect data stores from repository analysis"""
        data_stores = []
        repo_path = Path(repo_context.local_path)
        
        # Analyze configuration files for database connections
        config_stores = self._detect_config_data_stores(repo_path)
        data_stores.extend(config_stores)
        
        # Analyze code for data store usage
        code_stores = self._detect_code_data_stores(components, repo_path)
        data_stores.extend(code_stores)
        
        # Remove duplicates
        unique_stores = {}
        for store in data_stores:
            key = f"{store.type}_{store.name}"
            if key not in unique_stores:
                unique_stores[key] = store
        
        return list(unique_stores.values())
    
    def _detect_config_data_stores(self, repo_path: Path) -> List[DataStore]:
        """Detect data stores from configuration files"""
        data_stores = []
        
        # Common config file patterns
        config_patterns = [
            '**/.env*', '**/config.json', '**/appsettings.json',
            '**/database.yml', '**/config/database.*',
            '**/docker-compose.yml', '**/docker-compose.yaml'
        ]
        
        for pattern in config_patterns:
            for config_file in repo_path.glob(pattern):
                if config_file.is_file():
                    stores = self._parse_config_for_datastores(config_file)
                    data_stores.extend(stores)
        
        return data_stores
    
    def _parse_config_for_datastores(self, config_file: Path) -> List[DataStore]:
        """Parse configuration file for data store definitions"""
        data_stores = []
        
        try:
            content = self._read_file_safely(str(config_file))
            if not content:
                return data_stores
            
            # Database URL patterns
            db_patterns = {
                'postgresql': DataStoreType.DATABASE,
                'mysql': DataStoreType.DATABASE,
                'sqlite': DataStoreType.DATABASE,
                'mongodb': DataStoreType.DATABASE,
                'redis': DataStoreType.CACHE,
                'memcached': DataStoreType.CACHE,
                'elasticsearch': DataStoreType.DATABASE
            }
            
            for db_type, store_type in db_patterns.items():
                if re.search(db_type, content, re.IGNORECASE):
                    # Extract connection details
                    sensitive_data_types = self._extract_sensitive_data_types(content, db_type)
                    access_patterns = self._extract_access_patterns(content, db_type)
                    
                    data_store = DataStore(
                        id=f"{config_file.stem}_{db_type}",
                        name=f"{db_type.title()} Database",
                        type=store_type,
                        sensitive_data_types=sensitive_data_types,
                        access_patterns=access_patterns
                    )
                    data_stores.append(data_store)
            
        except Exception as e:
            logger.warning(f"Error parsing config file {config_file}: {e}")
        
        return data_stores
    
    def _detect_code_data_stores(self, components: List[Component], repo_path: Path) -> List[DataStore]:
        """Detect data stores from code analysis"""
        data_stores = []
        
        for component in components:
            try:
                file_path = repo_path / component.file_path
                content = self._read_file_safely(str(file_path))
                if not content:
                    continue
                
                # Look for data store usage patterns
                stores = self._extract_datastores_from_code(content, component)
                data_stores.extend(stores)
                
            except Exception as e:
                logger.warning(f"Error analyzing component {component.file_path}: {e}")
        
        return data_stores
    
    def _extract_datastores_from_code(self, content: str, component: Component) -> List[DataStore]:
        """Extract data store usage from code content"""
        data_stores = []
        
        # Database ORM patterns
        orm_patterns = {
            'SQLAlchemy': DataStoreType.DATABASE,
            'Django ORM': DataStoreType.DATABASE,
            'Mongoose': DataStoreType.DATABASE,
            'Sequelize': DataStoreType.DATABASE,
            'Hibernate': DataStoreType.DATABASE,
            'JPA': DataStoreType.DATABASE
        }
        
        for orm, store_type in orm_patterns.items():
            if re.search(orm.lower().replace(' ', ''), content, re.IGNORECASE):
                sensitive_types = []
                if component.handles_sensitive_data:
                    sensitive_types = ['user_data', 'authentication_data']
                
                access_patterns = self._extract_code_access_patterns(content, orm)
                
                data_store = DataStore(
                    id=f"{component.id}_{orm.lower().replace(' ', '_')}",
                    name=f"{orm} Database",
                    type=store_type,
                    sensitive_data_types=sensitive_types,
                    access_patterns=access_patterns
                )
                data_stores.append(data_store)
        
        return data_stores
    
    def _extract_sensitive_data_types(self, content: str, db_type: str) -> List[str]:
        """Extract types of sensitive data stored"""
        sensitive_types = []
        
        patterns = {
            'user_data': [r'user|profile|account|customer'],
            'authentication_data': [r'password|token|session|auth|credential'],
            'payment_data': [r'payment|credit.*card|billing|transaction'],
            'personal_data': [r'email|phone|address|ssn|personal'],
            'business_data': [r'order|invoice|contract|financial']
        }
        
        for data_type, type_patterns in patterns.items():
            for pattern in type_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    sensitive_types.append(data_type)
                    break
        
        return sensitive_types
    
    def _build_dependency_mapping(self, components: List[Component], repo_context: RepoContext) -> None:
        """Build dependency relationships between components"""
        repo_path = Path(repo_context.local_path)
        
        for component in components:
            try:
                file_path = repo_path / component.file_path
                content = self._read_file_safely(str(file_path))
                if not content:
                    continue
                
                # Find imports and dependencies
                dependencies = self._extract_internal_dependencies(content, components, component)
                component.dependencies.extend(dependencies)
                
            except Exception as e:
                logger.warning(f"Error building dependencies for {component.file_path}: {e}")
    
    def _extract_internal_dependencies(self, content: str, all_components: List[Component], current_component: Component) -> List[str]:
        """Extract internal component dependencies"""
        dependencies = []
        
        # Extract import statements
        import_patterns = [
            r'from\s+[\w.]+\s+import\s+([\w,\s]+)',  # Python
            r'import\s+([\w,\s{}]+)\s+from',  # JavaScript/TypeScript
            r'import\s+([\w.]+)',  # Java/Go
            r'require\([\'"]([^\'"]+)[\'"]'  # Node.js
        ]
        
        imports = []
        for pattern in import_patterns:
            matches = re.findall(pattern, content)
            imports.extend(matches)
        
        # Match imports to components
        for component in all_components:
            if component.id == current_component.id:
                continue
                
            component_name = component.name.lower()
            file_stem = Path(component.file_path).stem.lower()
            
            for import_item in imports:
                if (component_name in import_item.lower() or 
                    file_stem in import_item.lower()):
                    dependencies.append(component.id)
                    break
        
        return dependencies
    
    def _read_file_safely(self, file_path: str) -> Optional[str]:
        """Safely read file content with encoding detection"""
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except (UnicodeDecodeError, IOError):
                continue
        
        return None
    
    def _initialize_security_patterns(self) -> Dict[str, Any]:
        """Initialize security-specific detection patterns"""
        return {
            'auth_frameworks': [
                'passport', 'oauth', 'jwt', 'saml', 'ldap',
                'spring-security', 'flask-login', 'django-auth'
            ],
            'crypto_libraries': [
                'bcrypt', 'scrypt', 'argon2', 'pbkdf2',
                'crypto', 'cryptography', 'openssl'
            ],
            'security_headers': [
                'cors', 'csrf', 'xss', 'content-security-policy',
                'strict-transport-security', 'x-frame-options'
            ]
        }
    
    def _detect_security_patterns(self, repo_context: RepoContext, components: List[Component]) -> SecurityPatterns:
        """
        Detect security patterns across the entire codebase
        
        Args:
            repo_context: Repository context
            components: List of detected components
            
        Returns:
            SecurityPatterns object with detected patterns
        """
        logger.info("Detecting security patterns across codebase")
        
        repo_path = Path(repo_context.local_path)
        
        # Initialize pattern collections
        auth_mechanisms = set()
        auth_patterns = set()
        input_validation = set()
        encryption_usage = set()
        logging_patterns = set()
        
        # Analyze each component for security patterns
        for component in components:
            try:
                file_path = repo_path / component.file_path
                content = self._read_file_safely(str(file_path))
                if not content:
                    continue
                
                # Detect authentication mechanisms
                component_auth = self._detect_authentication_mechanisms(content)
                auth_mechanisms.update(component_auth)
                
                # Detect authorization patterns
                component_authz = self._detect_authorization_patterns(content)
                auth_patterns.update(component_authz)
                
                # Detect input validation patterns
                component_validation = self._detect_input_validation_patterns(content)
                input_validation.update(component_validation)
                
                # Detect encryption usage
                component_encryption = self._detect_encryption_patterns(content)
                encryption_usage.update(component_encryption)
                
                # Detect logging patterns
                component_logging = self._detect_logging_patterns(content)
                logging_patterns.update(component_logging)
                
            except Exception as e:
                logger.warning(f"Error analyzing security patterns in {component.file_path}: {e}")
        
        # Also scan configuration files for additional patterns
        config_patterns = self._scan_config_files_for_security_patterns(repo_path)
        auth_mechanisms.update(config_patterns.get('auth_mechanisms', []))
        encryption_usage.update(config_patterns.get('encryption', []))
        
        return SecurityPatterns(
            authentication_mechanisms=list(auth_mechanisms),
            authorization_patterns=list(auth_patterns),
            input_validation_patterns=list(input_validation),
            encryption_usage=list(encryption_usage),
            logging_patterns=list(logging_patterns)
        )
    
    def _detect_authentication_mechanisms(self, content: str) -> List[str]:
        """Detect authentication mechanisms in code content"""
        mechanisms = []
        
        auth_patterns = {
            'JWT': [
                r'jwt\.encode|jwt\.decode|jsonwebtoken',
                r'JwtAuthenticationFilter|JwtTokenProvider',
                r'@jwt_required|jwt.*verify'
            ],
            'Session-based': [
                r'session\[|request\.session|flask_session',
                r'HttpSession|SessionFactory',
                r'express-session|cookie-session'
            ],
            'OAuth 2.0': [
                r'oauth2|OAuth2|passport.*oauth',
                r'@EnableOAuth2|OAuth2RestTemplate',
                r'google.*oauth|github.*oauth|facebook.*oauth'
            ],
            'Basic Authentication': [
                r'BasicAuth|basic.*auth|Authorization.*Basic',
                r'@EnableWebSecurity.*basic|httpBasic\(\)',
                r'auth\.basic|basic.*authentication'
            ],
            'API Key': [
                r'api.*key|apikey|x-api-key',
                r'Authorization.*Bearer|bearer.*token',
                r'@ApiKeyAuth|ApiKeyAuthenticationFilter'
            ],
            'LDAP': [
                r'ldap|LDAP|ActiveDirectory',
                r'LdapAuthenticationProvider|@EnableLdap',
                r'ldap.*bind|ldap.*search'
            ],
            'SAML': [
                r'saml|SAML|SingleSignOn|SSO',
                r'SAMLAuthenticationProvider|@EnableSaml',
                r'saml.*response|saml.*assertion'
            ],
            'Multi-Factor Authentication': [
                r'mfa|MFA|two.*factor|2fa|totp|TOTP',
                r'google.*authenticator|authy',
                r'sms.*verification|phone.*verification'
            ],
            'Certificate-based': [
                r'client.*certificate|x509|X509',
                r'mutual.*tls|mTLS|client.*auth',
                r'certificate.*authentication'
            ]
        }
        
        for mechanism, patterns in auth_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    mechanisms.append(mechanism)
                    break
        
        return mechanisms
    
    def _detect_authorization_patterns(self, content: str) -> List[str]:
        """Detect authorization patterns in code content"""
        patterns = []
        
        authz_patterns = {
            'Role-Based Access Control (RBAC)': [
                r'@RolesAllowed|@Secured|hasRole|hasAuthority',
                r'role.*check|check.*role|user\.roles',
                r'ROLE_|roles\[|role.*based'
            ],
            'Attribute-Based Access Control (ABAC)': [
                r'@PreAuthorize|@PostAuthorize|hasPermission',
                r'attribute.*check|policy.*evaluation',
                r'permission.*check|access.*control.*list'
            ],
            'Resource-Based Authorization': [
                r'@PreAuthorize.*returnObject|@PostFilter',
                r'resource.*owner|owner.*check',
                r'can.*access|authorize.*resource'
            ],
            'Method-Level Security': [
                r'@Secured|@PreAuthorize|@PostAuthorize',
                r'@RolesAllowed|@PermitAll|@DenyAll',
                r'method.*security|secured.*method'
            ],
            'URL-Based Authorization': [
                r'antMatchers|requestMatchers|authorizeRequests',
                r'permitAll|authenticated|hasRole.*url',
                r'url.*authorization|path.*security'
            ],
            'Custom Authorization': [
                r'custom.*authorizer|authorization.*handler',
                r'access.*decision|permission.*evaluator',
                r'security.*interceptor|auth.*filter'
            ]
        }
        
        for pattern_name, pattern_list in authz_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, content, re.IGNORECASE):
                    patterns.append(pattern_name)
                    break
        
        return patterns
    
    def _detect_input_validation_patterns(self, content: str) -> List[str]:
        """Detect input validation patterns in code content"""
        patterns = []
        
        validation_patterns = {
            'Schema Validation': [
                r'@Valid|@Validated|ValidationException',
                r'schema\.validate|joi\.validate|yup\.validate',
                r'marshmallow|pydantic|cerberus'
            ],
            'Parameter Validation': [
                r'@NotNull|@NotEmpty|@Size|@Pattern',
                r'@Min|@Max|@Email|@URL',
                r'validator\.|validate\.|validation\.'
            ],
            'SQL Injection Prevention': [
                r'PreparedStatement|parameterized.*query',
                r'sqlalchemy.*text|query\.filter',
                r'escape.*sql|sanitize.*sql'
            ],
            'XSS Prevention': [
                r'escape.*html|sanitize.*html|xss.*filter',
                r'Content-Security-Policy|CSP',
                r'html.*escape|bleach|DOMPurify'
            ],
            'CSRF Protection': [
                r'csrf.*token|@CsrfToken|csrf.*protection',
                r'X-CSRF-TOKEN|_token|csrfmiddlewaretoken',
                r'SameSite.*cookie|csrf.*middleware'
            ],
            'File Upload Validation': [
                r'file.*validation|upload.*validation',
                r'allowed.*extensions|file.*type.*check',
                r'virus.*scan|malware.*check'
            ]
        }
        
        for pattern_name, pattern_list in validation_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, content, re.IGNORECASE):
                    patterns.append(pattern_name)
                    break
        
        return patterns
    
    def _detect_encryption_patterns(self, content: str) -> List[str]:
        """Detect encryption and cryptographic patterns in code content"""
        patterns = []
        
        crypto_patterns = {
            'Password Hashing': [
                r'bcrypt|scrypt|argon2|pbkdf2',
                r'password.*hash|hash.*password',
                r'PasswordEncoder|hashpw|check.*password'
            ],
            'Symmetric Encryption': [
                r'AES|aes|DES|des|ChaCha20',
                r'symmetric.*encrypt|encrypt.*symmetric',
                r'Cipher\.getInstance|crypto\.encrypt'
            ],
            'Asymmetric Encryption': [
                r'RSA|rsa|ECC|ecc|DSA|dsa',
                r'public.*key|private.*key|key.*pair',
                r'asymmetric.*encrypt|encrypt.*asymmetric'
            ],
            'Digital Signatures': [
                r'digital.*signature|sign.*verify|signature.*verify',
                r'HMAC|hmac|SHA.*signature',
                r'jwt\.sign|crypto\.sign'
            ],
            'TLS/SSL': [
                r'tls|TLS|ssl|SSL|https',
                r'certificate|cert|x509|X509',
                r'secure.*socket|ssl.*context'
            ],
            'Key Management': [
                r'key.*derivation|kdf|KDF',
                r'key.*storage|keystore|key.*vault',
                r'key.*rotation|key.*management'
            ],
            'Random Generation': [
                r'secure.*random|crypto.*random|urandom',
                r'SecureRandom|random\.SystemRandom',
                r'crypto\.getRandomValues|os\.urandom'
            ]
        }
        
        for pattern_name, pattern_list in crypto_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, content, re.IGNORECASE):
                    patterns.append(pattern_name)
                    break
        
        return patterns
    
    def _detect_logging_patterns(self, content: str) -> List[str]:
        """Detect security-relevant logging patterns in code content"""
        patterns = []
        
        logging_patterns = {
            'Authentication Logging': [
                r'log.*login|login.*log|auth.*log',
                r'failed.*login|successful.*login',
                r'authentication.*event|auth.*audit'
            ],
            'Authorization Logging': [
                r'access.*denied|permission.*denied',
                r'authorization.*failed|access.*granted',
                r'privilege.*escalation|unauthorized.*access'
            ],
            'Security Event Logging': [
                r'security.*event|security.*log|audit.*log',
                r'suspicious.*activity|security.*violation',
                r'intrusion.*detection|anomaly.*detection'
            ],
            'Error Logging': [
                r'error.*log|exception.*log|stack.*trace',
                r'log\.error|logger\.error|logging\.error',
                r'try.*except.*log|catch.*log'
            ],
            'Data Access Logging': [
                r'data.*access.*log|database.*log',
                r'query.*log|sql.*log|data.*audit',
                r'sensitive.*data.*access'
            ],
            'Session Logging': [
                r'session.*log|session.*audit',
                r'session.*created|session.*destroyed',
                r'session.*timeout|session.*expired'
            ]
        }
        
        for pattern_name, pattern_list in logging_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, content, re.IGNORECASE):
                    patterns.append(pattern_name)
                    break
        
        return patterns
    
    def _scan_config_files_for_security_patterns(self, repo_path: Path) -> Dict[str, List[str]]:
        """Scan configuration files for additional security patterns"""
        patterns = {
            'auth_mechanisms': [],
            'encryption': []
        }
        
        config_patterns = [
            '**/.env*', '**/config.json', '**/appsettings.json',
            '**/application.yml', '**/application.yaml',
            '**/security.yml', '**/security.yaml',
            '**/docker-compose.yml', '**/docker-compose.yaml'
        ]
        
        for pattern in config_patterns:
            for config_file in repo_path.glob(pattern):
                if config_file.is_file():
                    try:
                        content = self._read_file_safely(str(config_file))
                        if not content:
                            continue
                        
                        # Check for authentication configuration
                        if re.search(r'jwt|oauth|saml|ldap|basic.*auth', content, re.IGNORECASE):
                            patterns['auth_mechanisms'].append('Configuration-based Authentication')
                        
                        # Check for encryption configuration
                        if re.search(r'ssl|tls|encrypt|cipher|key.*store', content, re.IGNORECASE):
                            patterns['encryption'].append('Configuration-based Encryption')
                            
                    except Exception as e:
                        logger.warning(f"Error scanning config file {config_file}: {e}")
        
        return patterns
    
    def _identify_trust_boundaries(self, repo_context: RepoContext, components: List[Component], data_stores: List[DataStore]) -> List[TrustBoundary]:
        """
        Identify trust boundaries in the system
        
        Args:
            repo_context: Repository context
            components: List of system components
            data_stores: List of data stores
            
        Returns:
            List of identified trust boundaries
        """
        logger.info("Identifying trust boundaries")
        
        trust_boundaries = []
        
        # 1. Public-facing boundary (external users to application)
        public_components = []
        internal_components = []
        
        for component in components:
            has_public_endpoints = any(
                not endpoint.requires_auth and self._is_public_endpoint(endpoint.path)
                for endpoint in component.endpoints
            )
            
            if has_public_endpoints or component.type == ComponentType.CONTROLLER:
                public_components.append(component.id)
            else:
                internal_components.append(component.id)
        
        if public_components:
            trust_boundaries.append(TrustBoundary(
                id="public_boundary",
                name="Public-Facing Boundary",
                description="Boundary between external users and public-facing application components",
                components_inside=internal_components,
                components_outside=public_components
            ))
        
        # 2. Authentication boundary (unauthenticated vs authenticated)
        auth_required_components = []
        no_auth_components = []
        
        for component in components:
            requires_auth = any(endpoint.requires_auth for endpoint in component.endpoints)
            if requires_auth:
                auth_required_components.append(component.id)
            else:
                no_auth_components.append(component.id)
        
        if auth_required_components and no_auth_components:
            trust_boundaries.append(TrustBoundary(
                id="authentication_boundary",
                name="Authentication Boundary",
                description="Boundary between authenticated and unauthenticated components",
                components_inside=auth_required_components,
                components_outside=no_auth_components
            ))
        
        # 3. Data access boundary (components that handle sensitive data)
        sensitive_components = []
        non_sensitive_components = []
        
        for component in components:
            if component.handles_sensitive_data:
                sensitive_components.append(component.id)
            else:
                non_sensitive_components.append(component.id)
        
        if sensitive_components:
            trust_boundaries.append(TrustBoundary(
                id="data_access_boundary",
                name="Sensitive Data Access Boundary",
                description="Boundary around components that handle sensitive data",
                components_inside=sensitive_components,
                components_outside=non_sensitive_components
            ))
        
        # 4. Administrative boundary (admin vs regular user components)
        admin_components = []
        user_components = []
        
        for component in components:
            has_admin_endpoints = any(
                self._is_admin_endpoint(endpoint.path)
                for endpoint in component.endpoints
            )
            
            if has_admin_endpoints:
                admin_components.append(component.id)
            else:
                user_components.append(component.id)
        
        if admin_components:
            trust_boundaries.append(TrustBoundary(
                id="administrative_boundary",
                name="Administrative Boundary",
                description="Boundary between administrative and regular user components",
                components_inside=admin_components,
                components_outside=user_components
            ))
        
        # 5. External service boundary (internal vs external dependencies)
        internal_service_components = []
        external_service_components = []
        
        for component in components:
            has_external_deps = any(
                'External' in dep or 'API' in dep or 'Cloud' in dep
                for dep in component.dependencies
            )
            
            if has_external_deps:
                external_service_components.append(component.id)
            else:
                internal_service_components.append(component.id)
        
        if external_service_components:
            trust_boundaries.append(TrustBoundary(
                id="external_service_boundary",
                name="External Service Boundary",
                description="Boundary between internal components and external service integrations",
                components_inside=internal_service_components,
                components_outside=external_service_components
            ))
        
        # 6. Database boundary (application vs data layer)
        app_components = [c.id for c in components if c.type != ComponentType.MODEL]
        data_components = [c.id for c in components if c.type == ComponentType.MODEL]
        data_store_ids = [ds.id for ds in data_stores]
        
        if data_components or data_store_ids:
            trust_boundaries.append(TrustBoundary(
                id="database_boundary",
                name="Database Boundary",
                description="Boundary between application logic and data storage layer",
                components_inside=data_components + data_store_ids,
                components_outside=app_components
            ))
        
        logger.info(f"Identified {len(trust_boundaries)} trust boundaries")
        return trust_boundaries
    
    def _is_public_endpoint(self, path: str) -> bool:
        """Check if an endpoint path is typically public-facing"""
        public_patterns = [
            r'^/api/public',
            r'^/public',
            r'^/health',
            r'^/status',
            r'^/ping',
            r'^/docs',
            r'^/swagger',
            r'^/openapi',
            r'^/static',
            r'^/assets'
        ]
        
        return any(re.match(pattern, path, re.IGNORECASE) for pattern in public_patterns)
    
    def _is_admin_endpoint(self, path: str) -> bool:
        """Check if an endpoint path is administrative"""
        admin_patterns = [
            r'/admin',
            r'/management',
            r'/actuator',
            r'/metrics',
            r'/config',
            r'/system',
            r'/dashboard'
        ]
        
        return any(pattern in path.lower() for pattern in admin_patterns)
    
    def _initialize_security_patterns(self) -> Dict[str, Any]:
        """Initialize security pattern detection configurations"""
        return {
            'sensitive_data_patterns': [
                r'password|secret|key|token|credential',
                r'ssn|social.*security|credit.*card|payment',
                r'email|phone|address|personal.*data|pii|PII',
                r'encrypt|decrypt|hash|bcrypt|scrypt',
                r'private.*key|public.*key|certificate'
            ],
            'auth_patterns': [
                r'@login_required|@auth_required|@authenticated',
                r'@PreAuthorize|@Secured|@RolesAllowed',
                r'requireAuth|authenticate|authorize',
                r'jwt.*required|token.*required'
            ],
            'external_service_patterns': [
                r'requests\.|fetch\(|axios\.|http\.',
                r'RestTemplate|WebClient|HttpClient',
                r'api\..*\.com|service\..*\.com'
            ]
        }
    
    def _extract_access_patterns(self, content: str, db_type: str) -> List[str]:
        """Extract data access patterns from configuration content"""
        patterns = []
        
        # Connection pooling patterns
        if re.search(r'pool|connection.*pool|max.*connections', content, re.IGNORECASE):
            patterns.append('Connection Pooling')
        
        # Read/write splitting
        if re.search(r'read.*replica|write.*master|read.*write.*split', content, re.IGNORECASE):
            patterns.append('Read/Write Splitting')
        
        # Caching patterns
        if re.search(r'cache|redis|memcached', content, re.IGNORECASE):
            patterns.append('Caching Layer')
        
        # Encryption at rest
        if re.search(r'encrypt.*at.*rest|database.*encryption|tde', content, re.IGNORECASE):
            patterns.append('Encryption at Rest')
        
        # Backup patterns
        if re.search(r'backup|snapshot|dump', content, re.IGNORECASE):
            patterns.append('Backup/Recovery')
        
        return patterns
    
    def _extract_code_access_patterns(self, content: str, orm: str) -> List[str]:
        """Extract data access patterns from code content"""
        patterns = []
        
        # CRUD operation patterns
        crud_patterns = {
            'Create Operations': [r'\.save\(|\.create\(|\.insert\(|INSERT INTO'],
            'Read Operations': [r'\.find\(|\.get\(|\.query\(|SELECT.*FROM'],
            'Update Operations': [r'\.update\(|\.modify\(|UPDATE.*SET'],
            'Delete Operations': [r'\.delete\(|\.remove\(|DELETE FROM']
        }
        
        for pattern_name, pattern_list in crud_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, content, re.IGNORECASE):
                    patterns.append(pattern_name)
                    break
        
        # Transaction patterns
        if re.search(r'transaction|commit|rollback|begin.*transaction', content, re.IGNORECASE):
            patterns.append('Transactional Operations')
        
        # Batch operations
        if re.search(r'batch|bulk.*insert|bulk.*update', content, re.IGNORECASE):
            patterns.append('Batch Operations')
        
        # Query optimization patterns
        if re.search(r'index|optimize|explain|query.*plan', content, re.IGNORECASE):
            patterns.append('Query Optimization')
        
        # Migration patterns
        if re.search(r'migration|schema.*change|alter.*table', content, re.IGNORECASE):
            patterns.append('Schema Migration')
        
        return patterns
    
    def _build_data_flow_analysis(self, repo_context: RepoContext, components: List[Component], 
                                 data_stores: List[DataStore], trust_boundaries: List[TrustBoundary]) -> List[Flow]:
        """
        Build comprehensive data flow analysis
        
        Args:
            repo_context: Repository context
            components: List of system components
            data_stores: List of data stores
            trust_boundaries: List of trust boundaries
            
        Returns:
            List of identified data flows
        """
        logger.info("Building data flow analysis")
        
        flows = []
        
        # Detect common flow patterns
        auth_flows = self._detect_authentication_flows(components, trust_boundaries)
        flows.extend(auth_flows)
        
        registration_flows = self._detect_registration_flows(components, data_stores, trust_boundaries)
        flows.extend(registration_flows)
        
        payment_flows = self._detect_payment_flows(components, data_stores, trust_boundaries)
        flows.extend(payment_flows)
        
        admin_flows = self._detect_admin_flows(components, data_stores, trust_boundaries)
        flows.extend(admin_flows)
        
        data_access_flows = self._detect_data_access_flows(components, data_stores, trust_boundaries)
        flows.extend(data_access_flows)
        
        logger.info(f"Identified {len(flows)} data flows")
        return flows
    
    def _detect_authentication_flows(self, components: List[Component], trust_boundaries: List[TrustBoundary]) -> List[Flow]:
        """Detect authentication-related data flows"""
        flows = []
        
        # Find authentication-related components
        auth_components = []
        for component in components:
            has_auth_endpoints = any(
                self._is_auth_endpoint(endpoint.path) or endpoint.requires_auth
                for endpoint in component.endpoints
            )
            if has_auth_endpoints or 'auth' in component.auth_mechanisms:
                auth_components.append(component)
        
        if not auth_components:
            return flows
        
        # Build login flow
        login_flow = self._build_login_flow(auth_components, trust_boundaries)
        if login_flow:
            flows.append(login_flow)
        
        # Build logout flow
        logout_flow = self._build_logout_flow(auth_components, trust_boundaries)
        if logout_flow:
            flows.append(logout_flow)
        
        # Build token refresh flow
        token_refresh_flow = self._build_token_refresh_flow(auth_components, trust_boundaries)
        if token_refresh_flow:
            flows.append(token_refresh_flow)
        
        return flows
    
    def _detect_registration_flows(self, components: List[Component], data_stores: List[DataStore], 
                                  trust_boundaries: List[TrustBoundary]) -> List[Flow]:
        """Detect user registration data flows"""
        flows = []
        
        # Find registration-related components
        reg_components = []
        for component in components:
            has_reg_endpoints = any(
                self._is_registration_endpoint(endpoint.path)
                for endpoint in component.endpoints
            )
            if has_reg_endpoints:
                reg_components.append(component)
        
        if not reg_components:
            return flows
        
        # Build user registration flow
        registration_flow = self._build_registration_flow(reg_components, data_stores, trust_boundaries)
        if registration_flow:
            flows.append(registration_flow)
        
        return flows
    
    def _detect_payment_flows(self, components: List[Component], data_stores: List[DataStore], 
                             trust_boundaries: List[TrustBoundary]) -> List[Flow]:
        """Detect payment-related data flows"""
        flows = []
        
        # Find payment-related components
        payment_components = []
        for component in components:
            has_payment_endpoints = any(
                self._is_payment_endpoint(endpoint.path)
                for endpoint in component.endpoints
            )
            if has_payment_endpoints or self._handles_payment_data(component):
                payment_components.append(component)
        
        if not payment_components:
            return flows
        
        # Build payment processing flow
        payment_flow = self._build_payment_flow(payment_components, data_stores, trust_boundaries)
        if payment_flow:
            flows.append(payment_flow)
        
        return flows
    
    def _detect_admin_flows(self, components: List[Component], data_stores: List[DataStore], 
                           trust_boundaries: List[TrustBoundary]) -> List[Flow]:
        """Detect administrative operation flows"""
        flows = []
        
        # Find admin-related components
        admin_components = []
        for component in components:
            has_admin_endpoints = any(
                self._is_admin_endpoint(endpoint.path)
                for endpoint in component.endpoints
            )
            if has_admin_endpoints:
                admin_components.append(component)
        
        if not admin_components:
            return flows
        
        # Build admin operations flow
        admin_flow = self._build_admin_flow(admin_components, data_stores, trust_boundaries)
        if admin_flow:
            flows.append(admin_flow)
        
        return flows
    
    def _detect_data_access_flows(self, components: List[Component], data_stores: List[DataStore], 
                                 trust_boundaries: List[TrustBoundary]) -> List[Flow]:
        """Detect general data access flows"""
        flows = []
        
        # Find components that handle sensitive data
        sensitive_components = [c for c in components if c.handles_sensitive_data]
        
        if not sensitive_components:
            return flows
        
        # Build data access flow
        data_flow = self._build_data_access_flow(sensitive_components, data_stores, trust_boundaries)
        if data_flow:
            flows.append(data_flow)
        
        return flows
    
    def _build_login_flow(self, auth_components: List[Component], trust_boundaries: List[TrustBoundary]) -> Optional[Flow]:
        """Build login authentication flow"""
        steps = []
        step_num = 1
        components_involved = []
        boundary_crossings = []
        
        # Step 1: User submits credentials
        login_component = self._find_component_with_endpoint(auth_components, 'login')
        if login_component:
            components_involved.append(login_component.id)
            steps.append(FlowStep(
                step_number=step_num,
                description="User submits login credentials",
                component_id=login_component.id,
                data_processed=["username", "password"],
                trust_boundary_crossing=self._find_boundary_crossing(login_component.id, trust_boundaries, "public_boundary")
            ))
            step_num += 1
            
            if steps[-1].trust_boundary_crossing:
                boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 2: Validate credentials
        if login_component:
            steps.append(FlowStep(
                step_number=step_num,
                description="System validates user credentials",
                component_id=login_component.id,
                data_processed=["hashed_password", "user_data"],
                trust_boundary_crossing=self._find_boundary_crossing(login_component.id, trust_boundaries, "authentication_boundary")
            ))
            step_num += 1
            
            if steps[-1].trust_boundary_crossing:
                boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 3: Generate authentication token
        if login_component:
            steps.append(FlowStep(
                step_number=step_num,
                description="System generates authentication token",
                component_id=login_component.id,
                data_processed=["jwt_token", "session_data"],
                trust_boundary_crossing=None
            ))
            step_num += 1
        
        # Step 4: Return authentication response
        if login_component:
            steps.append(FlowStep(
                step_number=step_num,
                description="System returns authentication response",
                component_id=login_component.id,
                data_processed=["auth_token", "user_profile"],
                trust_boundary_crossing=self._find_boundary_crossing(login_component.id, trust_boundaries, "public_boundary")
            ))
            
            if steps[-1].trust_boundary_crossing:
                boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        if not steps:
            return None
        
        return Flow(
            id="login_flow",
            name="User Login Authentication",
            flow_type=FlowType.AUTHENTICATION,
            steps=steps,
            components_involved=list(set(components_involved)),
            data_sensitivity=DataSensitivityLevel.CONFIDENTIAL,
            trust_boundary_crossings=list(set(boundary_crossings)),
            description="Complete user login authentication process"
        )
    
    def _build_logout_flow(self, auth_components: List[Component], trust_boundaries: List[TrustBoundary]) -> Optional[Flow]:
        """Build logout flow"""
        steps = []
        step_num = 1
        components_involved = []
        boundary_crossings = []
        
        # Find logout component
        logout_component = self._find_component_with_endpoint(auth_components, 'logout')
        if not logout_component:
            return None
        
        components_involved.append(logout_component.id)
        
        # Step 1: User initiates logout
        steps.append(FlowStep(
            step_number=step_num,
            description="User initiates logout request",
            component_id=logout_component.id,
            data_processed=["auth_token"],
            trust_boundary_crossing=self._find_boundary_crossing(logout_component.id, trust_boundaries, "authentication_boundary")
        ))
        step_num += 1
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 2: Invalidate session/token
        steps.append(FlowStep(
            step_number=step_num,
            description="System invalidates authentication token/session",
            component_id=logout_component.id,
            data_processed=["session_data", "token_blacklist"],
            trust_boundary_crossing=None
        ))
        step_num += 1
        
        # Step 3: Confirm logout
        steps.append(FlowStep(
            step_number=step_num,
            description="System confirms successful logout",
            component_id=logout_component.id,
            data_processed=["logout_confirmation"],
            trust_boundary_crossing=self._find_boundary_crossing(logout_component.id, trust_boundaries, "public_boundary")
        ))
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        return Flow(
            id="logout_flow",
            name="User Logout Process",
            flow_type=FlowType.AUTHENTICATION,
            steps=steps,
            components_involved=components_involved,
            data_sensitivity=DataSensitivityLevel.INTERNAL,
            trust_boundary_crossings=list(set(boundary_crossings)),
            description="User logout and session termination process"
        )
    
    def _build_token_refresh_flow(self, auth_components: List[Component], trust_boundaries: List[TrustBoundary]) -> Optional[Flow]:
        """Build token refresh flow"""
        # Check if JWT or token-based auth is used
        has_token_auth = any(
            'JWT' in component.auth_mechanisms or 'API Key' in component.auth_mechanisms
            for component in auth_components
        )
        
        if not has_token_auth:
            return None
        
        steps = []
        step_num = 1
        components_involved = []
        boundary_crossings = []
        
        # Find refresh component (could be same as login)
        refresh_component = self._find_component_with_endpoint(auth_components, 'refresh') or auth_components[0]
        components_involved.append(refresh_component.id)
        
        # Step 1: Submit refresh token
        steps.append(FlowStep(
            step_number=step_num,
            description="Client submits refresh token",
            component_id=refresh_component.id,
            data_processed=["refresh_token"],
            trust_boundary_crossing=self._find_boundary_crossing(refresh_component.id, trust_boundaries, "authentication_boundary")
        ))
        step_num += 1
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 2: Validate refresh token
        steps.append(FlowStep(
            step_number=step_num,
            description="System validates refresh token",
            component_id=refresh_component.id,
            data_processed=["token_validation", "user_session"],
            trust_boundary_crossing=None
        ))
        step_num += 1
        
        # Step 3: Generate new access token
        steps.append(FlowStep(
            step_number=step_num,
            description="System generates new access token",
            component_id=refresh_component.id,
            data_processed=["new_access_token", "updated_session"],
            trust_boundary_crossing=self._find_boundary_crossing(refresh_component.id, trust_boundaries, "public_boundary")
        ))
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        return Flow(
            id="token_refresh_flow",
            name="Authentication Token Refresh",
            flow_type=FlowType.AUTHENTICATION,
            steps=steps,
            components_involved=components_involved,
            data_sensitivity=DataSensitivityLevel.CONFIDENTIAL,
            trust_boundary_crossings=list(set(boundary_crossings)),
            description="Process for refreshing expired authentication tokens"
        )
    
    def _build_registration_flow(self, reg_components: List[Component], data_stores: List[DataStore], 
                                trust_boundaries: List[TrustBoundary]) -> Optional[Flow]:
        """Build user registration flow"""
        steps = []
        step_num = 1
        components_involved = []
        boundary_crossings = []
        
        # Find registration component
        reg_component = reg_components[0]  # Take first registration component
        components_involved.append(reg_component.id)
        
        # Step 1: User submits registration data
        steps.append(FlowStep(
            step_number=step_num,
            description="User submits registration information",
            component_id=reg_component.id,
            data_processed=["email", "password", "personal_data"],
            trust_boundary_crossing=self._find_boundary_crossing(reg_component.id, trust_boundaries, "public_boundary")
        ))
        step_num += 1
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 2: Validate registration data
        steps.append(FlowStep(
            step_number=step_num,
            description="System validates registration data",
            component_id=reg_component.id,
            data_processed=["input_validation", "duplicate_check"],
            trust_boundary_crossing=None
        ))
        step_num += 1
        
        # Step 3: Store user data
        user_datastore = self._find_user_datastore(data_stores)
        if user_datastore:
            steps.append(FlowStep(
                step_number=step_num,
                description="System stores user account data",
                component_id=user_datastore.id,
                data_processed=["hashed_password", "user_profile", "account_metadata"],
                trust_boundary_crossing=self._find_boundary_crossing(user_datastore.id, trust_boundaries, "database_boundary")
            ))
            step_num += 1
            
            if steps[-1].trust_boundary_crossing:
                boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 4: Send confirmation
        steps.append(FlowStep(
            step_number=step_num,
            description="System sends registration confirmation",
            component_id=reg_component.id,
            data_processed=["confirmation_email", "account_status"],
            trust_boundary_crossing=self._find_boundary_crossing(reg_component.id, trust_boundaries, "public_boundary")
        ))
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        return Flow(
            id="user_registration_flow",
            name="User Account Registration",
            flow_type=FlowType.USER_REGISTRATION,
            steps=steps,
            components_involved=components_involved,
            data_sensitivity=DataSensitivityLevel.CONFIDENTIAL,
            trust_boundary_crossings=list(set(boundary_crossings)),
            description="Complete user account registration process"
        )
    
    def _build_payment_flow(self, payment_components: List[Component], data_stores: List[DataStore], 
                           trust_boundaries: List[TrustBoundary]) -> Optional[Flow]:
        """Build payment processing flow"""
        steps = []
        step_num = 1
        components_involved = []
        boundary_crossings = []
        
        # Find payment component
        payment_component = payment_components[0]
        components_involved.append(payment_component.id)
        
        # Step 1: User initiates payment
        steps.append(FlowStep(
            step_number=step_num,
            description="User initiates payment transaction",
            component_id=payment_component.id,
            data_processed=["payment_amount", "payment_method", "billing_info"],
            trust_boundary_crossing=self._find_boundary_crossing(payment_component.id, trust_boundaries, "public_boundary")
        ))
        step_num += 1
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 2: Validate payment data
        steps.append(FlowStep(
            step_number=step_num,
            description="System validates payment information",
            component_id=payment_component.id,
            data_processed=["card_validation", "fraud_check", "amount_verification"],
            trust_boundary_crossing=None
        ))
        step_num += 1
        
        # Step 3: Process with external payment gateway
        steps.append(FlowStep(
            step_number=step_num,
            description="System processes payment with external gateway",
            component_id=payment_component.id,
            data_processed=["encrypted_card_data", "transaction_request"],
            trust_boundary_crossing=self._find_boundary_crossing(payment_component.id, trust_boundaries, "external_service_boundary")
        ))
        step_num += 1
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 4: Store transaction record
        payment_datastore = self._find_payment_datastore(data_stores)
        if payment_datastore:
            steps.append(FlowStep(
                step_number=step_num,
                description="System stores transaction record",
                component_id=payment_datastore.id,
                data_processed=["transaction_id", "payment_status", "audit_trail"],
                trust_boundary_crossing=self._find_boundary_crossing(payment_datastore.id, trust_boundaries, "database_boundary")
            ))
            step_num += 1
            
            if steps[-1].trust_boundary_crossing:
                boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 5: Return payment result
        steps.append(FlowStep(
            step_number=step_num,
            description="System returns payment confirmation",
            component_id=payment_component.id,
            data_processed=["payment_confirmation", "receipt_data"],
            trust_boundary_crossing=self._find_boundary_crossing(payment_component.id, trust_boundaries, "public_boundary")
        ))
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        return Flow(
            id="payment_processing_flow",
            name="Payment Transaction Processing",
            flow_type=FlowType.PAYMENT,
            steps=steps,
            components_involved=components_involved,
            data_sensitivity=DataSensitivityLevel.RESTRICTED,
            trust_boundary_crossings=list(set(boundary_crossings)),
            description="Complete payment transaction processing flow"
        )
    
    def _build_admin_flow(self, admin_components: List[Component], data_stores: List[DataStore], 
                         trust_boundaries: List[TrustBoundary]) -> Optional[Flow]:
        """Build administrative operations flow"""
        steps = []
        step_num = 1
        components_involved = []
        boundary_crossings = []
        
        # Find admin component
        admin_component = admin_components[0]
        components_involved.append(admin_component.id)
        
        # Step 1: Admin authentication
        steps.append(FlowStep(
            step_number=step_num,
            description="Administrator authenticates with elevated privileges",
            component_id=admin_component.id,
            data_processed=["admin_credentials", "privilege_verification"],
            trust_boundary_crossing=self._find_boundary_crossing(admin_component.id, trust_boundaries, "administrative_boundary")
        ))
        step_num += 1
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 2: Perform admin operation
        steps.append(FlowStep(
            step_number=step_num,
            description="System executes administrative operation",
            component_id=admin_component.id,
            data_processed=["system_configuration", "user_management", "audit_data"],
            trust_boundary_crossing=None
        ))
        step_num += 1
        
        # Step 3: Update system data
        admin_datastore = self._find_system_datastore(data_stores)
        if admin_datastore:
            steps.append(FlowStep(
                step_number=step_num,
                description="System updates configuration/user data",
                component_id=admin_datastore.id,
                data_processed=["configuration_changes", "user_modifications", "system_state"],
                trust_boundary_crossing=self._find_boundary_crossing(admin_datastore.id, trust_boundaries, "database_boundary")
            ))
            step_num += 1
            
            if steps[-1].trust_boundary_crossing:
                boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 4: Log admin action
        steps.append(FlowStep(
            step_number=step_num,
            description="System logs administrative action",
            component_id=admin_component.id,
            data_processed=["audit_log", "admin_action_record", "timestamp"],
            trust_boundary_crossing=None
        ))
        
        return Flow(
            id="admin_operations_flow",
            name="Administrative Operations",
            flow_type=FlowType.ADMIN,
            steps=steps,
            components_involved=components_involved,
            data_sensitivity=DataSensitivityLevel.RESTRICTED,
            trust_boundary_crossings=list(set(boundary_crossings)),
            description="Administrative operations and system management flow"
        )
    
    def _build_data_access_flow(self, sensitive_components: List[Component], data_stores: List[DataStore], 
                               trust_boundaries: List[TrustBoundary]) -> Optional[Flow]:
        """Build general data access flow"""
        steps = []
        step_num = 1
        components_involved = []
        boundary_crossings = []
        
        # Find data access component
        data_component = sensitive_components[0]
        components_involved.append(data_component.id)
        
        # Step 1: Request data access
        steps.append(FlowStep(
            step_number=step_num,
            description="User/system requests access to sensitive data",
            component_id=data_component.id,
            data_processed=["access_request", "user_context"],
            trust_boundary_crossing=self._find_boundary_crossing(data_component.id, trust_boundaries, "data_access_boundary")
        ))
        step_num += 1
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 2: Authorize access
        steps.append(FlowStep(
            step_number=step_num,
            description="System verifies access permissions",
            component_id=data_component.id,
            data_processed=["permission_check", "authorization_rules"],
            trust_boundary_crossing=None
        ))
        step_num += 1
        
        # Step 3: Retrieve data
        sensitive_datastore = self._find_sensitive_datastore(data_stores)
        if sensitive_datastore:
            steps.append(FlowStep(
                step_number=step_num,
                description="System retrieves requested data",
                component_id=sensitive_datastore.id,
                data_processed=["sensitive_data", "query_results"],
                trust_boundary_crossing=self._find_boundary_crossing(sensitive_datastore.id, trust_boundaries, "database_boundary")
            ))
            step_num += 1
            
            if steps[-1].trust_boundary_crossing:
                boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        # Step 4: Return filtered data
        steps.append(FlowStep(
            step_number=step_num,
            description="System returns filtered/sanitized data",
            component_id=data_component.id,
            data_processed=["filtered_data", "sanitized_output"],
            trust_boundary_crossing=self._find_boundary_crossing(data_component.id, trust_boundaries, "data_access_boundary")
        ))
        
        if steps[-1].trust_boundary_crossing:
            boundary_crossings.append(steps[-1].trust_boundary_crossing)
        
        return Flow(
            id="data_access_flow",
            name="Sensitive Data Access",
            flow_type=FlowType.DATA_ACCESS,
            steps=steps,
            components_involved=components_involved,
            data_sensitivity=DataSensitivityLevel.CONFIDENTIAL,
            trust_boundary_crossings=list(set(boundary_crossings)),
            description="General sensitive data access and retrieval flow"
        )
    
    # Helper methods for flow detection
    def _is_auth_endpoint(self, path: str) -> bool:
        """Check if endpoint is authentication-related"""
        auth_patterns = ['/login', '/auth', '/signin', '/authenticate', '/token', '/logout', '/refresh']
        return any(pattern in path.lower() for pattern in auth_patterns)
    
    def _is_registration_endpoint(self, path: str) -> bool:
        """Check if endpoint is registration-related"""
        reg_patterns = ['/register', '/signup', '/create-account', '/join']
        return any(pattern in path.lower() for pattern in reg_patterns)
    
    def _is_payment_endpoint(self, path: str) -> bool:
        """Check if endpoint is payment-related"""
        payment_patterns = ['/payment', '/pay', '/checkout', '/billing', '/purchase', '/transaction']
        return any(pattern in path.lower() for pattern in payment_patterns)
    
    def _handles_payment_data(self, component: Component) -> bool:
        """Check if component handles payment data"""
        payment_indicators = ['payment', 'billing', 'transaction', 'credit', 'card', 'stripe', 'paypal']
        return any(
            indicator in component.name.lower() or 
            indicator in component.file_path.lower() or
            any(indicator in dep.lower() for dep in component.dependencies)
            for indicator in payment_indicators
        )
    
    def _find_component_with_endpoint(self, components: List[Component], endpoint_type: str) -> Optional[Component]:
        """Find component with specific endpoint type"""
        for component in components:
            for endpoint in component.endpoints:
                if endpoint_type in endpoint.path.lower():
                    return component
        return components[0] if components else None
    
    def _find_boundary_crossing(self, component_id: str, trust_boundaries: List[TrustBoundary], 
                               boundary_type: str) -> Optional[str]:
        """Find if component crosses a specific trust boundary"""
        for boundary in trust_boundaries:
            if boundary_type in boundary.id:
                if (component_id in boundary.components_inside or 
                    component_id in boundary.components_outside):
                    return boundary.id
        return None
    
    def _find_user_datastore(self, data_stores: List[DataStore]) -> Optional[DataStore]:
        """Find datastore that handles user data"""
        for store in data_stores:
            if 'user_data' in store.sensitive_data_types or 'authentication_data' in store.sensitive_data_types:
                return store
        return data_stores[0] if data_stores else None
    
    def _find_payment_datastore(self, data_stores: List[DataStore]) -> Optional[DataStore]:
        """Find datastore that handles payment data"""
        for store in data_stores:
            if 'payment_data' in store.sensitive_data_types:
                return store
        return self._find_user_datastore(data_stores)
    
    def _find_system_datastore(self, data_stores: List[DataStore]) -> Optional[DataStore]:
        """Find datastore for system/configuration data"""
        for store in data_stores:
            if store.type == DataStoreType.DATABASE:
                return store
        return data_stores[0] if data_stores else None
    
    def _find_sensitive_datastore(self, data_stores: List[DataStore]) -> Optional[DataStore]:
        """Find datastore with sensitive data"""
        for store in data_stores:
            if store.sensitive_data_types:
                return store
        return data_stores[0] if data_stores else None