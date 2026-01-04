"""
Core data models for the Threat Modeling Documentation Generator
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime


class ComponentType(str, Enum):
    SERVICE = "service"
    CONTROLLER = "controller"
    MIDDLEWARE = "middleware"
    WORKER = "worker"
    MODEL = "model"
    UTILITY = "utility"


class DataStoreType(str, Enum):
    DATABASE = "database"
    CACHE = "cache"
    FILE_STORAGE = "file_storage"
    EXTERNAL_API = "external_api"


class FlowType(str, Enum):
    AUTHENTICATION = "authentication"
    PAYMENT = "payment"
    DATA_ACCESS = "data_access"
    ADMIN = "admin"
    USER_REGISTRATION = "user_registration"


# Removed rigid ThreatDocType enum - replaced with flexible SecurityDocument model


class DataSensitivityLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class StrideCategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class ImpactLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LikelihoodLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Endpoint(BaseModel):
    """API endpoint model"""
    path: str
    method: str
    handler_function: Optional[str] = None
    requires_auth: bool = False
    sensitive_data: bool = False


class Component(BaseModel):
    """System component model"""
    id: str
    name: str
    type: ComponentType
    file_path: str
    endpoints: List[Endpoint] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    handles_sensitive_data: bool = False
    auth_mechanisms: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class DataStore(BaseModel):
    """Data store model"""
    id: str
    name: str
    type: DataStoreType
    sensitive_data_types: List[str] = Field(default_factory=list)
    access_patterns: List[str] = Field(default_factory=list)
    connection_info: Optional[Dict[str, Any]] = None


class TrustBoundary(BaseModel):
    """Trust boundary model"""
    id: str
    name: str
    description: str
    components_inside: List[str] = Field(default_factory=list)
    components_outside: List[str] = Field(default_factory=list)


class FlowStep(BaseModel):
    """Individual step in a data flow"""
    step_number: int
    description: str
    component_id: str
    data_processed: List[str] = Field(default_factory=list)
    trust_boundary_crossing: Optional[str] = None


class Flow(BaseModel):
    """Data flow model"""
    id: str
    name: str
    flow_type: FlowType
    steps: List[FlowStep] = Field(default_factory=list)
    components_involved: List[str] = Field(default_factory=list)
    data_sensitivity: DataSensitivityLevel
    trust_boundary_crossings: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class SecurityPatterns(BaseModel):
    """Security patterns detected in the codebase"""
    authentication_mechanisms: List[str] = Field(default_factory=list)
    authorization_patterns: List[str] = Field(default_factory=list)
    input_validation_patterns: List[str] = Field(default_factory=list)
    encryption_usage: List[str] = Field(default_factory=list)
    logging_patterns: List[str] = Field(default_factory=list)


class SecurityModel(BaseModel):
    """Complete security model of the repository"""
    repo_id: str
    components: List[Component] = Field(default_factory=list)
    data_stores: List[DataStore] = Field(default_factory=list)
    flows: List[Flow] = Field(default_factory=list)
    security_patterns: SecurityPatterns = Field(default_factory=SecurityPatterns)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)


class StructureAnalysis(BaseModel):
    """Repository structure analysis results"""
    total_files: int
    primary_languages: List[str] = Field(default_factory=list)
    directory_structure: Dict[str, Any] = Field(default_factory=dict)
    key_directories: List[str] = Field(default_factory=list)
    detected_frameworks: List[str] = Field(default_factory=list)


class RepoContext(BaseModel):
    """Repository context and metadata"""
    repo_id: str
    repo_url: Optional[str] = None
    local_path: str
    primary_languages: List[str] = Field(default_factory=list)
    structure_summary: Dict[str, Any] = Field(default_factory=dict)
    analysis_status: str = "pending"
    created_at: datetime = Field(default_factory=datetime.now)


class CodeReference(BaseModel):
    """Reference to specific code location"""
    id: str
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    code_snippet: Optional[str] = None


class SecurityDocument(BaseModel):
    """Flexible security documentation model - replaces rigid ThreatDoc"""
    id: str
    repo_id: str
    title: str
    content: str  # Comprehensive security analysis content
    scope: str    # "full_repo" or "pr_only" 
    metadata: Dict[str, Any] = Field(default_factory=dict)
    code_references: List[CodeReference] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None


class PRAnalysis(BaseModel):
    """PR-specific security analysis model"""
    id: str
    pr_id: str
    repo_id: str
    pr_url: str
    changed_files: List[str] = Field(default_factory=list)
    security_issues: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    risk_level: str  # "low", "medium", "high", "critical"
    has_repo_context: bool = False  # Whether full repo analysis was available
    context_used: Dict[str, Any] = Field(default_factory=dict)  # What repo context was used
    created_at: datetime = Field(default_factory=datetime.now)


# Legacy ThreatDoc model - kept for backward compatibility during migration
class ThreatDoc(BaseModel):
    """Legacy threat modeling document - use SecurityDocument for new implementations"""
    id: str
    repo_id: str
    title: str
    doc_type: str  # Changed from ThreatDocType enum to string for flexibility
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    code_references: List[CodeReference] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None


class Threat(BaseModel):
    """Individual threat model"""
    id: str
    stride_category: StrideCategory
    description: str
    affected_components: List[str] = Field(default_factory=list)
    impact_level: ImpactLevel
    likelihood: LikelihoodLevel
    mitigations: List[str] = Field(default_factory=list)
    cwe_references: List[str] = Field(default_factory=list)


class SearchResult(BaseModel):
    """Search result from RAG system"""
    doc_id: str
    title: str
    content_snippet: str
    relevance_score: float
    doc_type: str  # Changed from ThreatDocType enum to string for flexibility
    code_references: List[CodeReference] = Field(default_factory=list)


class Embedding(BaseModel):
    """Embedding model for vector storage"""
    id: str
    repo_id: str
    content_type: str  # "document" or "code"
    content_id: str
    embedding_vector: List[float]
    metadata: Dict[str, Any] = Field(default_factory=dict)