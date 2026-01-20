"""
Core data models for the Threat Modeling Documentation Generator
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime
from dataclasses import dataclass, field


class ComponentType(str, Enum):
    PROCESS = "process"
    EXTERNAL_ENTITY = "external_entity"
    DATA_STORE = "data_store"
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
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LikelihoodLevel(str, Enum):
    UNKNOWN = "unknown"
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
    component_type: ComponentType  # Changed from 'type' to 'component_type'
    file_path: Optional[str] = None
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


class Mitigation(BaseModel):
    """Security mitigation model"""
    id: str
    description: str
    implementation_notes: Optional[str] = None
    status: str = "proposed"  # proposed, implemented, verified
    effectiveness: Optional[str] = None  # low, medium, high
    cost: Optional[str] = None  # low, medium, high
    priority: Optional[str] = None  # low, medium, high, critical


class Threat(BaseModel):
    """Individual threat model"""
    id: str
    title: str
    description: str
    stride_category: StrideCategory
    impact: ImpactLevel
    likelihood: LikelihoodLevel
    affected_components: List[str] = Field(default_factory=list)
    mitigations: List[Mitigation] = Field(default_factory=list)
    cwe_references: List[str] = Field(default_factory=list)


class SecurityPatterns(BaseModel):
    """Security patterns detected in the codebase"""
    authentication_mechanisms: List[str] = Field(default_factory=list)
    authorization_patterns: List[str] = Field(default_factory=list)
    input_validation_patterns: List[str] = Field(default_factory=list)
    encryption_usage: List[str] = Field(default_factory=list)
    logging_patterns: List[str] = Field(default_factory=list)


class SecurityModel(BaseModel):
    """Complete security model of the repository"""
    id: str
    name: str
    description: Optional[str] = None
    repo_id: Optional[str] = None
    components: List[Component] = Field(default_factory=list)
    data_stores: List[DataStore] = Field(default_factory=list)
    flows: List[Flow] = Field(default_factory=list)
    threats: List[Threat] = Field(default_factory=list)  # Added threats field
    security_patterns: SecurityPatterns = Field(default_factory=SecurityPatterns)
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


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


# New Wiki-specific models for consolidated security documentation

class SecurityFinding(BaseModel):
    """Security finding for wiki integration"""
    id: str
    type: str  # vulnerability, threat, risk, etc.
    severity: str  # low, medium, high, critical
    description: str
    affected_components: List[str] = Field(default_factory=list)
    owasp_category: Optional[str] = None
    stride_category: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)
    code_references: List[CodeReference] = Field(default_factory=list)


class OWASPMapping(BaseModel):
    """OWASP guideline mapping"""
    cheatsheet: str
    section: str
    relevance_score: float
    recommendations: List[str] = Field(default_factory=list)


class OWASPGuidance(BaseModel):
    """OWASP guidance for wiki integration"""
    recommendations: List[str] = Field(default_factory=list)
    cheatsheet_references: List[Dict[str, Any]] = Field(default_factory=list)
    integration_points: List[str] = Field(default_factory=list)
    owasp_mappings: List[OWASPMapping] = Field(default_factory=list)


class WikiSectionContent(BaseModel):
    """Content for wiki section generation"""
    title: str
    content: str
    cross_references: List[str] = Field(default_factory=list)
    owasp_mappings: List[str] = Field(default_factory=list)
    code_snippets: List[CodeReference] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class WikiSection(BaseModel):
    """Individual wiki section"""
    id: str
    title: str
    content: str
    subsections: List['WikiSection'] = Field(default_factory=list)
    cross_references: List[str] = Field(default_factory=list)
    owasp_mappings: List[str] = Field(default_factory=list)
    code_references: List[CodeReference] = Field(default_factory=list)
    security_findings: List[SecurityFinding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityWiki(BaseModel):
    """Unified security wiki structure"""
    id: str
    repo_id: str
    title: str
    sections: Dict[str, WikiSection] = Field(default_factory=dict)
    cross_references: Dict[str, List[str]] = Field(default_factory=dict)
    search_index: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None


# Enable forward references for WikiSection self-reference
WikiSection.model_rebuild()


# User Wiki Collection Models (Phase 1 MVP)

class UserWiki(BaseModel):
    """User's personal wiki collection entry"""
    id: str
    user_id: str
    repo_id: str
    repository_url: str
    repository_name: str
    wiki_id: Optional[str] = None  # Reference to SecurityWiki
    analysis_status: str = "pending"  # pending, analyzing, completed, failed
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Computed fields for UI display
    @property
    def display_name(self) -> str:
        """Get display name for the repository"""
        if self.repository_name:
            return self.repository_name
        # Extract name from URL as fallback
        return self.repository_url.split('/')[-1].replace('.git', '')
    
    @property
    def is_completed(self) -> bool:
        """Check if analysis is completed"""
        return self.analysis_status == "completed"


# Chat System Models
@dataclass
class ChatMessage:
    """Individual chat message"""
    id: str
    role: str  # 'user' or 'assistant'
    content: str
    timestamp: datetime
    sources: List[Dict[str, Any]] = field(default_factory=list)

@dataclass 
class ChatSession:
    """Chat session with conversation history"""
    session_id: str
    repo_id: str
    user_id: str
    created_at: datetime
    messages: List[ChatMessage] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

class ChatRequest(BaseModel):
    """Request model for chat messages"""
    message: str = Field(..., description="User message")
    session_id: Optional[str] = Field(None, description="Existing session ID")

class ChatResponse(BaseModel):
    """Response model for chat messages"""
    message: str = Field(..., description="AI response")
    session_id: str = Field(..., description="Session ID")
    sources: List[Dict[str, Any]] = Field(default_factory=list, description="Source documents")
    timestamp: str = Field(..., description="Response timestamp")

class ChatHistoryResponse(BaseModel):
    """Response model for chat history"""
    session_id: str = Field(..., description="Session ID")
    messages: List[Dict[str, Any]] = Field(..., description="Chat messages")
    repository_name: Optional[str] = Field(None, description="Repository name")