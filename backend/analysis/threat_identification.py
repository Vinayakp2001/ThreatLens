"""STRIDE-based threat identification using OWASP threat modeling methodology."""

from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from ..models.system_model import (
    System, Component, DataStore, DataFlow, ExternalEntity, 
    TrustBoundary, ComponentType, DataStoreType, TrustLevel, 
    DataClassification, Protocol
)
from ..models.threats import (
    Threat, StrideCategory, LikelihoodLevel, ImpactLevel, 
    ThreatResponse, AttackVector
)


@dataclass
class ThreatContext:
    """Context information for threat identification."""
    system: System
    component_map: Dict[str, Component]
    datastore_map: Dict[str, DataStore]
    external_entity_map: Dict[str, ExternalEntity]
    trust_boundary_map: Dict[str, TrustBoundary]
    dataflow_map: Dict[str, DataFlow]


class ThreatIdentifier:
    """STRIDE-based threat identification engine."""
    
    def __init__(self):
        self.threat_counter = 0

    def identify_all_threats(self, system: System) -> List[Threat]:
        """Identify all STRIDE threats for the system."""
        context = self._build_threat_context(system)
        
        threats = []
        threats.extend(self.find_spoofing_threats(system, context))
        threats.extend(self.find_tampering_threats(system, context))
        threats.extend(self.find_repudiation_threats(system, context))
        threats.extend(self.find_information_disclosure_threats(system, context))
        threats.extend(self.find_denial_of_service_threats(system, context))
        threats.extend(self.find_elevation_of_privilege_threats(system, context))
        
        return threats

    def _build_threat_context(self, system: System) -> ThreatContext:
        """Build threat identification context."""
        return ThreatContext(
            system=system,
            component_map={comp.id: comp for comp in system.components},
            datastore_map={ds.id: ds for ds in system.data_stores},
            external_entity_map={ext.id: ext for ext in system.external_entities},
            trust_boundary_map={tb.id: tb for tb in system.trust_boundaries},
            dataflow_map={df.id: df for df in system.data_flows}
        )

    def find_spoofing_threats(self, system: System, context: ThreatContext = None) -> List[Threat]:
        """Identify spoofing threats - attacks on authentication."""
        if context is None:
            context = self._build_threat_context(system)
        
        threats = []
        
        # Check components for authentication weaknesses
        for component in system.components:
            threats.extend(self._find_component_spoofing_threats(component, context))
        
        # Check data flows for authentication bypass
        for data_flow in system.data_flows:
            threats.extend(self._find_dataflow_spoofing_threats(data_flow, context))
        
        # Check external entities for impersonation risks
        for external_entity in system.external_entities:
            threats.extend(self._find_external_spoofing_threats(external_entity, context))
        
        return threats

    def _find_component_spoofing_threats(self, component: Component, context: ThreatContext) -> List[Threat]:
        """Find spoofing threats for a specific component."""
        threats = []
        
        # Weak or missing authentication
        if not component.authentication_required:
            threat = self._create_threat(
                title=f"Missing Authentication in {component.name}",
                description=f"Component {component.name} does not require authentication, allowing potential spoofing attacks",
                stride_category=StrideCategory.SPOOFING,
                likelihood=LikelihoodLevel.HIGH if component.type == ComponentType.WEB_SERVICE else LikelihoodLevel.MEDIUM,
                impact=ImpactLevel.HIGH if component.trust_level == TrustLevel.HIGH else ImpactLevel.MEDIUM,
                affected_assets=[component.id],
                attack_vectors=[AttackVector.NETWORK, AttackVector.APPLICATION],
                prerequisites=["Network access to component", "Knowledge of component endpoints"],
                owasp_references=["Authentication_Cheat_Sheet", "Session_Management_Cheat_Sheet"],
                cwe_ids=["CWE-287", "CWE-306"]
            )
            threats.append(threat)
        
        # Weak authentication mechanisms
        if component.authentication_required and not component.authorization_mechanisms:
            threat = self._create_threat(
                title=f"Weak Authorization in {component.name}",
                description=f"Component {component.name} has authentication but lacks proper authorization mechanisms",
                stride_category=StrideCategory.SPOOFING,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=ImpactLevel.MEDIUM,
                affected_assets=[component.id],
                attack_vectors=[AttackVector.APPLICATION],
                prerequisites=["Valid user credentials", "Knowledge of component functionality"],
                owasp_references=["Authorization_Cheat_Sheet", "Access_Control_Cheat_Sheet"],
                cwe_ids=["CWE-285", "CWE-862"]
            )
            threats.append(threat)
        
        # Session management issues for web services
        if component.type == ComponentType.WEB_SERVICE:
            threat = self._create_threat(
                title=f"Session Hijacking in {component.name}",
                description=f"Web service {component.name} may be vulnerable to session hijacking attacks",
                stride_category=StrideCategory.SPOOFING,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=ImpactLevel.HIGH,
                affected_assets=[component.id],
                attack_vectors=[AttackVector.NETWORK, AttackVector.APPLICATION],
                prerequisites=["Network interception capability", "Session token exposure"],
                owasp_references=["Session_Management_Cheat_Sheet", "Transport_Layer_Security_Cheat_Sheet"],
                cwe_ids=["CWE-384", "CWE-613"]
            )
            threats.append(threat)
        
        return threats

    def _find_dataflow_spoofing_threats(self, data_flow: DataFlow, context: ThreatContext) -> List[Threat]:
        """Find spoofing threats in data flows."""
        threats = []
        
        # Unauthenticated data flows
        if not data_flow.authentication_required:
            threat = self._create_threat(
                title=f"Unauthenticated Data Flow: {data_flow.name}",
                description=f"Data flow {data_flow.name} lacks authentication, enabling spoofing attacks",
                stride_category=StrideCategory.SPOOFING,
                likelihood=LikelihoodLevel.HIGH,
                impact=self._determine_dataflow_impact(data_flow),
                affected_assets=[data_flow.source_id, data_flow.destination_id],
                attack_vectors=[AttackVector.NETWORK],
                prerequisites=["Network access to data flow", "Protocol knowledge"],
                owasp_references=["Authentication_Cheat_Sheet", "Transport_Layer_Security_Cheat_Sheet"],
                cwe_ids=["CWE-287", "CWE-306"]
            )
            threats.append(threat)
        
        # Insecure protocols
        if data_flow.protocol in [Protocol.HTTP, Protocol.TCP] and not data_flow.encryption_in_transit:
            threat = self._create_threat(
                title=f"Insecure Protocol in {data_flow.name}",
                description=f"Data flow {data_flow.name} uses insecure protocol without encryption",
                stride_category=StrideCategory.SPOOFING,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=self._determine_dataflow_impact(data_flow),
                affected_assets=[data_flow.source_id, data_flow.destination_id],
                attack_vectors=[AttackVector.NETWORK],
                prerequisites=["Network interception capability", "Protocol analysis tools"],
                owasp_references=["Transport_Layer_Security_Cheat_Sheet", "Cryptographic_Storage_Cheat_Sheet"],
                cwe_ids=["CWE-319", "CWE-326"]
            )
            threats.append(threat)
        
        return threats

    def _find_external_spoofing_threats(self, external_entity: ExternalEntity, context: ThreatContext) -> List[Threat]:
        """Find spoofing threats related to external entities."""
        threats = []
        
        # Weak external authentication
        if external_entity.authentication_method in [None, "API_Key"]:
            threat = self._create_threat(
                title=f"Weak External Authentication: {external_entity.name}",
                description=f"External entity {external_entity.name} uses weak or no authentication",
                stride_category=StrideCategory.SPOOFING,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=ImpactLevel.MEDIUM,
                affected_assets=[external_entity.id],
                attack_vectors=[AttackVector.NETWORK, AttackVector.APPLICATION],
                prerequisites=["API key compromise", "Network access"],
                owasp_references=["Authentication_Cheat_Sheet", "REST_Security_Cheat_Sheet"],
                cwe_ids=["CWE-287", "CWE-798"]
            )
            threats.append(threat)
        
        return threats

    def find_tampering_threats(self, system: System, context: ThreatContext = None) -> List[Threat]:
        """Identify tampering threats - attacks on integrity."""
        if context is None:
            context = self._build_threat_context(system)
        
        threats = []
        
        # Check data stores for integrity protection
        for data_store in system.data_stores:
            threats.extend(self._find_datastore_tampering_threats(data_store, context))
        
        # Check data flows for integrity protection
        for data_flow in system.data_flows:
            threats.extend(self._find_dataflow_tampering_threats(data_flow, context))
        
        # Check components for input validation
        for component in system.components:
            threats.extend(self._find_component_tampering_threats(component, context))
        
        return threats

    def _find_datastore_tampering_threats(self, data_store: DataStore, context: ThreatContext) -> List[Threat]:
        """Find tampering threats for data stores."""
        threats = []
        
        # Unencrypted sensitive data
        if (data_store.data_classification == DataClassification.SENSITIVE and 
            not data_store.encryption_at_rest):
            threat = self._create_threat(
                title=f"Unencrypted Sensitive Data in {data_store.name}",
                description=f"Sensitive data in {data_store.name} is not encrypted at rest",
                stride_category=StrideCategory.TAMPERING,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=ImpactLevel.HIGH,
                affected_assets=[data_store.id],
                attack_vectors=[AttackVector.PHYSICAL, AttackVector.SYSTEM],
                prerequisites=["Physical or system access", "Storage access"],
                owasp_references=["Cryptographic_Storage_Cheat_Sheet", "Key_Management_Cheat_Sheet"],
                cwe_ids=["CWE-311", "CWE-312"]
            )
            threats.append(threat)
        
        # Weak access controls
        if not data_store.access_controls:
            threat = self._create_threat(
                title=f"Missing Access Controls in {data_store.name}",
                description=f"Data store {data_store.name} lacks proper access controls",
                stride_category=StrideCategory.TAMPERING,
                likelihood=LikelihoodLevel.HIGH,
                impact=ImpactLevel.HIGH,
                affected_assets=[data_store.id],
                attack_vectors=[AttackVector.APPLICATION, AttackVector.SYSTEM],
                prerequisites=["Application access", "Database connection"],
                owasp_references=["Access_Control_Cheat_Sheet", "Authorization_Cheat_Sheet"],
                cwe_ids=["CWE-284", "CWE-862"]
            )
            threats.append(threat)
        
        # Missing backup integrity
        if not data_store.backup_enabled:
            threat = self._create_threat(
                title=f"Missing Backup Protection in {data_store.name}",
                description=f"Data store {data_store.name} lacks backup and recovery mechanisms",
                stride_category=StrideCategory.TAMPERING,
                likelihood=LikelihoodLevel.LOW,
                impact=ImpactLevel.HIGH,
                affected_assets=[data_store.id],
                attack_vectors=[AttackVector.SYSTEM],
                prerequisites=["System compromise", "Data corruption"],
                owasp_references=["Logging_Cheat_Sheet"],
                cwe_ids=["CWE-404"]
            )
            threats.append(threat)
        
        return threats

    def _find_dataflow_tampering_threats(self, data_flow: DataFlow, context: ThreatContext) -> List[Threat]:
        """Find tampering threats in data flows."""
        threats = []
        
        # Unencrypted data in transit
        if not data_flow.encryption_in_transit:
            threat = self._create_threat(
                title=f"Unencrypted Data in Transit: {data_flow.name}",
                description=f"Data flow {data_flow.name} transmits data without encryption",
                stride_category=StrideCategory.TAMPERING,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=self._determine_dataflow_impact(data_flow),
                affected_assets=[data_flow.source_id, data_flow.destination_id],
                attack_vectors=[AttackVector.NETWORK],
                prerequisites=["Network interception", "Man-in-the-middle position"],
                owasp_references=["Transport_Layer_Security_Cheat_Sheet", "Cryptographic_Storage_Cheat_Sheet"],
                cwe_ids=["CWE-319", "CWE-326"]
            )
            threats.append(threat)
        
        # Missing integrity checks
        threat = self._create_threat(
            title=f"Missing Integrity Verification: {data_flow.name}",
            description=f"Data flow {data_flow.name} lacks integrity verification mechanisms",
            stride_category=StrideCategory.TAMPERING,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=self._determine_dataflow_impact(data_flow),
            affected_assets=[data_flow.source_id, data_flow.destination_id],
            attack_vectors=[AttackVector.NETWORK, AttackVector.APPLICATION],
            prerequisites=["Network access", "Protocol manipulation capability"],
            owasp_references=["Transport_Layer_Security_Cheat_Sheet", "REST_Security_Cheat_Sheet"],
            cwe_ids=["CWE-345", "CWE-354"]
        )
        threats.append(threat)
        
        return threats

    def _find_component_tampering_threats(self, component: Component, context: ThreatContext) -> List[Threat]:
        """Find tampering threats for components."""
        threats = []
        
        # Input validation issues
        threat = self._create_threat(
            title=f"Input Validation Bypass in {component.name}",
            description=f"Component {component.name} may lack proper input validation",
            stride_category=StrideCategory.TAMPERING,
            likelihood=LikelihoodLevel.HIGH,
            impact=ImpactLevel.HIGH,
            affected_assets=[component.id],
            attack_vectors=[AttackVector.APPLICATION],
            prerequisites=["Application access", "Malicious input crafting"],
            owasp_references=["Input_Validation_Cheat_Sheet", "Injection_Prevention_Cheat_Sheet"],
            cwe_ids=["CWE-20", "CWE-79", "CWE-89"]
        )
        threats.append(threat)
        
        # Code injection for web services
        if component.type == ComponentType.WEB_SERVICE:
            threat = self._create_threat(
                title=f"Code Injection in {component.name}",
                description=f"Web service {component.name} may be vulnerable to code injection attacks",
                stride_category=StrideCategory.TAMPERING,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=ImpactLevel.HIGH,
                affected_assets=[component.id],
                attack_vectors=[AttackVector.APPLICATION],
                prerequisites=["Web application access", "Injection payload knowledge"],
                owasp_references=["Injection_Prevention_Cheat_Sheet", "SQL_Injection_Prevention_Cheat_Sheet"],
                cwe_ids=["CWE-89", "CWE-78", "CWE-94"]
            )
            threats.append(threat)
        
        return threats

    def find_repudiation_threats(self, system: System, context: ThreatContext = None) -> List[Threat]:
        """Identify repudiation threats - attacks on non-repudiation."""
        if context is None:
            context = self._build_threat_context(system)
        
        threats = []
        
        # Check components for logging and auditing
        for component in system.components:
            threats.extend(self._find_component_repudiation_threats(component, context))
        
        # Check data stores for audit trails
        for data_store in system.data_stores:
            threats.extend(self._find_datastore_repudiation_threats(data_store, context))
        
        return threats

    def _find_component_repudiation_threats(self, component: Component, context: ThreatContext) -> List[Threat]:
        """Find repudiation threats for components."""
        threats = []
        
        # Missing audit logging
        threat = self._create_threat(
            title=f"Missing Audit Logging in {component.name}",
            description=f"Component {component.name} lacks comprehensive audit logging",
            stride_category=StrideCategory.REPUDIATION,
            likelihood=LikelihoodLevel.HIGH,
            impact=ImpactLevel.MEDIUM,
            affected_assets=[component.id],
            attack_vectors=[AttackVector.APPLICATION],
            prerequisites=["Component access", "Malicious actions"],
            owasp_references=["Logging_Cheat_Sheet", "Authentication_Cheat_Sheet"],
            cwe_ids=["CWE-778", "CWE-117"]
        )
        threats.append(threat)
        
        # Insufficient log integrity
        threat = self._create_threat(
            title=f"Log Tampering in {component.name}",
            description=f"Audit logs in {component.name} may be tampered with or deleted",
            stride_category=StrideCategory.REPUDIATION,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.MEDIUM,
            affected_assets=[component.id],
            attack_vectors=[AttackVector.SYSTEM, AttackVector.APPLICATION],
            prerequisites=["System access", "Log file access"],
            owasp_references=["Logging_Cheat_Sheet"],
            cwe_ids=["CWE-117", "CWE-532"]
        )
        threats.append(threat)
        
        return threats

    def _find_datastore_repudiation_threats(self, data_store: DataStore, context: ThreatContext) -> List[Threat]:
        """Find repudiation threats for data stores."""
        threats = []
        
        # Missing database audit trails
        threat = self._create_threat(
            title=f"Missing Database Audit Trail in {data_store.name}",
            description=f"Data store {data_store.name} lacks audit trail for data modifications",
            stride_category=StrideCategory.REPUDIATION,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.MEDIUM,
            affected_assets=[data_store.id],
            attack_vectors=[AttackVector.APPLICATION, AttackVector.SYSTEM],
            prerequisites=["Database access", "Data modification capability"],
            owasp_references=["Logging_Cheat_Sheet"],
            cwe_ids=["CWE-778"]
        )
        threats.append(threat)
        
        return threats

    def find_information_disclosure_threats(self, system: System, context: ThreatContext = None) -> List[Threat]:
        """Identify information disclosure threats - attacks on confidentiality."""
        if context is None:
            context = self._build_threat_context(system)
        
        threats = []
        
        # Check data stores for confidentiality protection
        for data_store in system.data_stores:
            threats.extend(self._find_datastore_disclosure_threats(data_store, context))
        
        # Check data flows for confidentiality
        for data_flow in system.data_flows:
            threats.extend(self._find_dataflow_disclosure_threats(data_flow, context))
        
        # Check components for information leakage
        for component in system.components:
            threats.extend(self._find_component_disclosure_threats(component, context))
        
        return threats

    def _find_datastore_disclosure_threats(self, data_store: DataStore, context: ThreatContext) -> List[Threat]:
        """Find information disclosure threats for data stores."""
        threats = []
        
        # Unencrypted sensitive data
        if (data_store.data_classification == DataClassification.SENSITIVE and 
            not data_store.encryption_at_rest):
            threat = self._create_threat(
                title=f"Sensitive Data Exposure in {data_store.name}",
                description=f"Sensitive data in {data_store.name} is stored without encryption",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                likelihood=LikelihoodLevel.MEDIUM,
                impact=ImpactLevel.HIGH,
                affected_assets=[data_store.id],
                attack_vectors=[AttackVector.PHYSICAL, AttackVector.SYSTEM],
                prerequisites=["Storage access", "Data extraction capability"],
                owasp_references=["Cryptographic_Storage_Cheat_Sheet", "Key_Management_Cheat_Sheet"],
                cwe_ids=["CWE-311", "CWE-312"]
            )
            threats.append(threat)
        
        # Excessive database permissions
        threat = self._create_threat(
            title=f"Excessive Database Permissions in {data_store.name}",
            description=f"Database {data_store.name} may have overly permissive access controls",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.MEDIUM,
            affected_assets=[data_store.id],
            attack_vectors=[AttackVector.APPLICATION],
            prerequisites=["Database connection", "Privilege escalation"],
            owasp_references=["Access_Control_Cheat_Sheet"],
            cwe_ids=["CWE-284", "CWE-732"]
        )
        threats.append(threat)
        
        return threats

    def _find_dataflow_disclosure_threats(self, data_flow: DataFlow, context: ThreatContext) -> List[Threat]:
        """Find information disclosure threats in data flows."""
        threats = []
        
        # Unencrypted sensitive data in transit
        if (data_flow.data_classification == DataClassification.SENSITIVE and 
            not data_flow.encryption_in_transit):
            threat = self._create_threat(
                title=f"Sensitive Data Interception: {data_flow.name}",
                description=f"Sensitive data in {data_flow.name} transmitted without encryption",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                likelihood=LikelihoodLevel.HIGH,
                impact=ImpactLevel.HIGH,
                affected_assets=[data_flow.source_id, data_flow.destination_id],
                attack_vectors=[AttackVector.NETWORK],
                prerequisites=["Network interception", "Traffic analysis capability"],
                owasp_references=["Transport_Layer_Security_Cheat_Sheet"],
                cwe_ids=["CWE-319", "CWE-200"]
            )
            threats.append(threat)
        
        return threats

    def _find_component_disclosure_threats(self, component: Component, context: ThreatContext) -> List[Threat]:
        """Find information disclosure threats for components."""
        threats = []
        
        # Information leakage through error messages
        threat = self._create_threat(
            title=f"Information Leakage in {component.name}",
            description=f"Component {component.name} may leak sensitive information through error messages",
            stride_category=StrideCategory.INFORMATION_DISCLOSURE,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.MEDIUM,
            affected_assets=[component.id],
            attack_vectors=[AttackVector.APPLICATION],
            prerequisites=["Application access", "Error condition triggering"],
            owasp_references=["Error_Handling_Cheat_Sheet"],
            cwe_ids=["CWE-200", "CWE-209"]
        )
        threats.append(threat)
        
        # Debug information exposure
        if component.type == ComponentType.WEB_SERVICE:
            threat = self._create_threat(
                title=f"Debug Information Exposure in {component.name}",
                description=f"Web service {component.name} may expose debug information in production",
                stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                likelihood=LikelihoodLevel.LOW,
                impact=ImpactLevel.MEDIUM,
                affected_assets=[component.id],
                attack_vectors=[AttackVector.APPLICATION],
                prerequisites=["Web application access", "Debug mode enabled"],
                owasp_references=["Error_Handling_Cheat_Sheet"],
                cwe_ids=["CWE-200", "CWE-489"]
            )
            threats.append(threat)
        
        return threats

    def find_denial_of_service_threats(self, system: System, context: ThreatContext = None) -> List[Threat]:
        """Identify denial of service threats - attacks on availability."""
        if context is None:
            context = self._build_threat_context(system)
        
        threats = []
        
        # Check components for DoS vulnerabilities
        for component in system.components:
            threats.extend(self._find_component_dos_threats(component, context))
        
        # Check data stores for availability issues
        for data_store in system.data_stores:
            threats.extend(self._find_datastore_dos_threats(data_store, context))
        
        # Check data flows for bottlenecks
        for data_flow in system.data_flows:
            threats.extend(self._find_dataflow_dos_threats(data_flow, context))
        
        return threats

    def _find_component_dos_threats(self, component: Component, context: ThreatContext) -> List[Threat]:
        """Find DoS threats for components."""
        threats = []
        
        # Resource exhaustion
        threat = self._create_threat(
            title=f"Resource Exhaustion in {component.name}",
            description=f"Component {component.name} may be vulnerable to resource exhaustion attacks",
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.HIGH if component.type == ComponentType.WEB_SERVICE else ImpactLevel.MEDIUM,
            affected_assets=[component.id],
            attack_vectors=[AttackVector.NETWORK, AttackVector.APPLICATION],
            prerequisites=["Network access", "High request volume capability"],
            owasp_references=["Denial_of_Service_Cheat_Sheet"],
            cwe_ids=["CWE-400", "CWE-770"]
        )
        threats.append(threat)
        
        # Application-level DoS for web services
        if component.type == ComponentType.WEB_SERVICE:
            threat = self._create_threat(
                title=f"Application DoS in {component.name}",
                description=f"Web service {component.name} vulnerable to application-layer DoS attacks",
                stride_category=StrideCategory.DENIAL_OF_SERVICE,
                likelihood=LikelihoodLevel.HIGH,
                impact=ImpactLevel.HIGH,
                affected_assets=[component.id],
                attack_vectors=[AttackVector.APPLICATION],
                prerequisites=["Web application access", "Malicious request crafting"],
                owasp_references=["Denial_of_Service_Cheat_Sheet", "Input_Validation_Cheat_Sheet"],
                cwe_ids=["CWE-400", "CWE-770"]
            )
            threats.append(threat)
        
        return threats

    def _find_datastore_dos_threats(self, data_store: DataStore, context: ThreatContext) -> List[Threat]:
        """Find DoS threats for data stores."""
        threats = []
        
        # Database connection exhaustion
        threat = self._create_threat(
            title=f"Connection Exhaustion in {data_store.name}",
            description=f"Data store {data_store.name} may suffer from connection pool exhaustion",
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.HIGH,
            affected_assets=[data_store.id],
            attack_vectors=[AttackVector.APPLICATION],
            prerequisites=["Database access", "Connection flooding capability"],
            owasp_references=["Denial_of_Service_Cheat_Sheet"],
            cwe_ids=["CWE-400", "CWE-770"]
        )
        threats.append(threat)
        
        # Storage exhaustion
        threat = self._create_threat(
            title=f"Storage Exhaustion in {data_store.name}",
            description=f"Data store {data_store.name} may be vulnerable to storage exhaustion attacks",
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            likelihood=LikelihoodLevel.LOW,
            impact=ImpactLevel.HIGH,
            affected_assets=[data_store.id],
            attack_vectors=[AttackVector.APPLICATION],
            prerequisites=["Data insertion capability", "Large data volume"],
            owasp_references=["Denial_of_Service_Cheat_Sheet"],
            cwe_ids=["CWE-400", "CWE-770"]
        )
        threats.append(threat)
        
        return threats

    def _find_dataflow_dos_threats(self, data_flow: DataFlow, context: ThreatContext) -> List[Threat]:
        """Find DoS threats in data flows."""
        threats = []
        
        # Network bandwidth exhaustion
        threat = self._create_threat(
            title=f"Bandwidth Exhaustion: {data_flow.name}",
            description=f"Data flow {data_flow.name} may be vulnerable to bandwidth exhaustion",
            stride_category=StrideCategory.DENIAL_OF_SERVICE,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=self._determine_dataflow_impact(data_flow),
            affected_assets=[data_flow.source_id, data_flow.destination_id],
            attack_vectors=[AttackVector.NETWORK],
            prerequisites=["Network access", "High bandwidth capability"],
            owasp_references=["Denial_of_Service_Cheat_Sheet"],
            cwe_ids=["CWE-400"]
        )
        threats.append(threat)
        
        return threats

    def find_elevation_of_privilege_threats(self, system: System, context: ThreatContext = None) -> List[Threat]:
        """Identify elevation of privilege threats - attacks on authorization."""
        if context is None:
            context = self._build_threat_context(system)
        
        threats = []
        
        # Check components for privilege escalation
        for component in system.components:
            threats.extend(self._find_component_privilege_threats(component, context))
        
        # Check trust boundaries for privilege escalation
        for trust_boundary in system.trust_boundaries:
            threats.extend(self._find_trust_boundary_privilege_threats(trust_boundary, context))
        
        return threats

    def _find_component_privilege_threats(self, component: Component, context: ThreatContext) -> List[Threat]:
        """Find privilege escalation threats for components."""
        threats = []
        
        # Missing authorization checks
        if not component.authorization_mechanisms:
            threat = self._create_threat(
                title=f"Missing Authorization in {component.name}",
                description=f"Component {component.name} lacks proper authorization mechanisms",
                stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
                likelihood=LikelihoodLevel.HIGH,
                impact=ImpactLevel.HIGH,
                affected_assets=[component.id],
                attack_vectors=[AttackVector.APPLICATION],
                prerequisites=["Component access", "Valid authentication"],
                owasp_references=["Authorization_Cheat_Sheet", "Access_Control_Cheat_Sheet"],
                cwe_ids=["CWE-285", "CWE-862"]
            )
            threats.append(threat)
        
        # Privilege escalation through vulnerabilities
        threat = self._create_threat(
            title=f"Privilege Escalation in {component.name}",
            description=f"Component {component.name} may contain vulnerabilities leading to privilege escalation",
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.HIGH,
            affected_assets=[component.id],
            attack_vectors=[AttackVector.APPLICATION, AttackVector.SYSTEM],
            prerequisites=["Component access", "Vulnerability exploitation"],
            owasp_references=["Authorization_Cheat_Sheet"],
            cwe_ids=["CWE-269", "CWE-264"]
        )
        threats.append(threat)
        
        return threats

    def _find_trust_boundary_privilege_threats(self, trust_boundary: TrustBoundary, context: ThreatContext) -> List[Threat]:
        """Find privilege escalation threats across trust boundaries."""
        threats = []
        
        # Trust boundary bypass
        threat = self._create_threat(
            title=f"Trust Boundary Bypass: {trust_boundary.name}",
            description=f"Trust boundary {trust_boundary.name} may be bypassed to escalate privileges",
            stride_category=StrideCategory.ELEVATION_OF_PRIVILEGE,
            likelihood=LikelihoodLevel.MEDIUM,
            impact=ImpactLevel.HIGH,
            affected_assets=trust_boundary.component_ids,
            attack_vectors=[AttackVector.NETWORK, AttackVector.APPLICATION],
            prerequisites=["Network access", "Trust boundary knowledge"],
            owasp_references=["Authorization_Cheat_Sheet", "Access_Control_Cheat_Sheet"],
            cwe_ids=["CWE-285", "CWE-863"]
        )
        threats.append(threat)
        
        return threats

    def _create_threat(self, title: str, description: str, stride_category: StrideCategory,
                      likelihood: LikelihoodLevel, impact: ImpactLevel, affected_assets: List[str],
                      attack_vectors: List[AttackVector], prerequisites: List[str],
                      owasp_references: List[str], cwe_ids: List[str]) -> Threat:
        """Create a threat instance."""
        self.threat_counter += 1
        
        return Threat(
            id=f"threat_{self.threat_counter:04d}",
            title=title,
            description=description,
            stride_category=stride_category,
            likelihood=likelihood,
            impact=impact,
            risk_score=self._calculate_risk_score(likelihood, impact),
            affected_assets=affected_assets,
            attack_vectors=attack_vectors,
            prerequisites=prerequisites,
            mitigations=[],  # Will be populated by mitigation identification
            owasp_references=owasp_references,
            cwe_ids=cwe_ids,
            response=ThreatResponse.MITIGATE  # Default response
        )

    def _calculate_risk_score(self, likelihood: LikelihoodLevel, impact: ImpactLevel) -> float:
        """Calculate risk score based on likelihood and impact."""
        likelihood_values = {
            LikelihoodLevel.VERY_LOW: 1,
            LikelihoodLevel.LOW: 2,
            LikelihoodLevel.MEDIUM: 3,
            LikelihoodLevel.HIGH: 4,
            LikelihoodLevel.VERY_HIGH: 5
        }
        
        impact_values = {
            ImpactLevel.VERY_LOW: 1,
            ImpactLevel.LOW: 2,
            ImpactLevel.MEDIUM: 3,
            ImpactLevel.HIGH: 4,
            ImpactLevel.VERY_HIGH: 5
        }
        
        return likelihood_values[likelihood] * impact_values[impact]

    def _determine_dataflow_impact(self, data_flow: DataFlow) -> ImpactLevel:
        """Determine impact level based on data flow characteristics."""
        if data_flow.data_classification == DataClassification.SENSITIVE:
            return ImpactLevel.HIGH
        elif data_flow.data_classification == DataClassification.INTERNAL:
            return ImpactLevel.MEDIUM
        else:
            return ImpactLevel.LOW