"""System model construction from repository parser output."""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from ..models.system_model import (
    System, Component, DataStore, DataFlow, ExternalEntity, 
    TrustBoundary, CloudContext, ComponentType, DataStoreType,
    CloudProvider, DeploymentModel, TrustLevel, DataClassification,
    Interface, Protocol
)
from .repo_parser import (
    RepositoryParser, ParsedComponent, ParsedDataStore, 
    ParsedInfrastructure, ThirdPartyIntegration, InfrastructureType
)


@dataclass
class SystemBuildContext:
    """Context information for building system models."""
    repo_name: str
    repo_path: str
    detected_technologies: Set[str]
    cloud_services: Set[str]
    security_patterns: Set[str]


class SystemBuilder:
    """Builds System instances from repository parser output."""
    
    def __init__(self):
        self.component_counter = 0
        self.datastore_counter = 0
        self.dataflow_counter = 0
        self.trust_boundary_counter = 0

    def build_system_model(self, parser_output: Dict[str, any], repo_name: str, repo_path: str) -> System:
        """Build a complete System model from parser output."""
        context = self._create_build_context(parser_output, repo_name, repo_path)
        
        # Build core components
        components = self._build_components(parser_output['components'], context)
        data_stores = self._build_data_stores(parser_output['data_stores'], context)
        external_entities = self._build_external_entities(parser_output['third_party_integrations'], context)
        
        # Build relationships
        data_flows = self._build_data_flows(components, data_stores, external_entities, context)
        trust_boundaries = self._build_trust_boundaries(components, data_stores, context)
        
        # Build cloud context
        cloud_context = self._build_cloud_context(parser_output['infrastructure'], context)
        
        return System(
            id=f"system_{repo_name.lower().replace('-', '_')}",
            name=repo_name,
            description=f"System model for {repo_name} repository",
            components=components,
            data_stores=data_stores,
            data_flows=data_flows,
            external_entities=external_entities,
            trust_boundaries=trust_boundaries,
            cloud_context=cloud_context
        )

    def _create_build_context(self, parser_output: Dict[str, any], repo_name: str, repo_path: str) -> SystemBuildContext:
        """Create build context from parser output."""
        detected_technologies = set()
        cloud_services = set()
        security_patterns = set()
        
        # Extract technologies from components
        for component in parser_output['components']:
            detected_technologies.update(component.dependencies)
            security_patterns.update(component.authorization_patterns)
        
        # Extract cloud services from infrastructure
        for infra in parser_output['infrastructure']:
            cloud_services.update(infra.services)
        
        # Extract cloud services from third-party integrations
        for integration in parser_output['third_party_integrations']:
            if integration.type == "Cloud_Service":
                cloud_services.add(integration.name)
        
        return SystemBuildContext(
            repo_name=repo_name,
            repo_path=repo_path,
            detected_technologies=detected_technologies,
            cloud_services=cloud_services,
            security_patterns=security_patterns
        )

    def _build_components(self, parsed_components: List[ParsedComponent], context: SystemBuildContext) -> List[Component]:
        """Build Component instances from parsed components."""
        components = []
        
        for parsed_comp in parsed_components:
            self.component_counter += 1
            
            # Determine trust level based on security annotations and patterns
            trust_level = self._determine_component_trust_level(parsed_comp)
            
            # Build interfaces from endpoints
            interfaces = self._build_component_interfaces(parsed_comp)
            
            component = Component(
                id=f"comp_{self.component_counter:03d}",
                name=parsed_comp.name,
                type=parsed_comp.type,
                description=f"Component detected in {parsed_comp.file_path}",
                trust_level=trust_level,
                interfaces=interfaces,
                technologies=parsed_comp.dependencies,
                security_controls=parsed_comp.security_annotations,
                authentication_required=parsed_comp.authentication_required,
                authorization_mechanisms=parsed_comp.authorization_patterns
            )
            
            components.append(component)
        
        return components

    def _determine_component_trust_level(self, parsed_comp: ParsedComponent) -> TrustLevel:
        """Determine trust level based on component characteristics."""
        # High trust if has strong security controls
        if (parsed_comp.authentication_required and 
            parsed_comp.security_annotations and 
            any(auth in parsed_comp.authorization_patterns for auth in ['RBAC', 'ABAC'])):
            return TrustLevel.HIGH
        
        # Medium trust if has some security controls
        elif parsed_comp.authentication_required or parsed_comp.security_annotations:
            return TrustLevel.MEDIUM
        
        # Low trust if no security controls detected
        else:
            return TrustLevel.LOW

    def _build_component_interfaces(self, parsed_comp: ParsedComponent) -> List[Interface]:
        """Build interfaces from component endpoints."""
        interfaces = []
        
        for endpoint in parsed_comp.endpoints:
            # Determine protocol from endpoint
            protocol = self._determine_protocol_from_endpoint(endpoint)
            
            interface = Interface(
                id=f"int_{len(interfaces) + 1:03d}",
                name=f"interface_{endpoint.replace('/', '_').replace(':', '_')}",
                protocol=protocol,
                port=self._extract_port_from_endpoint(endpoint),
                endpoint=endpoint,
                authentication_required=parsed_comp.authentication_required,
                encryption_in_transit=self._has_encryption_in_transit(endpoint, protocol)
            )
            
            interfaces.append(interface)
        
        return interfaces

    def _determine_protocol_from_endpoint(self, endpoint: str) -> Protocol:
        """Determine protocol from endpoint string."""
        if endpoint.startswith('https://') or '/api/' in endpoint:
            return Protocol.HTTPS
        elif endpoint.startswith('http://'):
            return Protocol.HTTP
        elif endpoint.startswith('grpc://') or 'grpc' in endpoint.lower():
            return Protocol.GRPC
        elif endpoint.startswith('ws://') or endpoint.startswith('wss://'):
            return Protocol.WEBSOCKET
        else:
            return Protocol.HTTP  # Default assumption

    def _extract_port_from_endpoint(self, endpoint: str) -> Optional[int]:
        """Extract port number from endpoint if present."""
        import re
        port_match = re.search(r':(\d+)', endpoint)
        return int(port_match.group(1)) if port_match else None

    def _has_encryption_in_transit(self, endpoint: str, protocol: Protocol) -> bool:
        """Determine if endpoint uses encryption in transit."""
        return (endpoint.startswith('https://') or 
                endpoint.startswith('wss://') or 
                protocol in [Protocol.HTTPS, Protocol.GRPC])

    def _build_data_stores(self, parsed_data_stores: List[ParsedDataStore], context: SystemBuildContext) -> List[DataStore]:
        """Build DataStore instances from parsed data stores."""
        data_stores = []
        
        for parsed_ds in parsed_data_stores:
            self.datastore_counter += 1
            
            # Determine data classification based on patterns
            data_classification = self._determine_data_classification(parsed_ds, context)
            
            data_store = DataStore(
                id=f"ds_{self.datastore_counter:03d}",
                name=parsed_ds.name,
                type=parsed_ds.type,
                description=f"Data store detected in {', '.join(parsed_ds.file_paths)}",
                data_classification=data_classification,
                encryption_at_rest=parsed_ds.encryption_enabled,
                encryption_in_transit=self._determine_transit_encryption(parsed_ds),
                access_controls=self._extract_access_controls(parsed_ds),
                backup_enabled=self._has_backup_configuration(parsed_ds),
                connection_string_pattern=parsed_ds.connection_string_pattern
            )
            
            data_stores.append(data_store)
        
        return data_stores

    def _determine_data_classification(self, parsed_ds: ParsedDataStore, context: SystemBuildContext) -> DataClassification:
        """Determine data classification based on data store characteristics."""
        # Check for sensitive data patterns in file paths and access patterns
        sensitive_indicators = ['user', 'customer', 'personal', 'payment', 'financial', 'health', 'medical']
        
        file_content = ' '.join(parsed_ds.file_paths).lower()
        access_content = ' '.join(parsed_ds.access_patterns).lower()
        
        if any(indicator in file_content or indicator in access_content for indicator in sensitive_indicators):
            return DataClassification.SENSITIVE
        elif parsed_ds.encryption_enabled:
            return DataClassification.INTERNAL
        else:
            return DataClassification.PUBLIC

    def _determine_transit_encryption(self, parsed_ds: ParsedDataStore) -> bool:
        """Determine if data store uses encryption in transit."""
        if parsed_ds.connection_string_pattern:
            return ('ssl=true' in parsed_ds.connection_string_pattern.lower() or 
                   'sslmode=' in parsed_ds.connection_string_pattern.lower() or
                   parsed_ds.connection_string_pattern.startswith('rediss://'))
        return False

    def _extract_access_controls(self, parsed_ds: ParsedDataStore) -> List[str]:
        """Extract access control mechanisms from data store."""
        controls = []
        
        if 'SQL' in parsed_ds.access_patterns:
            controls.append('Database_User_Permissions')
        
        if 'NoSQL' in parsed_ds.access_patterns:
            controls.append('Document_Level_Security')
        
        if parsed_ds.encryption_enabled:
            controls.append('Encryption_Based_Access')
        
        return controls

    def _has_backup_configuration(self, parsed_ds: ParsedDataStore) -> bool:
        """Check if backup configuration is detected."""
        # This is a simplified check - in practice, would need more sophisticated detection
        backup_indicators = ['backup', 'snapshot', 'dump', 'export']
        
        file_content = ' '.join(parsed_ds.file_paths).lower()
        return any(indicator in file_content for indicator in backup_indicators)

    def _build_external_entities(self, third_party_integrations: List[ThirdPartyIntegration], 
                                context: SystemBuildContext) -> List[ExternalEntity]:
        """Build ExternalEntity instances from third-party integrations."""
        external_entities = []
        entity_counter = 0
        
        for integration in third_party_integrations:
            entity_counter += 1
            
            # Determine trust level based on authentication method
            trust_level = self._determine_external_entity_trust_level(integration)
            
            external_entity = ExternalEntity(
                id=f"ext_{entity_counter:03d}",
                name=integration.name,
                type=integration.type,
                description=f"External integration: {integration.name}",
                trust_level=trust_level,
                endpoints=integration.endpoints,
                authentication_method=integration.authentication_method,
                data_shared=integration.data_shared,
                compliance_requirements=self._determine_compliance_requirements(integration)
            )
            
            external_entities.append(external_entity)
        
        return external_entities

    def _determine_external_entity_trust_level(self, integration: ThirdPartyIntegration) -> TrustLevel:
        """Determine trust level for external entity."""
        if integration.authentication_method in ['OAuth', 'IAM', 'Service_Account']:
            return TrustLevel.MEDIUM
        elif integration.authentication_method in ['API_Key', 'Bearer_Token']:
            return TrustLevel.LOW
        else:
            return TrustLevel.UNTRUSTED

    def _determine_compliance_requirements(self, integration: ThirdPartyIntegration) -> List[str]:
        """Determine compliance requirements based on data shared."""
        requirements = []
        
        if 'Financial_Data' in integration.data_shared:
            requirements.extend(['PCI_DSS', 'SOX'])
        
        if 'Health_Data' in integration.data_shared:
            requirements.append('HIPAA')
        
        if 'User_Data' in integration.data_shared:
            requirements.extend(['GDPR', 'CCPA'])
        
        return requirements

    def _build_data_flows(self, components: List[Component], data_stores: List[DataStore], 
                         external_entities: List[ExternalEntity], context: SystemBuildContext) -> List[DataFlow]:
        """Build DataFlow instances based on component relationships."""
        data_flows = []
        
        # Component to data store flows
        for component in components:
            for data_store in data_stores:
                if self._has_data_flow_relationship(component, data_store, context):
                    flow = self._create_component_datastore_flow(component, data_store)
                    data_flows.append(flow)
        
        # Component to external entity flows
        for component in components:
            for external_entity in external_entities:
                if self._has_external_flow_relationship(component, external_entity, context):
                    flow = self._create_component_external_flow(component, external_entity)
                    data_flows.append(flow)
        
        # Inter-component flows
        for i, comp1 in enumerate(components):
            for comp2 in components[i+1:]:
                if self._has_inter_component_flow(comp1, comp2, context):
                    flow = self._create_inter_component_flow(comp1, comp2)
                    data_flows.append(flow)
        
        return data_flows

    def _has_data_flow_relationship(self, component: Component, data_store: DataStore, 
                                   context: SystemBuildContext) -> bool:
        """Check if component has data flow relationship with data store."""
        # Check if component technologies match data store type
        db_tech_mapping = {
            DataStoreType.RELATIONAL_DB: ['psycopg2', 'pymysql', 'sqlite3', 'sqlalchemy'],
            DataStoreType.DOCUMENT_DB: ['pymongo', 'mongoose'],
            DataStoreType.CACHE: ['redis-py', 'ioredis'],
            DataStoreType.SEARCH_ENGINE: ['elasticsearch-py']
        }
        
        relevant_techs = db_tech_mapping.get(data_store.type, [])
        return any(tech in component.technologies for tech in relevant_techs)

    def _create_component_datastore_flow(self, component: Component, data_store: DataStore) -> DataFlow:
        """Create data flow between component and data store."""
        self.dataflow_counter += 1
        
        return DataFlow(
            id=f"df_{self.dataflow_counter:03d}",
            name=f"{component.name}_to_{data_store.name}",
            source_id=component.id,
            destination_id=data_store.id,
            data_classification=data_store.data_classification,
            protocol=self._determine_datastore_protocol(data_store),
            authentication_required=component.authentication_required,
            encryption_in_transit=data_store.encryption_in_transit,
            data_types=['Database_Operations']
        )

    def _determine_datastore_protocol(self, data_store: DataStore) -> Protocol:
        """Determine protocol used for data store communication."""
        if data_store.type == DataStoreType.RELATIONAL_DB:
            return Protocol.TCP
        elif data_store.type == DataStoreType.DOCUMENT_DB:
            return Protocol.TCP
        elif data_store.type == DataStoreType.CACHE:
            return Protocol.TCP
        elif data_store.type == DataStoreType.SEARCH_ENGINE:
            return Protocol.HTTPS
        else:
            return Protocol.TCP

    def _has_external_flow_relationship(self, component: Component, external_entity: ExternalEntity, 
                                       context: SystemBuildContext) -> bool:
        """Check if component has flow relationship with external entity."""
        # Check if component makes HTTP calls (likely to external services)
        http_techs = ['requests', 'axios', 'fetch', 'http']
        return any(tech in component.technologies for tech in http_techs)

    def _create_component_external_flow(self, component: Component, external_entity: ExternalEntity) -> DataFlow:
        """Create data flow between component and external entity."""
        self.dataflow_counter += 1
        
        # Determine data classification based on external entity data shared
        data_classification = DataClassification.INTERNAL
        if any(sensitive in external_entity.data_shared 
               for sensitive in ['User_Data', 'Financial_Data', 'Health_Data']):
            data_classification = DataClassification.SENSITIVE
        
        return DataFlow(
            id=f"df_{self.dataflow_counter:03d}",
            name=f"{component.name}_to_{external_entity.name}",
            source_id=component.id,
            destination_id=external_entity.id,
            data_classification=data_classification,
            protocol=Protocol.HTTPS,
            authentication_required=external_entity.authentication_method is not None,
            encryption_in_transit=True,  # Assume HTTPS for external calls
            data_types=external_entity.data_shared
        )

    def _has_inter_component_flow(self, comp1: Component, comp2: Component, 
                                 context: SystemBuildContext) -> bool:
        """Check if two components have inter-component flow."""
        # Check if one is a web service and another is a microservice/background service
        web_service_types = [ComponentType.WEB_SERVICE, ComponentType.API_GATEWAY]
        service_types = [ComponentType.MICROSERVICE, ComponentType.BACKGROUND_SERVICE]
        
        return ((comp1.type in web_service_types and comp2.type in service_types) or
                (comp2.type in web_service_types and comp1.type in service_types))

    def _create_inter_component_flow(self, comp1: Component, comp2: Component) -> DataFlow:
        """Create data flow between two components."""
        self.dataflow_counter += 1
        
        return DataFlow(
            id=f"df_{self.dataflow_counter:03d}",
            name=f"{comp1.name}_to_{comp2.name}",
            source_id=comp1.id,
            destination_id=comp2.id,
            data_classification=DataClassification.INTERNAL,
            protocol=Protocol.HTTP,
            authentication_required=comp2.authentication_required,
            encryption_in_transit=True,
            data_types=['Service_Communication']
        )

    def _build_trust_boundaries(self, components: List[Component], data_stores: List[DataStore], 
                               context: SystemBuildContext) -> List[TrustBoundary]:
        """Build trust boundaries based on component and data store trust levels."""
        trust_boundaries = []
        
        # Group components by trust level
        trust_groups = {}
        for component in components:
            if component.trust_level not in trust_groups:
                trust_groups[component.trust_level] = []
            trust_groups[component.trust_level].append(component.id)
        
        # Create trust boundaries for each trust level group
        for trust_level, component_ids in trust_groups.items():
            if len(component_ids) > 1:  # Only create boundary if multiple components
                self.trust_boundary_counter += 1
                
                boundary = TrustBoundary(
                    id=f"tb_{self.trust_boundary_counter:03d}",
                    name=f"{trust_level.value}_trust_boundary",
                    trust_level=trust_level,
                    component_ids=component_ids,
                    description=f"Trust boundary for {trust_level.value} trust level components",
                    security_controls=self._determine_boundary_security_controls(trust_level, context)
                )
                
                trust_boundaries.append(boundary)
        
        # Create network-based trust boundaries
        network_boundary = self._create_network_trust_boundary(components, data_stores, context)
        if network_boundary:
            trust_boundaries.append(network_boundary)
        
        return trust_boundaries

    def _determine_boundary_security_controls(self, trust_level: TrustLevel, 
                                            context: SystemBuildContext) -> List[str]:
        """Determine security controls for trust boundary."""
        controls = []
        
        if trust_level == TrustLevel.HIGH:
            controls.extend(['Network_Segmentation', 'Access_Control_Lists', 'Monitoring'])
        elif trust_level == TrustLevel.MEDIUM:
            controls.extend(['Firewall_Rules', 'Authentication'])
        else:
            controls.append('Basic_Network_Controls')
        
        # Add cloud-specific controls if cloud services detected
        if context.cloud_services:
            controls.extend(['Security_Groups', 'VPC_Controls'])
        
        return controls

    def _create_network_trust_boundary(self, components: List[Component], data_stores: List[DataStore], 
                                      context: SystemBuildContext) -> Optional[TrustBoundary]:
        """Create network-based trust boundary."""
        # Create boundary between internal components and external-facing components
        internal_components = []
        external_components = []
        
        for component in components:
            if component.type in [ComponentType.WEB_SERVICE, ComponentType.API_GATEWAY]:
                external_components.append(component.id)
            else:
                internal_components.append(component.id)
        
        if internal_components and external_components:
            self.trust_boundary_counter += 1
            
            return TrustBoundary(
                id=f"tb_{self.trust_boundary_counter:03d}",
                name="network_perimeter_boundary",
                trust_level=TrustLevel.MEDIUM,
                component_ids=internal_components,
                description="Network perimeter trust boundary separating internal and external-facing components",
                security_controls=['Firewall', 'Load_Balancer', 'WAF', 'DDoS_Protection']
            )
        
        return None

    def _build_cloud_context(self, infrastructure: List[ParsedInfrastructure], 
                            context: SystemBuildContext) -> CloudContext:
        """Build cloud context from infrastructure configurations."""
        # Determine cloud provider
        cloud_provider = self._determine_cloud_provider(infrastructure, context)
        
        # Extract services used
        services_used = set()
        for infra in infrastructure:
            services_used.update(infra.services)
        
        # Determine deployment model
        deployment_model = self._determine_deployment_model(infrastructure, context)
        
        # Determine compliance requirements
        compliance_requirements = self._determine_system_compliance_requirements(context)
        
        # Determine data residency
        data_residency = self._determine_data_residency(infrastructure, context)
        
        return CloudContext(
            provider=cloud_provider,
            services_used=list(services_used),
            deployment_model=deployment_model,
            compliance_requirements=compliance_requirements,
            data_residency=data_residency,
            security_configurations=self._extract_security_configurations(infrastructure),
            network_configurations=self._extract_network_configurations(infrastructure)
        )

    def _determine_cloud_provider(self, infrastructure: List[ParsedInfrastructure], 
                                 context: SystemBuildContext) -> CloudProvider:
        """Determine primary cloud provider."""
        aws_indicators = ['aws', 'ec2', 's3', 'rds', 'lambda', 'cloudformation']
        azure_indicators = ['azure', 'microsoft', 'arm', 'bicep']
        gcp_indicators = ['gcp', 'google', 'gcloud', 'firebase']
        
        all_services = ' '.join(context.cloud_services).lower()
        
        if any(indicator in all_services for indicator in aws_indicators):
            return CloudProvider.AWS
        elif any(indicator in all_services for indicator in azure_indicators):
            return CloudProvider.AZURE
        elif any(indicator in all_services for indicator in gcp_indicators):
            return CloudProvider.GCP
        else:
            # Check if containerized (likely cloud-native)
            if any(infra.type == InfrastructureType.DOCKER for infra in infrastructure):
                return CloudProvider.MULTI_CLOUD
            else:
                return CloudProvider.ON_PREMISE

    def _determine_deployment_model(self, infrastructure: List[ParsedInfrastructure], 
                                   context: SystemBuildContext) -> DeploymentModel:
        """Determine deployment model."""
        has_containers = any(infra.type == InfrastructureType.DOCKER for infra in infrastructure)
        has_k8s = any(infra.type == InfrastructureType.KUBERNETES for infra in infrastructure)
        has_cloud_services = bool(context.cloud_services)
        
        if has_k8s or (has_containers and has_cloud_services):
            return DeploymentModel.PAAS
        elif has_containers:
            return DeploymentModel.IAAS
        elif has_cloud_services:
            return DeploymentModel.SAAS
        else:
            return DeploymentModel.HYBRID

    def _determine_system_compliance_requirements(self, context: SystemBuildContext) -> List[str]:
        """Determine system-wide compliance requirements."""
        requirements = set()
        
        # Check for financial/payment indicators
        financial_indicators = ['payment', 'financial', 'credit', 'bank']
        if any(indicator in ' '.join(context.detected_technologies).lower() 
               for indicator in financial_indicators):
            requirements.update(['PCI_DSS', 'SOX'])
        
        # Check for health indicators
        health_indicators = ['health', 'medical', 'hipaa', 'patient']
        if any(indicator in ' '.join(context.detected_technologies).lower() 
               for indicator in health_indicators):
            requirements.add('HIPAA')
        
        # Default privacy requirements for user data
        user_indicators = ['user', 'customer', 'personal', 'profile']
        if any(indicator in ' '.join(context.detected_technologies).lower() 
               for indicator in user_indicators):
            requirements.update(['GDPR', 'CCPA'])
        
        return list(requirements)

    def _determine_data_residency(self, infrastructure: List[ParsedInfrastructure], 
                                 context: SystemBuildContext) -> str:
        """Determine data residency requirements."""
        # This is simplified - in practice would need more sophisticated detection
        if context.cloud_services:
            return "Cloud_Provider_Regions"
        else:
            return "On_Premise"

    def _extract_security_configurations(self, infrastructure: List[ParsedInfrastructure]) -> Dict[str, any]:
        """Extract security configurations from infrastructure."""
        security_configs = {}
        
        for infra in infrastructure:
            security_configs.update(infra.security_configurations)
        
        return security_configs

    def _extract_network_configurations(self, infrastructure: List[ParsedInfrastructure]) -> Dict[str, any]:
        """Extract network configurations from infrastructure."""
        network_configs = {}
        
        for infra in infrastructure:
            network_configs.update(infra.network_configurations)
        
        return network_configs