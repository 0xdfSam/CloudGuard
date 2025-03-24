"""Base class for Azure service scanners."""

import abc
import logging
from typing import Dict, List, Optional, Any, Set

from azure.core.credentials import TokenCredential
from azure.mgmt.resource import ResourceManagementClient

from cloudguard.core.findings import Finding
from cloudguard.utils.logger import get_logger

logger = get_logger(__name__)


class AzureServiceScanner(abc.ABC):
    """Base class for Azure service scanners."""
    
    service_name = "azure_service"  # Override in subclasses
    
    def __init__(self, credential: TokenCredential, subscription_id: str):
        """Initialize service scanner.
        
        Args:
            credential: Azure credential for authentication
            subscription_id: Azure subscription ID
        """
        self.credential = credential
        self.subscription_id = subscription_id
        self.resource_client = ResourceManagementClient(credential, subscription_id)
        
    @abc.abstractmethod
    async def scan(self) -> List[Finding]:
        """Scan the Azure service for security findings.
        
        Returns:
            List of findings
        """
        pass
    
    @abc.abstractmethod
    async def get_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get resources for this service.
        
        Returns:
            Dictionary mapping resource types to lists of resources
        """
        pass
    
    def get_service_tags(self) -> Set[str]:
        """Get tags specific to this service for mapping findings to frameworks.
        
        Override in subclasses to provide service-specific tags.
        
        Returns:
            Set of service-specific tags
        """
        return set()
    
    def is_global_service(self) -> bool:
        """Determine if this is a global service.
        
        Override in subclasses for global services.
        
        Returns:
            True if this is a global service, False otherwise
        """
        return False
    
    async def get_resource_groups(self) -> List[str]:
        """Get list of resource groups in the subscription.
        
        Returns:
            List of resource group names
        """
        try:
            resource_groups = []
            for group in self.resource_client.resource_groups.list():
                resource_groups.append(group.name)
            return resource_groups
        except Exception as e:
            logger.error(f"Error retrieving resource groups for subscription {self.subscription_id}: {str(e)}")
            return []
    
    def get_resource_id(self, resource_type: str, resource_name: str, resource_group: Optional[str] = None) -> str:
        """Generate Azure resource ID.
        
        Args:
            resource_type: Azure resource type
            resource_name: Resource name
            resource_group: Resource group name (if applicable)
            
        Returns:
            Full Azure resource ID
        """
        if resource_group:
            return f"/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/{resource_type}/{resource_name}"
        return f"/subscriptions/{self.subscription_id}/providers/{resource_type}/{resource_name}"
    
    async def list_resources_by_type(self, resource_type: str) -> List[Dict[str, Any]]:
        """List resources of a specific type in the subscription.
        
        Args:
            resource_type: Azure resource type
            
        Returns:
            List of resources
        """
        try:
            resources = []
            filter_str = f"resourceType eq '{resource_type}'"
            
            for resource in self.resource_client.resources.list(filter=filter_str):
                resources.append({
                    "id": resource.id,
                    "name": resource.name,
                    "type": resource.type,
                    "location": resource.location,
                    "tags": resource.tags or {},
                    "properties": {}  # Properties require specific client calls
                })
            
            return resources
        except Exception as e:
            logger.error(f"Error listing resources of type {resource_type} in subscription {self.subscription_id}: {str(e)}")
            return []
    
    async def get_resource_tags(self, resource_id: str) -> Dict[str, str]:
        """Get tags for a specific resource.
        
        Args:
            resource_id: Azure resource ID
            
        Returns:
            Dictionary of resource tags
        """
        try:
            resource = self.resource_client.resources.get_by_id(resource_id, api_version="2021-04-01")
            return resource.tags or {}
        except Exception as e:
            logger.error(f"Error retrieving tags for resource {resource_id}: {str(e)}")
            return {} 