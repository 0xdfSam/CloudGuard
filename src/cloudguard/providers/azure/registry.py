"""Azure service registry module.

This module provides a registry for Azure service scanners.
"""

import logging
from typing import Dict, List, Optional, Set, Type, Any

from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

from cloudguard.utils.logger import get_logger
from .services.base import AzureServiceScanner
from .services.storage import StorageScanner
from .services.keyvault import KeyVaultScanner

logger = get_logger(__name__)


class AzureServiceRegistry:
    """Registry for Azure service scanners.
    
    This class manages the registration and retrieval of Azure service scanners.
    """
    
    def __init__(self):
        """Initialize the Azure service registry."""
        # Map of service names to scanner classes
        self.scanners: Dict[str, Type[AzureServiceScanner]] = {}
        self._register_scanners()
    
    def _register_scanners(self):
        """Register all available service scanners."""
        # Register all available service scanners
        self._register_scanner(StorageScanner)
        self._register_scanner(KeyVaultScanner)
        
        # Add other scanners as they are implemented
        
        logger.info(f"Registered {len(self.scanners)} Azure service scanners")
    
    def _register_scanner(self, scanner_class: Type[AzureServiceScanner]):
        """Register a service scanner.
        
        Args:
            scanner_class: The scanner class to register
        """
        service_name = scanner_class.service_name
        self.scanners[service_name] = scanner_class
        logger.debug(f"Registered Azure service scanner: {service_name}")
    
    def get_scanner(self, service_name: str, credential, subscription_id: str) -> AzureServiceScanner:
        """Get a scanner instance for the specified service.
        
        Args:
            service_name: The name of the service to scan
            credential: Azure credential
            subscription_id: Azure subscription ID
            
        Returns:
            Scanner instance for the specified service
            
        Raises:
            ValueError: If the service is not registered
        """
        scanner_class = self.scanners.get(service_name)
        if not scanner_class:
            raise ValueError(f"No scanner registered for service: {service_name}")
        
        return scanner_class(credential, subscription_id)
    
    def get_registered_services(self) -> List[str]:
        """Get a list of registered service names.
        
        Returns:
            List of registered service names
        """
        return list(self.scanners.keys())
    
    def get_service_tags(self) -> Dict[str, Set[str]]:
        """Get tags for all registered services.
        
        This method creates a dummy credential to instantiate scanners but
        does not make any actual API calls.
        
        Returns:
            Dictionary mapping service names to sets of tags
        """
        service_tags = {}
        
        try:
            # Create a dummy credential and subscription ID
            # This won't make any API calls, just for getting scanner instances
            dummy_credential = None
            dummy_subscription_id = "00000000-0000-0000-0000-000000000000"
            
            for service_name, scanner_class in self.scanners.items():
                try:
                    # Instantiate the scanner class to get its tags
                    # This doesn't make API calls, just returns the tags
                    scanner = scanner_class(dummy_credential, dummy_subscription_id)
                    service_tags[service_name] = scanner.get_service_tags()
                    
                except Exception as e:
                    logger.error(f"Error getting tags for service {service_name}: {str(e)}")
                    service_tags[service_name] = set()
            
        except Exception as e:
            logger.error(f"Error getting service tags: {str(e)}")
        
        return service_tags 