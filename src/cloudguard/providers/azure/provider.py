"""Azure provider scanner implementation."""

import asyncio
import logging
from typing import Dict, List, Optional, Set, Type

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from azure.core.exceptions import ClientAuthenticationError

from ...core.findings import Finding
from ...utils.config import AzureConfig
from ..base import BaseProvider
from .storage import StorageScanner

logger = logging.getLogger(__name__)


class AzureProvider(BaseProvider):
    """Azure cloud provider scanner."""

    name = "azure"

    def __init__(self, config: AzureConfig):
        """Initialize the Azure provider scanner.

        Args:
            config: Azure-specific configuration
        """
        super().__init__(config)
        self.azure_config = config
        self.credential = None
        self.subscription_ids = []
        self._supported_services = {
            "storage", "keyvault", "network", "compute", "database", "webapp", "container"
        }
        self.scanners = {}

    async def authenticate(self) -> bool:
        """Authenticate with Azure.

        Returns:
            True if authentication succeeded, False otherwise
        """
        try:
            logger.debug("Authenticating to Azure")
            
            # Determine authentication method
            if self.azure_config.client_id and self.azure_config.client_secret and self.azure_config.tenant_id:
                # Service principal authentication
                logger.debug("Using service principal authentication")
                self.credential = ClientSecretCredential(
                    tenant_id=self.azure_config.tenant_id,
                    client_id=self.azure_config.client_id,
                    client_secret=self.azure_config.client_secret
                )
            elif self.azure_config.use_managed_identity:
                # Managed identity authentication
                logger.debug("Using managed identity authentication")
                self.credential = DefaultAzureCredential(managed_identity_client_id=self.azure_config.client_id)
            else:
                # Default authentication (environment, managed identity, or local development)
                logger.debug("Using default authentication chain")
                self.credential = DefaultAzureCredential()
            
            # Test the credentials by listing subscriptions
            subscription_client = SubscriptionClient(self.credential)
            subscriptions = list(subscription_client.subscriptions.list())
            
            if not subscriptions:
                logger.error("No subscriptions found with provided credentials")
                return False
                
            # Use specified subscriptions or all available
            if self.azure_config.subscription_ids:
                self.subscription_ids = self.azure_config.subscription_ids
                logger.info(f"Using {len(self.subscription_ids)} specified subscriptions")
            else:
                self.subscription_ids = [sub.subscription_id for sub in subscriptions]
                logger.info(f"Found {len(self.subscription_ids)} subscriptions")
            
            # Validate access to each subscription
            for subscription_id in self.subscription_ids:
                try:
                    resource_client = ResourceManagementClient(self.credential, subscription_id)
                    # Just list one resource group to test access
                    list(resource_client.resource_groups.list(top=1))
                    logger.debug(f"Successfully accessed subscription {subscription_id}")
                except Exception as e:
                    logger.warning(f"Cannot access subscription {subscription_id}: {str(e)}")
                    self.subscription_ids.remove(subscription_id)
            
            if not self.subscription_ids:
                logger.error("No accessible subscriptions found")
                return False
                
            logger.info(f"Successfully authenticated to Azure with access to {len(self.subscription_ids)} subscriptions")
            return True
            
        except ClientAuthenticationError as e:
            logger.error(f"Azure authentication error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Azure authentication: {str(e)}")
            return False

    async def scan(self) -> List[Finding]:
        """Run security scans for Azure services.

        Returns:
            List of security findings
        """
        if not self.credential:
            success = await self.authenticate()
            if not success:
                logger.error("Azure authentication failed, cannot perform scan")
                return []

        # Initialize scanners for enabled services
        self._init_scanners()
        
        # Run all scanners concurrently
        tasks = []
        for service, scanner_class in self.scanners.items():
            if service in self.azure_config.services:
                logger.info(f"Starting Azure {service} scan")
                for subscription_id in self.subscription_ids:
                    scanner = scanner_class(self.credential, subscription_id)
                    tasks.append(scanner.scan())
        
        # Gather results
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        findings = []
        result_idx = 0
        for service in self.scanners:
            if service in self.azure_config.services:
                for _ in self.subscription_ids:
                    result = scan_results[result_idx]
                    result_idx += 1
                    
                    if isinstance(result, Exception):
                        logger.error(f"Error scanning Azure {service}: {str(result)}")
                    else:
                        logger.info(f"Completed Azure {service} scan, found {len(result)} issues")
                        findings.extend(result)
        
        return findings

    async def get_resources(self) -> Dict[str, List[Dict]]:
        """Get a list of resources from Azure.

        Returns:
            Dictionary mapping resource types to lists of resources
        """
        if not self.credential:
            success = await self.authenticate()
            if not success:
                logger.error("Azure authentication failed, cannot get resources")
                return {}

        # Initialize scanners if not already done
        self._init_scanners()
        
        # Get resources from all scanners
        resources = {}
        for service, scanner_class in self.scanners.items():
            if service in self.azure_config.services:
                for subscription_id in self.subscription_ids:
                    scanner = scanner_class(self.credential, subscription_id)
                    service_resources = await scanner.get_resources()
                    
                    # Merge resources by type
                    for resource_type, resource_list in service_resources.items():
                        if resource_type not in resources:
                            resources[resource_type] = []
                        resources[resource_type].extend(resource_list)
        
        return resources

    @property
    def supported_services(self) -> Set[str]:
        """Get the set of services supported by this provider.

        Returns:
            Set of service names
        """
        return self._supported_services

    def _init_scanners(self) -> None:
        """Initialize service-specific scanners."""
        
        # Only initialize scanners that haven't been initialized yet
        if not self.scanners:
            enabled_services = set(self.azure_config.services).intersection(self._supported_services)
            
            # Initialize scanners for enabled services
            for service in enabled_services:
                if service == "storage":
                    self.scanners["storage"] = StorageScanner
                # Add other service scanners as they're implemented
                # elif service == "keyvault":
                #     self.scanners["keyvault"] = KeyVaultScanner
                # etc.
            
            logger.debug(f"Initialized Azure scanners for services: {', '.join(self.scanners.keys())}") 