"""Azure scanner module.

This module provides functionality for scanning Azure resources for security issues.
"""

import asyncio
import logging
import concurrent.futures
from typing import Dict, List, Set, Any, Optional

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.core.exceptions import ClientAuthenticationError

from cloudguard.core.findings import Finding
from cloudguard.utils.logger import get_logger
from .registry import AzureServiceRegistry

logger = get_logger(__name__)


class AzureScanner:
    """Azure scanner for security checks.
    
    This class is responsible for scanning Azure resources for security issues.
    It leverages service-specific scanners to perform scans and aggregates the findings.
    """
    
    def __init__(
        self,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        subscriptions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
        use_mock: bool = False
    ):
        """Initialize the Azure scanner.
        
        Args:
            tenant_id: Azure tenant ID for authentication (optional)
            client_id: Azure client ID for authentication (optional)
            client_secret: Azure client secret for authentication (optional)
            subscriptions: List of subscription IDs to scan (optional)
            services: List of services to scan (optional)
            use_mock: Whether to use mock data for testing
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscriptions = subscriptions
        self.services = services
        self.registry = AzureServiceRegistry()
        
        # To be initialized in authenticate()
        self.credential = None
        self.subscription_client = None
        self._subscriptions_to_scan = None
        self._services_to_scan = None
        self.use_mock = use_mock
        
        logger.debug("Initialized Azure scanner")
    
    def authenticate(self) -> bool:
        """Authenticate with Azure.
        
        Returns:
            True if authentication is successful, False otherwise
        """
        if self.use_mock:
            logger.info("Using mock mode, authentication bypassed")
            return True
            
        try:
            logger.info("Authenticating with Azure")
            
            # Create credentials
            if self.client_id and self.client_secret and self.tenant_id:
                logger.debug("Using service principal authentication")
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
            else:
                logger.debug("Using default authentication")
                self.credential = DefaultAzureCredential()
            
            # Test credentials by creating a subscription client
            self.subscription_client = SubscriptionClient(self.credential)
            
            # List subscriptions to verify credentials work
            list(self.subscription_client.subscriptions.list())[0:1]
            
            # Determine subscriptions to scan
            self._subscriptions_to_scan = self._get_subscriptions_to_scan()
            
            # Determine services to scan
            self._services_to_scan = self._get_services_to_scan()
            
            if not self._subscriptions_to_scan:
                logger.error("No subscriptions to scan")
                return False
            
            if not self._services_to_scan:
                logger.error("No services to scan")
                return False
            
            logger.info(f"Successfully authenticated with Azure. Will scan {len(self._subscriptions_to_scan)} subscriptions and {len(self._services_to_scan)} services")
            return True
            
        except ClientAuthenticationError as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error authenticating with Azure: {str(e)}")
            return False
    
    def _get_subscriptions_to_scan(self) -> List[str]:
        """Get the list of subscriptions to scan.
        
        Returns:
            List of subscription IDs to scan
        """
        if self.use_mock:
            return ["00000000-0000-0000-0000-000000000000"]
        
        if self.subscriptions:
            # Use provided subscription IDs
            logger.info(f"Using {len(self.subscriptions)} provided subscription IDs")
            return self.subscriptions
        
        try:
            # List all accessible subscriptions
            subscriptions = list(self.subscription_client.subscriptions.list())
            subscription_ids = [sub.subscription_id for sub in subscriptions]
            
            logger.info(f"Found {len(subscription_ids)} accessible subscriptions")
            return subscription_ids
            
        except Exception as e:
            logger.error(f"Error retrieving subscriptions: {str(e)}")
            return []
    
    def _get_services_to_scan(self) -> List[str]:
        """Get the list of services to scan.
        
        Returns:
            List of service names to scan
        """
        # Get all registered services
        registered_services = self.registry.get_registered_services()
        
        if not self.services:
            # Use all registered services
            logger.info(f"Using all {len(registered_services)} registered services for scanning")
            return registered_services
        
        # Validate requested services against registered ones
        valid_services = []
        for service in self.services:
            if service in registered_services:
                valid_services.append(service)
            else:
                logger.warning(f"Service '{service}' is not registered and will be skipped")
        
        logger.info(f"Using {len(valid_services)} valid services for scanning")
        return valid_services
    
    async def scan(self) -> List[Finding]:
        """Scan Azure resources for security issues.
        
        Returns:
            List of findings
        """
        if self.use_mock:
            logger.info("Using mock mode, returning mock findings")
            # Create a mock finding for testing
            from cloudguard.core.findings import Finding, Severity, Resource
            mock_findings = [
                Finding(
                    title="Mock Azure Storage Finding",
                    description="This is a mock finding for testing purposes",
                    provider="azure",
                    service="storage",
                    severity=Severity.HIGH.value,
                    resources=[
                        Resource(
                            id="/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage",
                            name="teststorage",
                            type="storage_account",
                            region="eastus"
                        )
                    ]
                ),
                Finding(
                    title="Mock Azure Key Vault Finding",
                    description="This is a mock finding for testing purposes",
                    provider="azure",
                    service="keyvault",
                    severity=Severity.MEDIUM.value,
                    resources=[
                        Resource(
                            id="/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/testvault",
                            name="testvault",
                            type="key_vault",
                            region="eastus"
                        )
                    ]
                )
            ]
            return mock_findings
        
        logger.info("Starting Azure security scan")
        
        if not self.credential:
            if not self.authenticate():
                logger.error("Authentication failed, aborting scan")
                return []
        
        all_findings = []
        
        # Create tasks for parallel execution
        tasks = []
        
        for subscription_id in self._subscriptions_to_scan:
            for service_name in self._services_to_scan:
                # Create task for each (subscription, service) pair
                tasks.append(self._scan_service_in_subscription(subscription_id, service_name))
        
        # Execute all tasks in parallel
        if tasks:
            # Use asyncio.gather to run tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Error in scan task: {str(result)}")
        
        logger.info(f"Completed Azure security scan, found {len(all_findings)} issues")
        return all_findings
    
    async def _scan_service_in_subscription(self, subscription_id: str, service_name: str) -> List[Finding]:
        """Scan a specific service in a specific subscription.
        
        Args:
            subscription_id: Subscription ID to scan
            service_name: Service name to scan
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            logger.info(f"Scanning service '{service_name}' in subscription '{subscription_id}'")
            
            # Get scanner instance for the service
            scanner = self.registry.get_scanner(service_name, self.credential, subscription_id)
            
            # Run the scan
            service_findings = await scanner.scan()
            
            # Add findings to the list
            if service_findings:
                findings.extend(service_findings)
                logger.info(f"Found {len(service_findings)} issues in service '{service_name}' in subscription '{subscription_id}'")
            else:
                logger.info(f"No issues found in service '{service_name}' in subscription '{subscription_id}'")
            
        except Exception as e:
            logger.error(f"Error scanning service '{service_name}' in subscription '{subscription_id}': {str(e)}")
        
        return findings
    
    async def get_resources(self) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """Get Azure resources.
        
        Returns:
            Dictionary mapping subscription IDs to dictionaries mapping service names to lists of resources
        """
        if self.use_mock:
            return {
                "00000000-0000-0000-0000-000000000000": [
                    {
                        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage",
                        "name": "teststorage",
                        "type": "Microsoft.Storage/storageAccounts",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "encryption": {
                                "services": {
                                    "blob": {"enabled": True},
                                    "file": {"enabled": True},
                                    "table": {"enabled": True},
                                    "queue": {"enabled": True}
                                },
                                "keySource": "Microsoft.Storage"
                            },
                            "networkAcls": {
                                "bypass": "AzureServices",
                                "defaultAction": "Allow"
                            }
                        }
                    },
                    {
                        "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.KeyVault/vaults/testvault",
                        "name": "testvault",
                        "type": "Microsoft.KeyVault/vaults",
                        "location": "eastus",
                        "properties": {
                            "provisioningState": "Succeeded",
                            "enableSoftDelete": False,
                            "enablePurgeProtection": False,
                            "networkAcls": {
                                "bypass": "AzureServices",
                                "defaultAction": "Allow"
                            }
                        }
                    }
                ]
            }
        
        logger.info("Retrieving Azure resources")
        
        if not self.credential:
            if not self.authenticate():
                logger.error("Authentication failed, aborting resource retrieval")
                return {}
        
        all_resources = {}
        
        # Create tasks for parallel execution
        tasks = []
        
        for subscription_id in self._subscriptions_to_scan:
            all_resources[subscription_id] = {}
            for service_name in self._services_to_scan:
                # Create task for each (subscription, service) pair
                tasks.append(self._get_service_resources_in_subscription(subscription_id, service_name))
        
        # Execute all tasks in parallel
        if tasks:
            # Use asyncio.gather to run tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            task_index = 0
            for subscription_id in self._subscriptions_to_scan:
                for service_name in self._services_to_scan:
                    result = results[task_index]
                    if isinstance(result, tuple) and len(result) == 3:
                        sub_id, svc_name, resources = result
                        all_resources[sub_id][svc_name] = resources
                    elif isinstance(result, Exception):
                        logger.error(f"Error retrieving resources: {str(result)}")
                    
                    task_index += 1
        
        logger.info(f"Completed Azure resource retrieval")
        return all_resources
    
    async def _get_service_resources_in_subscription(self, subscription_id: str, service_name: str) -> tuple:
        """Get resources for a specific service in a specific subscription.
        
        Args:
            subscription_id: Subscription ID to scan
            service_name: Service name to scan
            
        Returns:
            Tuple containing (subscription_id, service_name, resources)
        """
        resources = {}
        
        try:
            logger.info(f"Retrieving resources for service '{service_name}' in subscription '{subscription_id}'")
            
            # Get scanner instance for the service
            scanner = self.registry.get_scanner(service_name, self.credential, subscription_id)
            
            # Get resources
            service_resources = await scanner.get_resources()
            
            # Add resources to the list
            if service_resources:
                resources = service_resources
                logger.info(f"Retrieved resources for service '{service_name}' in subscription '{subscription_id}'")
            else:
                logger.info(f"No resources found for service '{service_name}' in subscription '{subscription_id}'")
            
        except Exception as e:
            logger.error(f"Error retrieving resources for service '{service_name}' in subscription '{subscription_id}': {str(e)}")
        
        return (subscription_id, service_name, resources)
    
    def get_service_tags(self) -> Dict[str, Set[str]]:
        """Get all service tags.
        
        Returns:
            Dictionary mapping service names to sets of tags
        """
        return self.registry.get_service_tags() 