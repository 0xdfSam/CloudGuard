"""Azure Storage service scanner."""

import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.storage.models import StorageAccount
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError

from cloudguard.core.findings import Finding, Severity, Remediation, RemediationStep, Resource, FrameworkMapping
from cloudguard.frameworks.mapping import get_framework_mappings_from_tags
from .base import AzureServiceScanner
from cloudguard.utils.logger import get_logger

logger = get_logger(__name__)


class StorageScanner(AzureServiceScanner):
    """Azure Storage service scanner."""
    
    service_name = "storage"
    
    def __init__(self, credential, subscription_id):
        """Initialize the storage scanner.
        
        Args:
            credential: Azure credential
            subscription_id: Azure subscription ID
        """
        super().__init__(credential, subscription_id)
        self.storage_client = StorageManagementClient(credential, subscription_id)
    
    async def scan(self) -> List[Finding]:
        """Scan Azure Storage accounts for security issues.
        
        Returns:
            List of findings
        """
        logger.info(f"Scanning Azure Storage accounts in subscription {self.subscription_id}")
        findings = []
        
        try:
            # Get storage accounts
            storage_accounts = list(self.storage_client.storage_accounts.list())
            
            if not storage_accounts:
                logger.info(f"No storage accounts found in subscription {self.subscription_id}")
                return findings
            
            logger.info(f"Found {len(storage_accounts)} storage accounts in subscription {self.subscription_id}")
            
            # Check each storage account
            for account in storage_accounts:
                logger.debug(f"Checking storage account: {account.name}")
                
                # Check for public access
                public_findings = await self._check_public_access(account)
                findings.extend(public_findings)
                
                # Check for encryption
                encryption_findings = await self._check_encryption(account)
                findings.extend(encryption_findings)
                
                # Check for secure transfer
                secure_transfer_findings = await self._check_secure_transfer(account)
                findings.extend(secure_transfer_findings)
                
                # Check for network access
                network_findings = await self._check_network_access(account)
                findings.extend(network_findings)
                
                # Check for logging
                logging_findings = await self._check_logging(account)
                findings.extend(logging_findings)
            
            logger.info(f"Completed Azure Storage scan in subscription {self.subscription_id}, found {len(findings)} issues")
            
        except Exception as e:
            logger.error(f"Error scanning Azure Storage accounts: {str(e)}")
        
        return findings
    
    async def get_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get Azure Storage resources.
        
        Returns:
            Dictionary mapping resource types to lists of resources
        """
        resources = {
            "storage_accounts": []
        }
        
        try:
            # Get storage accounts
            storage_accounts = list(self.storage_client.storage_accounts.list())
            
            for account in storage_accounts:
                # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
                resource_group = account.id.split('/')[4]
                
                # Get blob service properties
                try:
                    blob_props = self.storage_client.blob_services.get_service_properties(
                        resource_group_name=resource_group,
                        account_name=account.name
                    )
                except Exception as e:
                    logger.debug(f"Could not retrieve blob properties for {account.name}: {str(e)}")
                    blob_props = None
                
                # Convert to dictionary
                account_dict = {
                    "id": account.id,
                    "name": account.name,
                    "resource_group": resource_group,
                    "location": account.location,
                    "tags": account.tags or {},
                    "properties": {
                        "sku": account.sku.name if account.sku else None,
                        "kind": account.kind,
                        "creation_time": account.creation_time.isoformat() if account.creation_time else None,
                        "primary_location": account.primary_location,
                        "status": account.provisioning_state,
                        "public_network_access": account.public_network_access,
                        "allow_blob_public_access": account.allow_blob_public_access,
                        "require_infrastructure_encryption": account.encryption.require_infrastructure_encryption if account.encryption else None,
                        "https_only": account.enable_https_traffic_only,
                        "network_acls": {
                            "default_action": account.network_rule_set.default_action if account.network_rule_set else None,
                            "ip_rules": [ip.ip_address_or_range for ip in account.network_rule_set.ip_rules] if account.network_rule_set and account.network_rule_set.ip_rules else [],
                            "virtual_network_rules": [vnet.virtual_network_resource_id for vnet in account.network_rule_set.virtual_network_rules] if account.network_rule_set and account.network_rule_set.virtual_network_rules else []
                        },
                        "logging_enabled": blob_props and blob_props.logging and blob_props.logging.delete and blob_props.logging.read and blob_props.logging.write
                    }
                }
                
                resources["storage_accounts"].append(account_dict)
                
            logger.info(f"Retrieved {len(resources['storage_accounts'])} storage accounts from subscription {self.subscription_id}")
            
        except Exception as e:
            logger.error(f"Error retrieving Azure Storage resources: {str(e)}")
        
        return resources
    
    def get_service_tags(self) -> Set[str]:
        """Get tags specific to Azure Storage service.
        
        Returns:
            Set of service-specific tags
        """
        return {
            "public_storage_account", 
            "unencrypted_data", 
            "insecure_storage_transport",
            "storage_logging_disabled",
            "unrestricted_network_access"
        }
    
    async def _check_public_access(self, account: StorageAccount) -> List[Finding]:
        """Check if storage account allows public access.
        
        Args:
            account: Storage account to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = account.id.split('/')[4]
            
            # Check if public access is enabled
            if account.allow_blob_public_access or account.public_network_access == "Enabled":
                # Create resource
                resource = Resource(
                    id=account.id,
                    name=account.name,
                    type="storage_account",
                    region=account.location,
                    properties={
                        "allow_blob_public_access": account.allow_blob_public_access,
                        "public_network_access": account.public_network_access,
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Disable public access to the storage account",
                    description="Public access to Azure Storage accounts should be disabled to prevent unauthorized access to data. Configure proper authentication and network controls instead.",
                    steps=[
                        RemediationStep(
                            title="Disable blob public access",
                            description="Disable blob public access for the storage account using Azure Portal or Azure CLI.",
                            code="az storage account update --name {account_name} --resource-group {resource_group} --allow-blob-public-access false".format(
                                account_name=account.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        ),
                        RemediationStep(
                            title="Configure network restrictions",
                            description="Configure network restrictions to limit access to specific networks.",
                            code="az storage account update --name {account_name} --resource-group {resource_group} --default-action Deny".format(
                                account_name=account.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/storage/common/storage-auth",
                        "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"public_storage_account"})
                
                # Create finding
                finding = Finding(
                    title=f"Public access enabled for storage account '{account.name}'",
                    description=f"The storage account '{account.name}' has public access enabled, which could lead to unauthorized access to data.",
                    severity=Severity.HIGH,
                    provider="azure",
                    service="storage",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"public_storage_account", "storage", "access_control"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found public access enabled for storage account: {account.name}")
            
        except Exception as e:
            logger.error(f"Error checking public access for storage account {account.name}: {str(e)}")
        
        return findings
    
    async def _check_encryption(self, account: StorageAccount) -> List[Finding]:
        """Check if storage account is encrypted.
        
        Args:
            account: Storage account to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = account.id.split('/')[4]
            
            # Check if infrastructure encryption is required
            if account.encryption and not account.encryption.require_infrastructure_encryption:
                # Create resource
                resource = Resource(
                    id=account.id,
                    name=account.name,
                    type="storage_account",
                    region=account.location,
                    properties={
                        "encryption": account.encryption.__dict__ if account.encryption else {},
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable infrastructure encryption for the storage account",
                    description="Azure Storage accounts should have infrastructure encryption enabled for enhanced security. This provides an additional layer of encryption for your data.",
                    steps=[
                        RemediationStep(
                            title="Enable infrastructure encryption",
                            description="Infrastructure encryption must be enabled when the storage account is created. To enable it, you'll need to recreate the storage account.",
                            code="az storage account create --name {account_name} --resource-group {resource_group} --location {location} --require-infrastructure-encryption true".format(
                                account_name=account.name,
                                resource_group=resource_group,
                                location=account.location
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"unencrypted_data"})
                
                # Create finding
                finding = Finding(
                    title=f"Infrastructure encryption not enabled for storage account '{account.name}'",
                    description=f"The storage account '{account.name}' does not have infrastructure encryption enabled, which may not meet security requirements for sensitive data.",
                    severity=Severity.MEDIUM,
                    provider="azure",
                    service="storage",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"unencrypted_data", "storage", "encryption"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found infrastructure encryption not enabled for storage account: {account.name}")
            
        except Exception as e:
            logger.error(f"Error checking encryption for storage account {account.name}: {str(e)}")
        
        return findings
    
    async def _check_secure_transfer(self, account: StorageAccount) -> List[Finding]:
        """Check if storage account requires secure transfer.
        
        Args:
            account: Storage account to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = account.id.split('/')[4]
            
            # Check if secure transfer is required
            if not account.enable_https_traffic_only:
                # Create resource
                resource = Resource(
                    id=account.id,
                    name=account.name,
                    type="storage_account",
                    region=account.location,
                    properties={
                        "enable_https_traffic_only": account.enable_https_traffic_only,
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable secure transfer for the storage account",
                    description="Azure Storage accounts should require secure transfer (HTTPS) to ensure data is encrypted in transit.",
                    steps=[
                        RemediationStep(
                            title="Enable secure transfer",
                            description="Enable secure transfer for the storage account using Azure Portal or Azure CLI.",
                            code="az storage account update --name {account_name} --resource-group {resource_group} --https-only true".format(
                                account_name=account.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"insecure_storage_transport"})
                
                # Create finding
                finding = Finding(
                    title=f"Secure transfer not enabled for storage account '{account.name}'",
                    description=f"The storage account '{account.name}' does not require secure transfer (HTTPS), which could allow data to be transmitted unencrypted.",
                    severity=Severity.HIGH,
                    provider="azure",
                    service="storage",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"insecure_storage_transport", "storage", "encryption_in_transit"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found secure transfer not enabled for storage account: {account.name}")
            
        except Exception as e:
            logger.error(f"Error checking secure transfer for storage account {account.name}: {str(e)}")
        
        return findings
    
    async def _check_network_access(self, account: StorageAccount) -> List[Finding]:
        """Check if storage account has network restrictions.
        
        Args:
            account: Storage account to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = account.id.split('/')[4]
            
            # Check if network access is unrestricted
            if not account.network_rule_set or account.network_rule_set.default_action == "Allow":
                # Create resource
                resource = Resource(
                    id=account.id,
                    name=account.name,
                    type="storage_account",
                    region=account.location,
                    properties={
                        "network_rule_set": account.network_rule_set.__dict__ if account.network_rule_set else {},
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Configure network restrictions for the storage account",
                    description="Azure Storage accounts should have network restrictions to limit access to specific networks. This reduces the attack surface and prevents unauthorized access.",
                    steps=[
                        RemediationStep(
                            title="Configure default network rule",
                            description="Set the default network rule to deny all access, then add specific network rules for required access.",
                            code="az storage account update --name {account_name} --resource-group {resource_group} --default-action Deny".format(
                                account_name=account.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        ),
                        RemediationStep(
                            title="Add network rules",
                            description="Add network rules for required access, such as IP ranges or virtual networks.",
                            code="az storage account network-rule add --name {account_name} --resource-group {resource_group} --ip-address <your-ip-address>".format(
                                account_name=account.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"unrestricted_network_access"})
                
                # Create finding
                finding = Finding(
                    title=f"Unrestricted network access for storage account '{account.name}'",
                    description=f"The storage account '{account.name}' does not have network restrictions, allowing access from any network. This increases the attack surface and may lead to unauthorized access.",
                    severity=Severity.MEDIUM,
                    provider="azure",
                    service="storage",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"unrestricted_network_access", "storage", "network_security"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found unrestricted network access for storage account: {account.name}")
            
        except Exception as e:
            logger.error(f"Error checking network access for storage account {account.name}: {str(e)}")
        
        return findings
    
    async def _check_logging(self, account: StorageAccount) -> List[Finding]:
        """Check if storage account has logging enabled.
        
        Args:
            account: Storage account to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = account.id.split('/')[4]
            
            # Get blob service properties
            blob_props = None
            try:
                blob_props = self.storage_client.blob_services.get_service_properties(
                    resource_group_name=resource_group,
                    account_name=account.name
                )
            except Exception as e:
                logger.debug(f"Could not retrieve blob properties for {account.name}: {str(e)}")
            
            # Check if logging is enabled
            if not blob_props or not blob_props.logging or not (blob_props.logging.delete and blob_props.logging.read and blob_props.logging.write):
                # Create resource
                resource = Resource(
                    id=account.id,
                    name=account.name,
                    type="storage_account",
                    region=account.location,
                    properties={
                        "logging": blob_props.logging.__dict__ if blob_props and blob_props.logging else {},
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable logging for the storage account",
                    description="Azure Storage accounts should have logging enabled to track access and operations. This aids in security monitoring and forensic investigation.",
                    steps=[
                        RemediationStep(
                            title="Enable logging",
                            description="Enable logging for the storage account using Azure Portal or Azure CLI.",
                            code="az storage logging update --account-name {account_name} --service b --log rwd --retention 90".format(
                                account_name=account.name
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/storage/common/storage-analytics-logging"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"storage_logging_disabled"})
                
                # Create finding
                finding = Finding(
                    title=f"Logging not fully enabled for storage account '{account.name}'",
                    description=f"The storage account '{account.name}' does not have logging fully enabled for read, write, and delete operations. This makes it difficult to track access and detect unauthorized activities.",
                    severity=Severity.LOW,
                    provider="azure",
                    service="storage",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"storage_logging_disabled", "storage", "logging"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found logging not fully enabled for storage account: {account.name}")
            
        except Exception as e:
            logger.error(f"Error checking logging for storage account {account.name}: {str(e)}")
        
        return findings 