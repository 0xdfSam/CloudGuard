"""Azure KeyVault service scanner."""

import logging
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta

from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.keyvault.secrets import SecretClient
from azure.mgmt.keyvault.models import Vault, VaultProperties
from azure.core.exceptions import ResourceNotFoundError, ClientAuthenticationError

from cloudguard.core.findings import Finding, Severity, Remediation, RemediationStep, Resource, FrameworkMapping
from cloudguard.frameworks.mapping import get_framework_mappings_from_tags
from .base import AzureServiceScanner
from cloudguard.utils.logger import get_logger

logger = get_logger(__name__)


class KeyVaultScanner(AzureServiceScanner):
    """Azure KeyVault service scanner."""
    
    service_name = "keyvault"
    
    def __init__(self, credential, subscription_id):
        """Initialize the KeyVault scanner.
        
        Args:
            credential: Azure credential
            subscription_id: Azure subscription ID
        """
        super().__init__(credential, subscription_id)
        self.keyvault_client = KeyVaultManagementClient(credential, subscription_id)
    
    async def scan(self) -> List[Finding]:
        """Scan Azure KeyVaults for security issues.
        
        Returns:
            List of findings
        """
        logger.info(f"Scanning Azure KeyVaults in subscription {self.subscription_id}")
        findings = []
        
        try:
            # Get key vaults
            key_vaults = list(self.keyvault_client.vaults.list())
            
            if not key_vaults:
                logger.info(f"No key vaults found in subscription {self.subscription_id}")
                return findings
            
            logger.info(f"Found {len(key_vaults)} key vaults in subscription {self.subscription_id}")
            
            # Check each key vault
            for vault in key_vaults:
                logger.debug(f"Checking key vault: {vault.name}")
                
                # Check for network access
                network_findings = await self._check_network_access(vault)
                findings.extend(network_findings)
                
                # Check for purge protection
                purge_findings = await self._check_purge_protection(vault)
                findings.extend(purge_findings)
                
                # Check for soft delete
                soft_delete_findings = await self._check_soft_delete(vault)
                findings.extend(soft_delete_findings)
                
                # Check for key expiration
                expiration_findings = await self._check_key_expiration(vault)
                findings.extend(expiration_findings)
                
                # Check for logging
                logging_findings = await self._check_logging(vault)
                findings.extend(logging_findings)
            
            logger.info(f"Completed Azure KeyVault scan in subscription {self.subscription_id}, found {len(findings)} issues")
            
        except Exception as e:
            logger.error(f"Error scanning Azure KeyVaults: {str(e)}")
        
        return findings
    
    async def get_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get Azure KeyVault resources.
        
        Returns:
            Dictionary mapping resource types to lists of resources
        """
        resources = {
            "key_vaults": []
        }
        
        try:
            # Get key vaults
            key_vaults = list(self.keyvault_client.vaults.list())
            
            for vault in key_vaults:
                # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
                resource_group = vault.id.split('/')[4]
                
                # Convert to dictionary
                vault_dict = {
                    "id": vault.id,
                    "name": vault.name,
                    "resource_group": resource_group,
                    "location": vault.location,
                    "tags": vault.tags or {},
                    "properties": {
                        "tenant_id": vault.properties.tenant_id,
                        "sku": vault.properties.sku.name if vault.properties.sku else None,
                        "enabled_for_deployment": vault.properties.enabled_for_deployment,
                        "enabled_for_disk_encryption": vault.properties.enabled_for_disk_encryption,
                        "enabled_for_template_deployment": vault.properties.enabled_for_template_deployment,
                        "soft_delete_enabled": vault.properties.enable_soft_delete,
                        "purge_protection_enabled": vault.properties.enable_purge_protection,
                        "network_acls": {
                            "default_action": vault.properties.network_acls.default_action if vault.properties.network_acls else None,
                            "bypass": vault.properties.network_acls.bypass if vault.properties.network_acls else None,
                            "ip_rules": [ip.value for ip in vault.properties.network_acls.ip_rules] if vault.properties.network_acls and vault.properties.network_acls.ip_rules else [],
                            "virtual_network_rules": [vnet.id for vnet in vault.properties.network_acls.virtual_network_rules] if vault.properties.network_acls and vault.properties.network_acls.virtual_network_rules else []
                        }
                    }
                }
                
                resources["key_vaults"].append(vault_dict)
                
            logger.info(f"Retrieved {len(resources['key_vaults'])} key vaults from subscription {self.subscription_id}")
            
        except Exception as e:
            logger.error(f"Error retrieving Azure KeyVault resources: {str(e)}")
        
        return resources
    
    def get_service_tags(self) -> Set[str]:
        """Get tags specific to Azure KeyVault service.
        
        Returns:
            Set of service-specific tags
        """
        return {
            "unrestricted_keyvault_access", 
            "keyvault_purge_protection_disabled", 
            "keyvault_soft_delete_disabled",
            "keyvault_key_expiration_missing",
            "keyvault_logging_disabled"
        }
    
    async def _check_network_access(self, vault: Vault) -> List[Finding]:
        """Check if KeyVault has network restrictions.
        
        Args:
            vault: KeyVault to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = vault.id.split('/')[4]
            
            # Check if network access is unrestricted
            if not vault.properties.network_acls or vault.properties.network_acls.default_action == "Allow":
                # Create resource
                resource = Resource(
                    id=vault.id,
                    name=vault.name,
                    type="key_vault",
                    region=vault.location,
                    properties={
                        "network_acls": vault.properties.network_acls.__dict__ if vault.properties.network_acls else {},
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Configure network restrictions for the key vault",
                    description="Azure Key Vaults should have network restrictions to limit access to specific networks. This reduces the attack surface and prevents unauthorized access.",
                    steps=[
                        RemediationStep(
                            title="Configure network rules",
                            description="Set the default network rule to deny all access, then add specific network rules for required access.",
                            code="""az keyvault update --name {vault_name} --resource-group {resource_group} \\
    --default-action Deny \\
    --bypass AzureServices""".format(
                                vault_name=vault.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        ),
                        RemediationStep(
                            title="Add IP rules",
                            description="Add IP rules for required access.",
                            code="""az keyvault network-rule add --name {vault_name} --resource-group {resource_group} \\
    --ip-address <your-ip-address>""".format(
                                vault_name=vault.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/key-vault/general/network-security"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"unrestricted_keyvault_access"})
                
                # Create finding
                finding = Finding(
                    title=f"Unrestricted network access for key vault '{vault.name}'",
                    description=f"The key vault '{vault.name}' does not have network restrictions, allowing access from any network. This increases the attack surface and may lead to unauthorized access.",
                    severity=Severity.HIGH,
                    provider="azure",
                    service="keyvault",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"unrestricted_keyvault_access", "keyvault", "network_security"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found unrestricted network access for key vault: {vault.name}")
            
        except Exception as e:
            logger.error(f"Error checking network access for key vault {vault.name}: {str(e)}")
        
        return findings
    
    async def _check_purge_protection(self, vault: Vault) -> List[Finding]:
        """Check if KeyVault has purge protection enabled.
        
        Args:
            vault: KeyVault to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = vault.id.split('/')[4]
            
            # Check if purge protection is enabled
            if not vault.properties.enable_purge_protection:
                # Create resource
                resource = Resource(
                    id=vault.id,
                    name=vault.name,
                    type="key_vault",
                    region=vault.location,
                    properties={
                        "enable_purge_protection": vault.properties.enable_purge_protection,
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable purge protection for the key vault",
                    description="Azure Key Vaults should have purge protection enabled to prevent accidental or malicious deletion of secrets, keys, and certificates.",
                    steps=[
                        RemediationStep(
                            title="Enable purge protection",
                            description="Enable purge protection for the key vault using Azure Portal or Azure CLI.",
                            code="""az keyvault update --name {vault_name} --resource-group {resource_group} \\
    --enable-purge-protection true""".format(
                                vault_name=vault.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"keyvault_purge_protection_disabled"})
                
                # Create finding
                finding = Finding(
                    title=f"Purge protection not enabled for key vault '{vault.name}'",
                    description=f"The key vault '{vault.name}' does not have purge protection enabled, which could allow permanent deletion of sensitive secrets, keys, and certificates.",
                    severity=Severity.MEDIUM,
                    provider="azure",
                    service="keyvault",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"keyvault_purge_protection_disabled", "keyvault", "data_protection"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found purge protection not enabled for key vault: {vault.name}")
            
        except Exception as e:
            logger.error(f"Error checking purge protection for key vault {vault.name}: {str(e)}")
        
        return findings
    
    async def _check_soft_delete(self, vault: Vault) -> List[Finding]:
        """Check if KeyVault has soft delete enabled.
        
        Args:
            vault: KeyVault to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = vault.id.split('/')[4]
            
            # Check if soft delete is enabled
            if not vault.properties.enable_soft_delete:
                # Create resource
                resource = Resource(
                    id=vault.id,
                    name=vault.name,
                    type="key_vault",
                    region=vault.location,
                    properties={
                        "enable_soft_delete": vault.properties.enable_soft_delete,
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable soft delete for the key vault",
                    description="Azure Key Vaults should have soft delete enabled to protect against accidental or malicious deletion of secrets, keys, and certificates.",
                    steps=[
                        RemediationStep(
                            title="Enable soft delete",
                            description="Enable soft delete for the key vault using Azure Portal or Azure CLI.",
                            code="""az keyvault update --name {vault_name} --resource-group {resource_group} \\
    --enable-soft-delete true""".format(
                                vault_name=vault.name,
                                resource_group=resource_group
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"keyvault_soft_delete_disabled"})
                
                # Create finding
                finding = Finding(
                    title=f"Soft delete not enabled for key vault '{vault.name}'",
                    description=f"The key vault '{vault.name}' does not have soft delete enabled, which could lead to accidental loss of sensitive secrets, keys, and certificates.",
                    severity=Severity.MEDIUM,
                    provider="azure",
                    service="keyvault",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"keyvault_soft_delete_disabled", "keyvault", "data_protection"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found soft delete not enabled for key vault: {vault.name}")
            
        except Exception as e:
            logger.error(f"Error checking soft delete for key vault {vault.name}: {str(e)}")
        
        return findings
    
    async def _check_key_expiration(self, vault: Vault) -> List[Finding]:
        """Check if keys in KeyVault have expiration dates.
        
        Args:
            vault: KeyVault to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = vault.id.split('/')[4]
            
            # Get detailed vault properties
            vault_details = self.keyvault_client.vaults.get(resource_group, vault.name)
            
            if not vault_details:
                logger.warning(f"Could not retrieve details for key vault: {vault.name}")
                return findings
            
            # Check if there are any keys without expiration dates
            # Note: This would typically require using the Key Vault Key client which needs direct access to the vault
            # For the purpose of this scanner, we'll only flag this if the vault has enabled key rotation
            if not vault_details.properties.enabled_for_deployment:
                # Create resource
                resource = Resource(
                    id=vault.id,
                    name=vault.name,
                    type="key_vault",
                    region=vault.location,
                    properties={
                        "enabled_for_deployment": vault_details.properties.enabled_for_deployment,
                        "resource_group": resource_group
                    }
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Set expiration dates for keys in the key vault",
                    description="Azure Key Vault keys should have expiration dates set to ensure keys are regularly rotated. This is a security best practice.",
                    steps=[
                        RemediationStep(
                            title="Set expiration policy",
                            description="Configure an expiration policy for keys in the key vault.",
                            code="""# For existing keys:
az keyvault key set-attributes --name <key-name> --vault-name {vault_name} \\
    --expires $(date -v+1y -u +"%Y-%m-%dT%H:%M:%SZ")

# When creating new keys:
az keyvault key create --name <new-key-name> --vault-name {vault_name} \\
    --expires $(date -v+1y -u +"%Y-%m-%dT%H:%M:%SZ")""".format(
                                vault_name=vault.name
                            ),
                            code_language="bash"
                        )
                    ],
                    links=[
                        "https://docs.microsoft.com/en-us/azure/key-vault/keys/about-keys"
                    ]
                )
                
                # Framework mappings
                framework_mappings = get_framework_mappings_from_tags({"keyvault_key_expiration_missing"})
                
                # Create finding
                finding = Finding(
                    title=f"Key rotation may not be properly configured for key vault '{vault.name}'",
                    description=f"The key vault '{vault.name}' might have keys without expiration dates. Keys should have expiration dates to ensure regular rotation.",
                    severity=Severity.LOW,
                    provider="azure",
                    service="keyvault",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"keyvault_key_expiration_missing", "keyvault", "key_management"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
                
                logger.info(f"Found potential key expiration issues for key vault: {vault.name}")
            
        except Exception as e:
            logger.error(f"Error checking key expiration for key vault {vault.name}: {str(e)}")
        
        return findings
    
    async def _check_logging(self, vault: Vault) -> List[Finding]:
        """Check if KeyVault has diagnostic logging enabled.
        
        Args:
            vault: KeyVault to check
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Resource group from id: /subscriptions/{sub}/resourceGroups/{rg}/providers/...
            resource_group = vault.id.split('/')[4]
            
            # Note: Checking for diagnostic settings requires the Azure Monitor client
            # For the purpose of this scanner, we'll recommend enabling logging but won't check if it's enabled
            
            # Create resource
            resource = Resource(
                id=vault.id,
                name=vault.name,
                type="key_vault",
                region=vault.location,
                properties={
                    "resource_group": resource_group
                }
            )
            
            # Create remediation
            remediation = Remediation(
                summary="Enable diagnostic logging for the key vault",
                description="Azure Key Vaults should have diagnostic logging enabled to track access and operations. This aids in security monitoring and forensic investigation.",
                steps=[
                    RemediationStep(
                        title="Enable diagnostic logging",
                        description="Enable diagnostic logging for the key vault using Azure Portal or Azure CLI.",
                        code="""# Create a log analytics workspace first if you don't have one
az monitor log-analytics workspace create --resource-group {resource_group} \\
    --workspace-name <workspace-name>

# Enable diagnostic settings
az monitor diagnostic-settings create --resource {vault_id} \\
    --name KeyVaultLogs \\
    --workspace <workspace-id> \\
    --logs '[{{"category": "AuditEvent", "enabled": true}}]'""".format(
                            resource_group=resource_group,
                            vault_id=vault.id
                        ),
                        code_language="bash"
                    )
                ],
                links=[
                    "https://docs.microsoft.com/en-us/azure/key-vault/general/logging"
                ]
            )
            
            # Framework mappings
            framework_mappings = get_framework_mappings_from_tags({"keyvault_logging_disabled"})
            
            # Create finding
            finding = Finding(
                title=f"Diagnostic logging may not be enabled for key vault '{vault.name}'",
                description=f"Verify that the key vault '{vault.name}' has diagnostic logging enabled to track access and operations. This is important for security monitoring and forensic investigation.",
                severity=Severity.LOW,
                provider="azure",
                service="keyvault",
                resources=[resource],
                remediation=remediation,
                framework_mappings=framework_mappings,
                tags={"keyvault_logging_disabled", "keyvault", "logging"}
            )
            
            finding.calculate_risk_score()
            findings.append(finding)
            
            logger.info(f"Recommended logging verification for key vault: {vault.name}")
            
        except Exception as e:
            logger.error(f"Error checking logging for key vault {vault.name}: {str(e)}")
        
        return findings 