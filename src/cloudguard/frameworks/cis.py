"""CIS (Center for Internet Security) Benchmarks framework mapping utilities."""

from typing import Dict, List, Optional, Any

# Mapping of common cloud misconfigurations to CIS Benchmark controls
# Focusing on AWS and Azure cloud platforms
CIS_MAPPINGS = {
    # AWS S3
    "public_s3_bucket": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "2.1.5",
        "name": "Ensure that S3 Buckets are configured with 'Block public access'",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "S3 buckets should be configured to block public access to prevent unauthorized data exposure."
    },
    "unencrypted_s3_bucket": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "2.1.1",
        "name": "Ensure all S3 buckets employ encryption-at-rest",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "S3 buckets should have encryption enabled to protect data at rest."
    },
    "s3_bucket_logging_disabled": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "2.6",
        "name": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "S3 bucket access logging should be enabled to track access to buckets and objects."
    },
    
    # AWS IAM
    "weak_password_policy": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "1.8",
        "name": "Ensure IAM password policy requires minimum password length of 14 or greater",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "IAM password policies should enforce a minimum password length to improve security."
    },
    "no_mfa": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "1.10",
        "name": "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "MFA should be enabled for all users with console access to provide an additional layer of security."
    },
    "root_account_use": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "1.1",
        "name": "Maintain current contact details",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "The root account should not be used for everyday tasks and should have contact details maintained."
    },
    "inactive_access_keys": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "1.3",
        "name": "Ensure credentials unused for 90 days or greater are disabled",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "Access keys that haven't been used in 90 days or more should be disabled to reduce security risks."
    },
    
    # AWS CloudTrail
    "disabled_cloudtrail": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "3.1",
        "name": "Ensure CloudTrail is enabled in all regions",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "CloudTrail should be enabled in all regions to track API calls and changes to resources."
    },
    "unencrypted_cloudtrail": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "3.7",
        "name": "Ensure CloudTrail logs are encrypted at rest using KMS CMKs",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "CloudTrail logs should be encrypted at rest to protect sensitive information."
    },
    
    # AWS EC2
    "default_security_group_open": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "5.3",
        "name": "Ensure the default security group of every VPC restricts all traffic",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "Default security groups should be configured to restrict all traffic to prevent unintended access."
    },
    "overly_permissive_security_group": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "5.2",
        "name": "Ensure security groups are attached to another resource",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "Security groups should have specific, restricted rules and be properly attached to resources."
    },
    
    # AWS RDS
    "publicly_accessible_db": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "2.3.3",
        "name": "Ensure RDS instances are not publicly accessible",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "RDS instances should not be publicly accessible to reduce attack surface."
    },
    "unencrypted_rds": {
        "benchmark": "CIS AWS Foundations",
        "version": "1.4.0",
        "id": "2.3.1",
        "name": "Ensure RDS instances are encrypted at rest",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services/",
        "description": "RDS instances should be encrypted at rest to protect sensitive data."
    },
    
    # Azure Storage
    "public_storage_account": {
        "benchmark": "CIS Microsoft Azure Foundations",
        "version": "1.4.0",
        "id": "3.1",
        "name": "Ensure that 'Secure transfer required' is set to 'Enabled'",
        "url": "https://www.cisecurity.org/benchmark/azure/",
        "description": "Storage accounts should be configured to require secure transfer to prevent data exposure."
    },
    "unencrypted_storage_account": {
        "benchmark": "CIS Microsoft Azure Foundations",
        "version": "1.4.0",
        "id": "3.2",
        "name": "Ensure that storage account access keys are periodically regenerated",
        "url": "https://www.cisecurity.org/benchmark/azure/",
        "description": "Storage account keys should be rotated regularly to maintain security."
    },
    
    # Azure IAM
    "azure_mfa_disabled": {
        "benchmark": "CIS Microsoft Azure Foundations",
        "version": "1.4.0",
        "id": "1.2",
        "name": "Ensure that multi-factor authentication is enabled for all privileged users",
        "url": "https://www.cisecurity.org/benchmark/azure/",
        "description": "Multi-factor authentication should be enabled for all privileged users to provide an additional layer of security."
    },
    "azure_excessive_admin_users": {
        "benchmark": "CIS Microsoft Azure Foundations",
        "version": "1.4.0",
        "id": "1.1",
        "name": "Ensure that multi-factor authentication is enabled for all non-privileged users",
        "url": "https://www.cisecurity.org/benchmark/azure/",
        "description": "The number of Global Administrators should be limited to minimize security risks."
    },
    
    # Azure Network Security
    "azure_network_security_group_open": {
        "benchmark": "CIS Microsoft Azure Foundations",
        "version": "1.4.0",
        "id": "6.2",
        "name": "Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'",
        "url": "https://www.cisecurity.org/benchmark/azure/",
        "description": "Network Security Group flow logs should be retained for at least 90 days for security analysis."
    },
    "azure_vm_disk_unencrypted": {
        "benchmark": "CIS Microsoft Azure Foundations",
        "version": "1.4.0",
        "id": "7.1",
        "name": "Ensure that 'OS disk' are encrypted",
        "url": "https://www.cisecurity.org/benchmark/azure/",
        "description": "VM disks should be encrypted to protect data at rest."
    }
}


def get_cis_mapping_by_tag(tag: str) -> Optional[Dict[str, Any]]:
    """Get CIS Benchmark mapping by tag.
    
    Args:
        tag: Tag to look up in mappings
        
    Returns:
        Mapping details or None if not found
    """
    return CIS_MAPPINGS.get(tag)


def get_cis_mappings_by_benchmark(benchmark: str, version: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get CIS Benchmark mappings by benchmark name and optionally version.
    
    Args:
        benchmark: Benchmark name (e.g., "CIS AWS Foundations")
        version: Optional benchmark version (e.g., "1.4.0")
        
    Returns:
        List of mappings for the specified benchmark
    """
    results = []
    for mapping in CIS_MAPPINGS.values():
        if mapping["benchmark"] == benchmark:
            if version is None or mapping["version"] == version:
                results.append(mapping)
    return results 