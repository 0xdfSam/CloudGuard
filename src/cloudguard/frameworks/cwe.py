"""CWE (Common Weakness Enumeration) framework mapping utilities."""

from typing import Dict, List, Optional, Set, Any

# Mapping of common cloud misconfigurations to CWE IDs
CWE_MAPPINGS = {
    # Access Control
    "public_s3_bucket": {
        "id": "CWE-284",
        "name": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html",
        "description": "Public S3 buckets allow unrestricted access to data, violating proper access control principles."
    },
    "public_storage_account": {
        "id": "CWE-284",
        "name": "Improper Access Control",
        "url": "https://cwe.mitre.org/data/definitions/284.html",
        "description": "Public Azure Storage accounts allow unrestricted access to data, violating proper access control principles."
    },
    "weak_iam_policy": {
        "id": "CWE-272",
        "name": "Least Privilege Violation",
        "url": "https://cwe.mitre.org/data/definitions/272.html",
        "description": "Overly permissive IAM policies violate the principle of least privilege."
    },
    "excessive_permissions": {
        "id": "CWE-272",
        "name": "Least Privilege Violation",
        "url": "https://cwe.mitre.org/data/definitions/272.html",
        "description": "Users or roles with excessive permissions violate the principle of least privilege."
    },
    
    # Authentication
    "weak_password_policy": {
        "id": "CWE-521",
        "name": "Weak Password Requirements",
        "url": "https://cwe.mitre.org/data/definitions/521.html",
        "description": "Weak password policies increase the risk of password-based attacks."
    },
    "no_mfa": {
        "id": "CWE-308",
        "name": "Use of Single-factor Authentication",
        "url": "https://cwe.mitre.org/data/definitions/308.html",
        "description": "Lack of multi-factor authentication relies only on single-factor authentication."
    },
    "plaintext_credentials": {
        "id": "CWE-312",
        "name": "Cleartext Storage of Sensitive Information",
        "url": "https://cwe.mitre.org/data/definitions/312.html",
        "description": "Storing credentials in plaintext exposes sensitive information."
    },
    
    # Encryption
    "unencrypted_data": {
        "id": "CWE-311",
        "name": "Missing Encryption of Sensitive Data",
        "url": "https://cwe.mitre.org/data/definitions/311.html",
        "description": "Failing to encrypt sensitive data increases the risk of unauthorized access."
    },
    "weak_encryption": {
        "id": "CWE-326",
        "name": "Inadequate Encryption Strength",
        "url": "https://cwe.mitre.org/data/definitions/326.html",
        "description": "Using weak encryption algorithms or key sizes reduces the effectiveness of encryption."
    },
    "no_encryption_in_transit": {
        "id": "CWE-319",
        "name": "Cleartext Transmission of Sensitive Information",
        "url": "https://cwe.mitre.org/data/definitions/319.html",
        "description": "Transmitting data without encryption exposes it to interception and unauthorized access."
    },
    
    # Network Security
    "overly_permissive_security_group": {
        "id": "CWE-668",
        "name": "Exposure of Resource to Wrong Sphere",
        "url": "https://cwe.mitre.org/data/definitions/668.html",
        "description": "Overly permissive security groups expose resources to unauthorized networks or users."
    },
    "default_vpc_settings": {
        "id": "CWE-276",
        "name": "Incorrect Default Permissions",
        "url": "https://cwe.mitre.org/data/definitions/276.html",
        "description": "Using default VPC settings may provide more access than necessary."
    },
    
    # Logging and Monitoring
    "disabled_logging": {
        "id": "CWE-778",
        "name": "Insufficient Logging",
        "url": "https://cwe.mitre.org/data/definitions/778.html",
        "description": "Insufficient logging makes it difficult to detect and investigate security incidents."
    },
    "disabled_monitoring": {
        "id": "CWE-693",
        "name": "Protection Mechanism Failure",
        "url": "https://cwe.mitre.org/data/definitions/693.html",
        "description": "Disabled monitoring reduces the ability to detect and respond to security events."
    },
    
    # Configuration
    "insecure_default_configuration": {
        "id": "CWE-276",
        "name": "Incorrect Default Permissions",
        "url": "https://cwe.mitre.org/data/definitions/276.html",
        "description": "Using insecure default configurations can lead to unauthorized access."
    },
    "misconfigured_resource": {
        "id": "CWE-1220",
        "name": "Insufficient Granularity of Access Control",
        "url": "https://cwe.mitre.org/data/definitions/1220.html",
        "description": "Misconfigured resources may not have sufficiently granular access controls."
    },
    
    # Key Management
    "no_key_rotation": {
        "id": "CWE-324",
        "name": "Use of a Key Past its Expiration Date",
        "url": "https://cwe.mitre.org/data/definitions/324.html",
        "description": "Not rotating keys regularly increases the risk of key compromise over time."
    },
    
    # Database Security
    "publicly_accessible_db": {
        "id": "CWE-668",
        "name": "Exposure of Resource to Wrong Sphere",
        "url": "https://cwe.mitre.org/data/definitions/668.html",
        "description": "Making databases publicly accessible exposes them to unauthorized networks or users."
    }
}


def get_cwe(cwe_id: str) -> Optional[Dict[str, Any]]:
    """Get CWE details by ID.
    
    Args:
        cwe_id: CWE ID (e.g., "CWE-284")
        
    Returns:
        CWE details or None if not found
    """
    for cwe in CWE_MAPPINGS.values():
        if cwe["id"] == cwe_id:
            return cwe
    return None


def get_cwe_mapping_by_tag(tag: str) -> Optional[Dict[str, Any]]:
    """Get CWE mapping by tag.
    
    Args:
        tag: Tag to look up in mappings
        
    Returns:
        Mapping details or None if not found
    """
    return CWE_MAPPINGS.get(tag) 