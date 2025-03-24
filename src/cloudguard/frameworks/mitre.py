"""MITRE ATT&CK framework mapping utilities."""

from typing import Dict, List, Optional, Set, Any

# Mapping of common cloud misconfigurations to MITRE ATT&CK techniques
MITRE_ATTACK_MAPPINGS = {
    # Initial Access
    "public_s3_bucket": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Public S3 buckets can be exploited to gain access to sensitive data."
    },
    "public_storage_account": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Public Azure Storage accounts can be exploited to gain access to sensitive data."
    },
    "weak_password_policy": {
        "id": "T1078",
        "name": "Valid Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "description": "Weak password policies can enable brute force attacks to gain valid credentials."
    },
    
    # Persistence
    "iam_user_with_keys": {
        "id": "T1098",
        "name": "Account Manipulation",
        "url": "https://attack.mitre.org/techniques/T1098/",
        "description": "Long-lived IAM access keys can be used for persistence if compromised."
    },
    "privileged_role_assignment": {
        "id": "T1098",
        "name": "Account Manipulation",
        "url": "https://attack.mitre.org/techniques/T1098/",
        "description": "Excessive role assignments in Azure can be used for persistence."
    },
    
    # Privilege Escalation
    "excessive_permissions": {
        "id": "T1078.004",
        "name": "Valid Accounts: Cloud Accounts",
        "url": "https://attack.mitre.org/techniques/T1078/004/",
        "description": "Users or roles with excessive permissions can be exploited for privilege escalation."
    },
    "risky_permissions": {
        "id": "T1484.001",
        "name": "Domain Policy Modification: Group Policy Modification",
        "url": "https://attack.mitre.org/techniques/T1484/001/",
        "description": "Risky permissions can allow attackers to modify policies and escalate privileges."
    },
    
    # Defense Evasion
    "disabled_logging": {
        "id": "T1562.008",
        "name": "Impair Defenses: Disable Cloud Logs",
        "url": "https://attack.mitre.org/techniques/T1562/008/",
        "description": "Disabled logging can prevent detection of malicious activities."
    },
    "disabled_monitoring": {
        "id": "T1562",
        "name": "Impair Defenses",
        "url": "https://attack.mitre.org/techniques/T1562/",
        "description": "Disabled monitoring can prevent detection of malicious activities."
    },
    
    # Credential Access
    "unencrypted_credentials": {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
        "description": "Unencrypted credentials can be easily accessed by attackers."
    },
    "no_mfa": {
        "id": "T1556",
        "name": "Modify Authentication Process",
        "url": "https://attack.mitre.org/techniques/T1556/",
        "description": "Lack of multi-factor authentication makes it easier to use stolen credentials."
    },
    
    # Discovery
    "metadata_service_access": {
        "id": "T1580",
        "name": "Cloud Infrastructure Discovery",
        "url": "https://attack.mitre.org/techniques/T1580/",
        "description": "Unrestricted access to metadata services allows discovery of cloud infrastructure details."
    },
    
    # Lateral Movement
    "overly_permissive_security_group": {
        "id": "T1021",
        "name": "Remote Services",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "description": "Overly permissive security groups can enable lateral movement between instances."
    },
    
    # Collection
    "data_exfiltration": {
        "id": "T1530",
        "name": "Data from Cloud Storage",
        "url": "https://attack.mitre.org/techniques/T1530/",
        "description": "Misconfigured cloud storage can allow unauthorized data exfiltration."
    },
    
    # Command and Control
    "publicly_exposed_service": {
        "id": "T1133",
        "name": "External Remote Services",
        "url": "https://attack.mitre.org/techniques/T1133/",
        "description": "Publicly exposed services can be used for command and control."
    },
    
    # Impact
    "unencrypted_data": {
        "id": "T1485",
        "name": "Data Destruction",
        "url": "https://attack.mitre.org/techniques/T1485/",
        "description": "Unencrypted data is more vulnerable to unauthorized access and destruction."
    }
}


def get_mitre_technique(technique_id: str) -> Optional[Dict[str, Any]]:
    """Get MITRE ATT&CK technique details by ID.
    
    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1190")
        
    Returns:
        Technique details or None if not found
    """
    for technique in MITRE_ATTACK_MAPPINGS.values():
        if technique["id"] == technique_id:
            return technique
    return None


def get_mitre_mapping_by_tag(tag: str) -> Optional[Dict[str, Any]]:
    """Get MITRE ATT&CK mapping by tag.
    
    Args:
        tag: Tag to look up in mappings
        
    Returns:
        Mapping details or None if not found
    """
    return MITRE_ATTACK_MAPPINGS.get(tag) 