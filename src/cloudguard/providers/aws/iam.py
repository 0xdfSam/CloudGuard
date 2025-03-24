"""AWS IAM scanner implementation."""

import asyncio
import logging
from typing import Dict, List, Optional, Set, Any

import boto3
import botocore.exceptions

from ...core.findings import Finding, FrameworkMapping, Remediation, RemediationDifficulty, RemediationStep, Resource, Severity
from ...utils.config import AwsConfig

logger = logging.getLogger(__name__)


class IamScanner:
    """Scanner for AWS IAM service."""

    def __init__(self, sessions: Dict[str, boto3.Session], config: AwsConfig):
        """Initialize the IAM scanner.

        Args:
            sessions: Map of region to boto3 Session
            config: AWS configuration
        """
        self.sessions = sessions
        self.config = config
        # IAM is a global service, use us-east-1 by default
        self.session = sessions.get('us-east-1', next(iter(sessions.values())))
        self.iam_client = self.session.client('iam')

    async def scan(self) -> List[Finding]:
        """Scan IAM for security issues.

        Returns:
            List of findings related to IAM
        """
        logger.info("Starting IAM security scan")
        findings = []

        # Run checks concurrently
        tasks = [
            self._check_password_policy(),
            self._check_root_access_keys(),
            self._check_mfa_for_console_users(),
            self._check_unused_credentials(),
            self._check_excessive_permissions()
        ]
        
        results = await asyncio.gather(*tasks)
        
        # Flatten results
        for result in results:
            findings.extend(result)
        
        logger.info(f"IAM scan complete. Found {len(findings)} issues.")
        return findings

    async def get_resources(self) -> Dict[str, List[Dict]]:
        """Get IAM resources from AWS.

        Returns:
            Dictionary with IAM resources
        """
        resources = {
            "iam_users": [],
            "iam_roles": [],
            "iam_groups": [],
            "iam_policies": []
        }
        
        try:
            # Get users
            paginator = self.iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    resources["iam_users"].append({
                        "name": user.get('UserName'),
                        "id": user.get('UserId'),
                        "arn": user.get('Arn'),
                        "create_date": user.get('CreateDate').isoformat() if user.get('CreateDate') else None
                    })
            
            # Get roles
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    resources["iam_roles"].append({
                        "name": role.get('RoleName'),
                        "id": role.get('RoleId'),
                        "arn": role.get('Arn'),
                        "create_date": role.get('CreateDate').isoformat() if role.get('CreateDate') else None
                    })
            
            # Get groups
            paginator = self.iam_client.get_paginator('list_groups')
            for page in paginator.paginate():
                for group in page.get('Groups', []):
                    resources["iam_groups"].append({
                        "name": group.get('GroupName'),
                        "id": group.get('GroupId'),
                        "arn": group.get('Arn'),
                        "create_date": group.get('CreateDate').isoformat() if group.get('CreateDate') else None
                    })
            
            # Get policies
            paginator = self.iam_client.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):  # Get only customer managed policies
                for policy in page.get('Policies', []):
                    resources["iam_policies"].append({
                        "name": policy.get('PolicyName'),
                        "id": policy.get('PolicyId'),
                        "arn": policy.get('Arn'),
                        "create_date": policy.get('CreateDate').isoformat() if policy.get('CreateDate') else None
                    })
            
        except Exception as e:
            logger.error(f"Error getting IAM resources: {str(e)}")
        
        return resources

    async def _check_password_policy(self) -> List[Finding]:
        """Check if the account password policy meets security best practices.

        Returns:
            List of findings related to password policy
        """
        findings = []
        try:
            try:
                policy = self.iam_client.get_account_password_policy()
                policy = policy.get('PasswordPolicy', {})
                
                issues = []
                
                # Check minimum password length
                if policy.get('MinimumPasswordLength', 0) < 14:
                    issues.append("Minimum password length is less than 14 characters")
                
                # Check password complexity
                if not policy.get('RequireSymbols', False):
                    issues.append("Password policy does not require symbols")
                if not policy.get('RequireNumbers', False):
                    issues.append("Password policy does not require numbers")
                if not policy.get('RequireUppercaseCharacters', False):
                    issues.append("Password policy does not require uppercase characters")
                if not policy.get('RequireLowercaseCharacters', False):
                    issues.append("Password policy does not require lowercase characters")
                
                # Check password reuse
                if not policy.get('PasswordReusePrevention', 0) >= 24:
                    issues.append("Password reuse prevention is not set to 24 or more")
                
                # Check password expiration
                if not policy.get('ExpirePasswords', False):
                    issues.append("Passwords are not set to expire")
                elif policy.get('MaxPasswordAge', 0) > 90:
                    issues.append(f"Maximum password age is greater than 90 days ({policy.get('MaxPasswordAge')})")
                
                if issues:
                    resource = Resource(
                        id="account_password_policy",
                        name="Account Password Policy",
                        type="iam_password_policy",
                        region="global",
                        arn=f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:account-password-policy"
                    )
                    
                    remediation_steps = [
                        RemediationStep(
                            title="Update password policy",
                            description="Update the account password policy to meet security best practices.",
                            code="aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24 --max-password-age 90",
                            code_language="bash"
                        )
                    ]
                    
                    remediation = Remediation(
                        summary="Strengthen IAM password policy",
                        description="The IAM password policy should be configured to enforce strong passwords. This includes requiring a minimum length, complexity, preventing reuse, and ensuring passwords expire regularly.",
                        steps=remediation_steps,
                        difficulty=RemediationDifficulty.EASY,
                        links=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                        ]
                    )
                    
                    framework_mappings = [
                        FrameworkMapping(
                            framework="MITRE ATT&CK",
                            id="T1552",
                            name="Unsecured Credentials",
                            url="https://attack.mitre.org/techniques/T1552/"
                        ),
                        FrameworkMapping(
                            framework="CWE",
                            id="CWE-521",
                            name="Weak Password Requirements",
                            url="https://cwe.mitre.org/data/definitions/521.html"
                        )
                    ]
                    
                    finding = Finding(
                        title="IAM Password Policy Does Not Meet Security Best Practices",
                        description=f"The AWS account password policy does not meet security best practices. The following issues were identified: {', '.join(issues)}.",
                        provider="aws",
                        service="iam",
                        severity=Severity.MEDIUM,
                        resources=[resource],
                        remediation=remediation,
                        framework_mappings=framework_mappings,
                        tags={"password_policy", "iam", "authentication"}
                    )
                    
                    finding.calculate_risk_score()
                    findings.append(finding)
            
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    # No password policy is configured
                    resource = Resource(
                        id="account_password_policy",
                        name="Account Password Policy",
                        type="iam_password_policy",
                        region="global",
                        arn=f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:account-password-policy"
                    )
                    
                    remediation_steps = [
                        RemediationStep(
                            title="Create password policy",
                            description="Create an account password policy that meets security best practices.",
                            code="aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24 --max-password-age 90",
                            code_language="bash"
                        )
                    ]
                    
                    remediation = Remediation(
                        summary="Create IAM password policy",
                        description="No IAM password policy is configured for this account. A password policy should be created to enforce strong passwords, including minimum length, complexity, preventing reuse, and ensuring passwords expire regularly.",
                        steps=remediation_steps,
                        difficulty=RemediationDifficulty.EASY,
                        links=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                        ]
                    )
                    
                    framework_mappings = [
                        FrameworkMapping(
                            framework="MITRE ATT&CK",
                            id="T1552",
                            name="Unsecured Credentials",
                            url="https://attack.mitre.org/techniques/T1552/"
                        ),
                        FrameworkMapping(
                            framework="CWE",
                            id="CWE-521",
                            name="Weak Password Requirements",
                            url="https://cwe.mitre.org/data/definitions/521.html"
                        )
                    ]
                    
                    finding = Finding(
                        title="No IAM Password Policy Configured",
                        description="The AWS account does not have a password policy configured. This means that password complexity and rotation requirements are not enforced, potentially allowing weak passwords.",
                        provider="aws",
                        service="iam",
                        severity=Severity.HIGH,
                        resources=[resource],
                        remediation=remediation,
                        framework_mappings=framework_mappings,
                        tags={"password_policy", "iam", "authentication"}
                    )
                    
                    finding.calculate_risk_score()
                    findings.append(finding)
                else:
                    logger.error(f"Error checking password policy: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error checking password policy: {str(e)}")
        
        return findings

    async def _check_root_access_keys(self) -> List[Finding]:
        """Check if the root user has access keys.

        Returns:
            List of findings related to root access keys
        """
        findings = []
        try:
            # Check if root user has access keys
            response = self.iam_client.get_account_summary()
            if response.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0) > 0:
                resource = Resource(
                    id="root_user",
                    name="Root User",
                    type="iam_user",
                    region="global",
                    arn=f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:root"
                )
                
                remediation_steps = [
                    RemediationStep(
                        title="Delete root access keys",
                        description="Access the AWS console with the root user and delete any access keys.",
                        code="# This must be done manually through the AWS console\n# 1. Log in as the root user\n# 2. Go to IAM > Security credentials\n# 3. Under 'Access keys', delete any existing keys",
                        code_language="bash"
                    )
                ]
                
                remediation = Remediation(
                    summary="Remove root user access keys",
                    description="The root user should not have access keys. Access keys for the root user provide unrestricted access to all resources in the account and cannot be limited by IAM policies.",
                    steps=remediation_steps,
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials"
                    ]
                )
                
                framework_mappings = [
                    FrameworkMapping(
                        framework="MITRE ATT&CK",
                        id="T1552",
                        name="Unsecured Credentials",
                        url="https://attack.mitre.org/techniques/T1552/"
                    ),
                    FrameworkMapping(
                        framework="CWE",
                        id="CWE-287",
                        name="Improper Authentication",
                        url="https://cwe.mitre.org/data/definitions/287.html"
                    )
                ]
                
                finding = Finding(
                    title="Root User Has Access Keys",
                    description="The AWS account root user has access keys. This is a security risk as the root user has unrestricted access to all resources in the account. Root user access keys should be deleted and IAM users with appropriate permissions should be used instead.",
                    provider="aws",
                    service="iam",
                    severity=Severity.CRITICAL,
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"root_user", "iam", "authentication", "access_keys"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error checking root access keys: {str(e)}")
        
        return findings

    async def _check_mfa_for_console_users(self) -> List[Finding]:
        """Check if users with console access have MFA enabled.

        Returns:
            List of findings related to MFA
        """
        findings = []
        try:
            # Get all users
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    username = user.get('UserName')
                    
                    # Skip checking for MFA if user doesn't have console access
                    try:
                        login_profile = self.iam_client.get_login_profile(UserName=username)
                        has_console_access = True
                    except botocore.exceptions.ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchEntity':
                            has_console_access = False
                        else:
                            logger.error(f"Error checking login profile for user {username}: {str(e)}")
                            continue
                    
                    if has_console_access:
                        # Check if MFA is enabled
                        mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                        if not mfa_devices.get('MFADevices', []):
                            resource = Resource(
                                id=user.get('UserId'),
                                name=username,
                                type="iam_user",
                                region="global",
                                arn=user.get('Arn')
                            )
                            
                            remediation_steps = [
                                RemediationStep(
                                    title="Enable MFA for user",
                                    description=f"Enable MFA for IAM user {username}.",
                                    code=f"# User must log in to the AWS console and enable MFA under IAM > Security credentials\n# Or you can use the CLI:\naws iam enable-mfa-device --user-name {username} --serial-number arn:aws:iam::{{account_id}}:mfa/{username} --authentication-code1 {{code1}} --authentication-code2 {{code2}}",
                                    code_language="bash"
                                )
                            ]
                            
                            remediation = Remediation(
                                summary="Enable MFA for IAM user",
                                description="All IAM users with console access should have MFA enabled to provide an additional layer of security. MFA adds an extra authentication factor, requiring a physical or virtual device to generate a one-time code.",
                                steps=remediation_steps,
                                difficulty=RemediationDifficulty.EASY,
                                links=[
                                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
                                ]
                            )
                            
                            framework_mappings = [
                                FrameworkMapping(
                                    framework="MITRE ATT&CK",
                                    id="T1078",
                                    name="Valid Accounts",
                                    url="https://attack.mitre.org/techniques/T1078/"
                                ),
                                FrameworkMapping(
                                    framework="CWE",
                                    id="CWE-308",
                                    name="Use of Single-factor Authentication",
                                    url="https://cwe.mitre.org/data/definitions/308.html"
                                )
                            ]
                            
                            finding = Finding(
                                title=f"IAM User {username} Does Not Have MFA Enabled",
                                description=f"The IAM user {username} has console access but does not have MFA enabled. Without MFA, the user's account is more susceptible to password attacks.",
                                provider="aws",
                                service="iam",
                                severity=Severity.HIGH,
                                resources=[resource],
                                remediation=remediation,
                                framework_mappings=framework_mappings,
                                tags={"mfa", "iam", "authentication"}
                            )
                            
                            finding.calculate_risk_score()
                            findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error checking MFA for console users: {str(e)}")
        
        return findings

    async def _check_unused_credentials(self) -> List[Finding]:
        """Check for unused credentials (access keys and passwords).

        Returns:
            List of findings related to unused credentials
        """
        findings = []
        try:
            # Get credential report
            try:
                response = self.iam_client.generate_credential_report()
                response = self.iam_client.get_credential_report()
                report = response['Content'].decode('utf-8').split('\n')
                
                headers = report[0].split(',')
                for line in report[1:]:
                    if not line:
                        continue
                    
                    user_data = dict(zip(headers, line.split(',')))
                    username = user_data.get('user')
                    
                    # Skip root user, we handle it separately
                    if username == '<root_account>':
                        continue
                    
                    # Check for unused passwords
                    if user_data.get('password_enabled') == 'true':
                        if user_data.get('password_last_used') == 'no_information' or user_data.get('password_last_used') == 'N/A':
                            # Password has never been used
                            resource = Resource(
                                id=username,
                                name=username,
                                type="iam_user",
                                region="global",
                                arn=f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:user/{username}"
                            )
                            
                            remediation_steps = [
                                RemediationStep(
                                    title="Disable unused password",
                                    description=f"Remove console access for user {username} if it's not needed.",
                                    code=f"aws iam delete-login-profile --user-name {username}",
                                    code_language="bash"
                                )
                            ]
                            
                            remediation = Remediation(
                                summary="Remove unused console access",
                                description="IAM users with unused passwords should have their console access removed to reduce the attack surface.",
                                steps=remediation_steps,
                                difficulty=RemediationDifficulty.EASY,
                                links=[
                                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html"
                                ]
                            )
                            
                            framework_mappings = [
                                FrameworkMapping(
                                    framework="MITRE ATT&CK",
                                    id="T1078",
                                    name="Valid Accounts",
                                    url="https://attack.mitre.org/techniques/T1078/"
                                ),
                                FrameworkMapping(
                                    framework="CWE",
                                    id="CWE-262",
                                    name="Not Using Password Aging",
                                    url="https://cwe.mitre.org/data/definitions/262.html"
                                )
                            ]
                            
                            finding = Finding(
                                title=f"IAM User {username} Has Unused Console Password",
                                description=f"The IAM user {username} has console access (password enabled) but has never logged in. Unused credentials should be removed to reduce the attack surface.",
                                provider="aws",
                                service="iam",
                                severity=Severity.MEDIUM,
                                resources=[resource],
                                remediation=remediation,
                                framework_mappings=framework_mappings,
                                tags={"unused_credentials", "iam", "authentication"}
                            )
                            
                            finding.calculate_risk_score()
                            findings.append(finding)
                    
                    # Check for unused access keys
                    for key_num in ['1', '2']:
                        if user_data.get(f'access_key_{key_num}_active') == 'true':
                            if user_data.get(f'access_key_{key_num}_last_used_date') == 'N/A':
                                # Access key has never been used
                                resource = Resource(
                                    id=username,
                                    name=username,
                                    type="iam_user",
                                    region="global",
                                    arn=f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:user/{username}"
                                )
                                
                                remediation_steps = [
                                    RemediationStep(
                                        title="Deactivate unused access key",
                                        description=f"Deactivate the unused access key {key_num} for user {username}.",
                                        code=f"aws iam update-access-key --user-name {username} --access-key-id ACCESS_KEY_ID --status Inactive",
                                        code_language="bash"
                                    ),
                                    RemediationStep(
                                        title="Delete unused access key",
                                        description=f"Once verified that the key is not needed, delete it.",
                                        code=f"aws iam delete-access-key --user-name {username} --access-key-id ACCESS_KEY_ID",
                                        code_language="bash"
                                    )
                                ]
                                
                                remediation = Remediation(
                                    summary="Remove unused access keys",
                                    description="IAM users with unused access keys should have those keys deactivated or deleted to reduce the attack surface.",
                                    steps=remediation_steps,
                                    difficulty=RemediationDifficulty.EASY,
                                    links=[
                                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                                    ]
                                )
                                
                                framework_mappings = [
                                    FrameworkMapping(
                                        framework="MITRE ATT&CK",
                                        id="T1552",
                                        name="Unsecured Credentials",
                                        url="https://attack.mitre.org/techniques/T1552/"
                                    ),
                                    FrameworkMapping(
                                        framework="CWE",
                                        id="CWE-295",
                                        name="Certificate Renewal or Revocation",
                                        url="https://cwe.mitre.org/data/definitions/295.html"
                                    )
                                ]
                                
                                finding = Finding(
                                    title=f"IAM User {username} Has Unused Access Key {key_num}",
                                    description=f"The IAM user {username} has an active access key (key {key_num}) that has never been used. Unused credentials should be removed to reduce the attack surface.",
                                    provider="aws",
                                    service="iam",
                                    severity=Severity.MEDIUM,
                                    resources=[resource],
                                    remediation=remediation,
                                    framework_mappings=framework_mappings,
                                    tags={"unused_credentials", "iam", "access_keys"}
                                )
                                
                                finding.calculate_risk_score()
                                findings.append(finding)
            
            except botocore.exceptions.ClientError as e:
                logger.error(f"Error getting credential report: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error checking unused credentials: {str(e)}")
        
        return findings

    async def _check_excessive_permissions(self) -> List[Finding]:
        """Check for users or roles with excessive permissions.

        Returns:
            List of findings related to excessive permissions
        """
        findings = []
        try:
            # This is a simplified version - in a real scanner this would be more sophisticated
            # Check for users with AdministratorAccess policy
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    username = user.get('UserName')
                    
                    # Get attached policies
                    attached_policies = self.iam_client.list_attached_user_policies(UserName=username)
                    
                    for policy in attached_policies.get('AttachedPolicies', []):
                        if policy.get('PolicyName') == 'AdministratorAccess':
                            resource = Resource(
                                id=user.get('UserId'),
                                name=username,
                                type="iam_user",
                                region="global",
                                arn=user.get('Arn')
                            )
                            
                            remediation_steps = [
                                RemediationStep(
                                    title="Review and restrict permissions",
                                    description=f"Review the permissions needed by user {username} and replace the AdministratorAccess policy with more specific policies.",
                                    code=f"# Detach the AdministratorAccess policy\naws iam detach-user-policy --user-name {username} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n# Attach more specific policies as needed\n# aws iam attach-user-policy --user-name {username} --policy-arn POLICY_ARN",
                                    code_language="bash"
                                )
                            ]
                            
                            remediation = Remediation(
                                summary="Implement least privilege for IAM user",
                                description="IAM users should be granted least privilege access, with only the permissions required to perform their tasks. The AdministratorAccess policy grants full access to all AWS services and resources.",
                                steps=remediation_steps,
                                difficulty=RemediationDifficulty.MODERATE,
                                links=[
                                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                                ]
                            )
                            
                            framework_mappings = [
                                FrameworkMapping(
                                    framework="MITRE ATT&CK",
                                    id="T1078",
                                    name="Valid Accounts",
                                    url="https://attack.mitre.org/techniques/T1078/"
                                ),
                                FrameworkMapping(
                                    framework="CWE",
                                    id="CWE-272",
                                    name="Least Privilege Violation",
                                    url="https://cwe.mitre.org/data/definitions/272.html"
                                )
                            ]
                            
                            finding = Finding(
                                title=f"IAM User {username} Has Administrator Permissions",
                                description=f"The IAM user {username} has the AdministratorAccess policy attached, which grants full access to all AWS services and resources. This violates the principle of least privilege and could lead to accidental or malicious misuse of resources.",
                                provider="aws",
                                service="iam",
                                severity=Severity.HIGH,
                                resources=[resource],
                                remediation=remediation,
                                framework_mappings=framework_mappings,
                                tags={"least_privilege", "iam", "administrator"}
                            )
                            
                            finding.calculate_risk_score()
                            findings.append(finding)
                            break
        
        except Exception as e:
            logger.error(f"Error checking excessive permissions: {str(e)}")
        
        return findings 