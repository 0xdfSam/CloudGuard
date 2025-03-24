"""
IAM service scanner implementation for AWS.

This module provides functionality to scan IAM resources for security issues.
"""

import logging
from typing import Dict, List, Set, Any, Optional

import boto3
from botocore.exceptions import ClientError

from cloudguard.core.findings import Finding, Severity, Resource, Remediation, RemediationStep, RemediationDifficulty
from cloudguard.providers.aws.scanner import AwsServiceScanner
from cloudguard.frameworks.mapping import get_framework_mappings_from_tags
from cloudguard.utils.logger import get_logger

logger = get_logger(__name__)

class IamScanner(AwsServiceScanner):
    """Scanner for AWS IAM service to detect security issues."""

    service_name = "iam"

    def __init__(self, session: boto3.Session, region: str):
        """Initialize the IAM scanner with AWS session and region.

        Args:
            session: boto3 Session object
            region: AWS region name
        """
        super().__init__(session, region)
        self.iam_client = session.client('iam')

    def scan(self) -> List[Finding]:
        """Scan IAM resources for security issues.

        Returns:
            List of findings detected during the scan
        """
        findings = []
        logger.info("Scanning IAM resources for security issues")

        try:
            # Check for root account access keys
            findings.extend(self._check_root_access_keys())
            
            # Check IAM users for security issues
            findings.extend(self._check_iam_users())
            
            # Check IAM policies for security issues
            findings.extend(self._check_iam_policies())
            
            # Check password policy
            findings.extend(self._check_password_policy())
            
            # Check MFA on root account
            findings.extend(self._check_root_mfa())

            logger.info(f"IAM scan completed, found {len(findings)} issues")
            return findings
        except ClientError as e:
            logger.error(f"Error scanning IAM resources: {str(e)}")
            return []

    def get_resources(self) -> List[Dict[str, Any]]:
        """Get IAM resources.

        Returns:
            List of IAM resources with their details
        """
        resources = []
        
        try:
            # Get IAM users
            users = self.iam_client.list_users()
            for user in users.get('Users', []):
                user_resource = {
                    'id': user.get('UserId'),
                    'name': user.get('UserName'),
                    'arn': user.get('Arn'),
                    'resource_type': 'iam_user',
                    'created_date': user.get('CreateDate'),
                    'tags': self._get_resource_tags('user', user.get('UserName'))
                }
                resources.append(user_resource)
            
            # Get IAM roles
            roles = self.iam_client.list_roles()
            for role in roles.get('Roles', []):
                role_resource = {
                    'id': role.get('RoleId'),
                    'name': role.get('RoleName'),
                    'arn': role.get('Arn'),
                    'resource_type': 'iam_role',
                    'created_date': role.get('CreateDate'),
                    'tags': self._get_resource_tags('role', role.get('RoleName'))
                }
                resources.append(role_resource)
            
            # Get IAM policies
            policies = self.iam_client.list_policies(Scope='Local')
            for policy in policies.get('Policies', []):
                policy_resource = {
                    'id': policy.get('PolicyId'),
                    'name': policy.get('PolicyName'),
                    'arn': policy.get('Arn'),
                    'resource_type': 'iam_policy',
                    'created_date': policy.get('CreateDate'),
                    'tags': self._get_resource_tags('policy', policy.get('PolicyArn'))
                }
                resources.append(policy_resource)
            
            return resources
        except ClientError as e:
            logger.error(f"Error retrieving IAM resources: {str(e)}")
            return []

    def get_service_tags(self) -> Set[str]:
        """Get tags specific to IAM service.

        Returns:
            Set of tags for IAM service
        """
        return {"aws", "iam", "identity", "access", "security"}

    def _get_resource_tags(self, resource_type: str, resource_id: str) -> Dict[str, str]:
        """Get tags for an IAM resource.

        Args:
            resource_type: Type of IAM resource ('user', 'role', or 'policy')
            resource_id: ID or name of the resource

        Returns:
            Dictionary of resource tags
        """
        try:
            if resource_type == 'user':
                response = self.iam_client.list_user_tags(UserName=resource_id)
                return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
            elif resource_type == 'role':
                response = self.iam_client.list_role_tags(RoleName=resource_id)
                return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
            elif resource_type == 'policy':
                response = self.iam_client.list_policy_tags(PolicyArn=resource_id)
                return {tag['Key']: tag['Value'] for tag in response.get('Tags', [])}
            return {}
        except ClientError as e:
            logger.error(f"Error retrieving tags for {resource_type} {resource_id}: {str(e)}")
            return {}

    def _check_root_access_keys(self) -> List[Finding]:
        """Check if root account has access keys.

        Returns:
            List of findings related to root access keys
        """
        findings = []
        try:
            # Get account summary to check root access keys
            account_summary = self.iam_client.get_account_summary()
            if account_summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0) > 0:
                finding = Finding(
                    title="Root account has active access keys",
                    description="The root account has access keys. This is a security risk as the root account has unlimited privileges.",
                    severity=Severity.CRITICAL,
                    resource_id="ROOT_ACCOUNT",
                    resource_type="iam_user",
                    service="iam",
                    region=self.region,
                    risk_score=RiskScore.CRITICAL,
                    remediation_steps=[
                        "1. Create an IAM user with administrative privileges",
                        "2. Delete the root account access keys",
                        "3. Use IAM users for all AWS operations"
                    ],
                    compliance={
                        "CIS AWS Foundations": "1.4",
                        "AWS Well-Architected Framework": "SEC02-BP01"
                    }
                )
                findings.append(finding)
        except ClientError as e:
            logger.error(f"Error checking root access keys: {str(e)}")
        return findings

    def _check_iam_users(self) -> List[Finding]:
        """Check IAM users for security issues.

        Returns:
            List of findings related to IAM users
        """
        findings = []
        try:
            users = self.iam_client.list_users().get('Users', [])
            
            for user in users:
                username = user.get('UserName')
                
                # Check for console access without MFA
                try:
                    login_profile = self.iam_client.get_login_profile(UserName=username)
                    # If we get here, the user has console access
                    
                    # Check if MFA is enabled
                    mfa_devices = self.iam_client.list_mfa_devices(UserName=username)
                    if not mfa_devices.get('MFADevices'):
                        finding = Finding(
                            title=f"IAM user {username} has console access without MFA",
                            description=f"The IAM user {username} has console access but does not have MFA enabled. This is a security risk.",
                            severity=Severity.HIGH,
                            resource_id=username,
                            resource_type="iam_user",
                            service="iam",
                            region=self.region,
                            risk_score=RiskScore.HIGH,
                            remediation_steps=[
                                f"1. Enable MFA for the IAM user {username}",
                                "2. Configure an MFA device for the user",
                                "3. Make MFA mandatory for all users through an IAM policy"
                            ],
                            compliance={
                                "CIS AWS Foundations": "1.2",
                                "AWS Well-Architected Framework": "SEC02-BP02"
                            }
                        )
                        findings.append(finding)
                except ClientError:
                    # User doesn't have console access, skip MFA check
                    pass
                
                # Check for access keys older than 90 days
                access_keys = self.iam_client.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                for key in access_keys:
                    if key.get('Status') == 'Active':
                        # Calculate age in days
                        import datetime
                        now = datetime.datetime.now(datetime.timezone.utc)
                        create_date = key.get('CreateDate')
                        age_in_days = (now - create_date).days
                        
                        if age_in_days > 90:
                            finding = Finding(
                                title=f"IAM user {username} has access key older than 90 days",
                                description=f"The IAM user {username} has an access key that is {age_in_days} days old. Access keys should be rotated regularly.",
                                severity=Severity.MEDIUM,
                                resource_id=username,
                                resource_type="iam_user",
                                service="iam",
                                region=self.region,
                                risk_score=RiskScore.MEDIUM,
                                remediation_steps=[
                                    f"1. Create a new access key for user {username}",
                                    "2. Update applications to use the new key",
                                    f"3. Deactivate and then delete the old access key for user {username}",
                                    "4. Implement a key rotation policy"
                                ],
                                compliance={
                                    "CIS AWS Foundations": "1.3",
                                    "AWS Well-Architected Framework": "SEC02-BP03"
                                }
                            )
                            findings.append(finding)
        except ClientError as e:
            logger.error(f"Error checking IAM users: {str(e)}")
        return findings

    def _check_iam_policies(self) -> List[Finding]:
        """Check IAM policies for security issues.

        Returns:
            List of findings related to IAM policies
        """
        findings = []
        try:
            # Get customer managed policies
            policies = self.iam_client.list_policies(Scope='Local').get('Policies', [])
            
            for policy in policies:
                policy_arn = policy.get('Arn')
                policy_name = policy.get('PolicyName')
                
                # Get policy version details
                policy_version = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy.get('DefaultVersionId')
                )
                
                policy_document = policy_version.get('PolicyVersion', {}).get('Document', {})
                
                # Check for overly permissive policies (wildcard actions with wildcard resources)
                if self._has_admin_privilege(policy_document):
                    finding = Finding(
                        title=f"Policy {policy_name} has administrator privileges",
                        description=f"The IAM policy {policy_name} has administrator privileges. This policy grants excessive permissions.",
                        severity=Severity.HIGH,
                        resource_id=policy_name,
                        resource_type="iam_policy",
                        service="iam",
                        region=self.region,
                        risk_score=RiskScore.HIGH,
                        remediation_steps=[
                            f"1. Review the permissions in policy {policy_name}",
                            "2. Apply the principle of least privilege",
                            "3. Replace wildcard permissions with specific actions and resources",
                            "4. Create separate policies for different roles/needs"
                        ],
                        compliance={
                            "CIS AWS Foundations": "1.16",
                            "AWS Well-Architected Framework": "SEC02-BP06"
                        }
                    )
                    findings.append(finding)
        except ClientError as e:
            logger.error(f"Error checking IAM policies: {str(e)}")
        return findings

    def _has_admin_privilege(self, policy_document: Dict) -> bool:
        """Check if a policy has administrator privileges.

        Args:
            policy_document: IAM policy document

        Returns:
            True if the policy has admin privileges, False otherwise
        """
        for statement in policy_document.get('Statement', []):
            effect = statement.get('Effect')
            action = statement.get('Action')
            resource = statement.get('Resource')
            
            # Check for "*" in both action and resource
            if effect == 'Allow':
                if action == '*' and resource == '*':
                    return True
                elif isinstance(action, list) and '*' in action and resource == '*':
                    return True
        return False

    def _check_password_policy(self) -> List[Finding]:
        """Check account password policy for security issues.

        Returns:
            List of findings related to password policy
        """
        findings = []
        try:
            try:
                policy = self.iam_client.get_account_password_policy().get('PasswordPolicy', {})
            except ClientError as e:
                if "NoSuchEntity" in str(e):
                    # No password policy set
                    finding = Finding(
                        title="No account password policy set",
                        description="The AWS account does not have a password policy set. This means default password policy is in effect, which is less secure.",
                        severity=Severity.HIGH,
                        resource_id="PASSWORD_POLICY",
                        resource_type="iam_password_policy",
                        service="iam",
                        region=self.region,
                        risk_score=RiskScore.HIGH,
                        remediation_steps=[
                            "1. Create a strong password policy",
                            "2. Set minimum password length to at least 14 characters",
                            "3. Require at least one uppercase letter, lowercase letter, number, and symbol",
                            "4. Enable password expiration (90 days or less)",
                            "5. Prevent password reuse (remember at least 24 passwords)"
                        ],
                        compliance={
                            "CIS AWS Foundations": "1.5-1.11",
                            "AWS Well-Architected Framework": "SEC02-BP04"
                        }
                    )
                    findings.append(finding)
                    return findings
                else:
                    raise
            
            # Check minimum password length
            if not policy.get('MinimumPasswordLength', 0) >= 14:
                finding = Finding(
                    title="Password policy minimum length too short",
                    description=f"The password policy minimum length is set to {policy.get('MinimumPasswordLength', 0)} characters. Should be at least 14 characters.",
                    severity=Severity.MEDIUM,
                    resource_id="PASSWORD_POLICY",
                    resource_type="iam_password_policy",
                    service="iam",
                    region=self.region,
                    risk_score=RiskScore.MEDIUM,
                    remediation_steps=[
                        "1. Update the password policy to require at least 14 characters"
                    ],
                    compliance={
                        "CIS AWS Foundations": "1.8",
                        "AWS Well-Architected Framework": "SEC02-BP04"
                    }
                )
                findings.append(finding)
            
            # Check password reuse
            if not policy.get('PasswordReusePrevention', 0) >= 24:
                finding = Finding(
                    title="Password reuse prevention policy too weak",
                    description=f"The password policy prevents reuse of the last {policy.get('PasswordReusePrevention', 0)} passwords. Should prevent reuse of at least 24 passwords.",
                    severity=Severity.LOW,
                    resource_id="PASSWORD_POLICY",
                    resource_type="iam_password_policy",
                    service="iam",
                    region=self.region,
                    risk_score=RiskScore.LOW,
                    remediation_steps=[
                        "1. Update the password policy to prevent reuse of at least 24 passwords"
                    ],
                    compliance={
                        "CIS AWS Foundations": "1.10",
                        "AWS Well-Architected Framework": "SEC02-BP04"
                    }
                )
                findings.append(finding)
            
            # Check password expiration
            if not policy.get('MaxPasswordAge', 0) <= 90 and policy.get('MaxPasswordAge', 0) > 0:
                finding = Finding(
                    title="Password expiration policy too long",
                    description=f"The password expiration policy is set to {policy.get('MaxPasswordAge', 0)} days. Should be 90 days or less.",
                    severity=Severity.LOW,
                    resource_id="PASSWORD_POLICY",
                    resource_type="iam_password_policy",
                    service="iam",
                    region=self.region,
                    risk_score=RiskScore.LOW,
                    remediation_steps=[
                        "1. Update the password policy to expire passwords after 90 days or less"
                    ],
                    compliance={
                        "CIS AWS Foundations": "1.11",
                        "AWS Well-Architected Framework": "SEC02-BP04"
                    }
                )
                findings.append(finding)
        except ClientError as e:
            logger.error(f"Error checking password policy: {str(e)}")
        return findings

    def _check_root_mfa(self) -> List[Finding]:
        """Check if MFA is enabled for root account.

        Returns:
            List of findings related to root MFA
        """
        findings = []
        try:
            # Get account summary to check root MFA
            account_summary = self.iam_client.get_account_summary()
            if not account_summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0):
                finding = Finding(
                    title="Root account does not have MFA enabled",
                    description="The root account does not have MFA enabled. This is a critical security risk.",
                    severity=Severity.CRITICAL,
                    resource_id="ROOT_ACCOUNT",
                    resource_type="iam_user",
                    service="iam",
                    region=self.region,
                    risk_score=RiskScore.CRITICAL,
                    remediation_steps=[
                        "1. Log in to the AWS Management Console as the root user",
                        "2. Navigate to the IAM dashboard",
                        "3. Select 'Security credentials'",
                        "4. In the 'Multi-factor authentication (MFA)' section, choose 'Activate MFA'",
                        "5. Complete the MFA device setup process"
                    ],
                    compliance={
                        "CIS AWS Foundations": "1.5",
                        "AWS Well-Architected Framework": "SEC02-BP01"
                    }
                )
                findings.append(finding)
        except ClientError as e:
            logger.error(f"Error checking root MFA: {str(e)}")
        return findings

    def get_client_name(self) -> str:
        """Get the name of the boto3 client to use.
        
        Returns:
            Boto3 client name
        """
        return "iam"
    
    def is_global_service(self) -> bool:
        """Determine if this is a global service.
        
        Returns:
            True as IAM is a global service
        """
        return True 