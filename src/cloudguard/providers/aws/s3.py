"""AWS S3 bucket scanner implementation."""

import asyncio
import logging
from typing import Dict, List, Optional, Set

import boto3
import botocore.exceptions

from ...core.findings import Finding, FrameworkMapping, Remediation, RemediationDifficulty, RemediationStep, Resource, Severity
from ...utils.config import AwsConfig

logger = logging.getLogger(__name__)


class S3Scanner:
    """Scanner for AWS S3 service."""

    def __init__(self, sessions: Dict[str, boto3.Session], config: AwsConfig):
        """Initialize the S3 scanner.

        Args:
            sessions: Map of region to boto3 Session
            config: AWS configuration
        """
        self.sessions = sessions
        self.config = config

    async def scan(self) -> List[Finding]:
        """Scan S3 buckets for security issues.

        Returns:
            List of findings related to S3 buckets
        """
        logger.info("Starting S3 bucket security scan")
        findings = []

        # Run checks for each region concurrently
        tasks = []
        for region, session in self.sessions.items():
            tasks.append(self._scan_region(region, session))
        
        region_findings = await asyncio.gather(*tasks)
        
        # Flatten results
        for region_result in region_findings:
            findings.extend(region_result)
        
        logger.info(f"S3 scan complete. Found {len(findings)} issues.")
        return findings

    async def get_resources(self) -> Dict[str, List[Dict]]:
        """Get S3 resources from AWS.

        Returns:
            Dictionary with S3 bucket resources
        """
        resources = {"s3_buckets": []}
        
        for region, session in self.sessions.items():
            try:
                s3_client = session.client('s3')
                response = s3_client.list_buckets()
                
                for bucket in response.get('Buckets', []):
                    # Get bucket location
                    try:
                        location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                        bucket_region = location.get('LocationConstraint', 'us-east-1') or 'us-east-1'
                    except Exception:
                        bucket_region = 'unknown'
                    
                    resources["s3_buckets"].append({
                        "name": bucket['Name'],
                        "creation_date": bucket['CreationDate'].isoformat() if 'CreationDate' in bucket else None,
                        "region": bucket_region
                    })
            except Exception as e:
                logger.error(f"Error getting S3 resources in region {region}: {str(e)}")
        
        return resources

    async def _scan_region(self, region: str, session: boto3.Session) -> List[Finding]:
        """Scan S3 buckets in a specific region.

        Args:
            region: AWS region name
            session: boto3 Session for the region

        Returns:
            List of findings for the region
        """
        findings = []
        try:
            s3_client = session.client('s3')
            
            # Get all buckets
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            # Check each bucket
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Only scan buckets in the current region or all regions if not region-specific
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket_name)
                    bucket_region = location.get('LocationConstraint', 'us-east-1') or 'us-east-1'
                    
                    # Skip buckets not in this region unless we're in the bucket's region
                    if bucket_region != region and region != 'us-east-1':
                        continue
                    
                    # Check public access settings
                    public_access_findings = await self._check_public_access(s3_client, bucket_name, region)
                    findings.extend(public_access_findings)
                    
                    # Check encryption settings
                    encryption_findings = await self._check_encryption(s3_client, bucket_name, region)
                    findings.extend(encryption_findings)
                    
                    # Check bucket policy
                    policy_findings = await self._check_bucket_policy(s3_client, bucket_name, region)
                    findings.extend(policy_findings)
                    
                    # Check logging configuration
                    logging_findings = await self._check_logging(s3_client, bucket_name, region)
                    findings.extend(logging_findings)
                    
                except botocore.exceptions.ClientError as e:
                    logger.warning(f"Error checking bucket {bucket_name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error scanning S3 in region {region}: {str(e)}")
        
        return findings

    async def _check_public_access(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if the bucket has public access.

        Args:
            s3_client: boto3 S3 client
            bucket_name: Name of the bucket to check
            region: AWS region

        Returns:
            List of findings related to public access
        """
        findings = []
        try:
            # Check bucket ACL
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            public_acl = False
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    public_acl = True
                    break
            
            if public_acl:
                resource = Resource(
                    id=bucket_name,
                    name=bucket_name,
                    type="s3_bucket",
                    region=region,
                    arn=f"arn:aws:s3:::{bucket_name}"
                )
                
                # Create remediation steps
                remediation_steps = [
                    RemediationStep(
                        title="Remove public access grants from bucket ACL",
                        description="Use the AWS CLI or Console to remove public access grants from the bucket ACL.",
                        code=f"aws s3api put-bucket-acl --bucket {bucket_name} --acl private",
                        code_language="bash"
                    ),
                    RemediationStep(
                        title="Enable bucket public access block",
                        description="Block all public access to the bucket using the public access block feature.",
                        code=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                        code_language="bash"
                    )
                ]
                
                remediation = Remediation(
                    summary="Remove public access to S3 bucket",
                    description="S3 buckets should not allow public access unless strictly necessary for specific use cases. Public buckets can lead to data exposure and unauthorized access to your data.",
                    steps=remediation_steps,
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                        "https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/"
                    ]
                )
                
                # Framework mappings
                framework_mappings = [
                    FrameworkMapping(
                        framework="MITRE ATT&CK",
                        id="T1530",
                        name="Data from Cloud Storage",
                        url="https://attack.mitre.org/techniques/T1530/"
                    ),
                    FrameworkMapping(
                        framework="CWE",
                        id="CWE-284",
                        name="Improper Access Control",
                        url="https://cwe.mitre.org/data/definitions/284.html"
                    )
                ]
                
                finding = Finding(
                    title="S3 Bucket Has Public Access Configured via ACL",
                    description=f"The S3 bucket '{bucket_name}' has public access configured through its ACL. This allows anyone on the internet to access the bucket and its contents, which may lead to data exposure.",
                    provider="aws",
                    service="s3",
                    severity=Severity.HIGH,
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"public_access", "s3", "data_exposure"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
            
            # Check public access block configuration
            try:
                public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                config = public_access_block.get('PublicAccessBlockConfiguration', {})
                
                if not all([
                    config.get('BlockPublicAcls', False),
                    config.get('IgnorePublicAcls', False),
                    config.get('BlockPublicPolicy', False),
                    config.get('RestrictPublicBuckets', False)
                ]):
                    resource = Resource(
                        id=bucket_name,
                        name=bucket_name,
                        type="s3_bucket",
                        region=region,
                        arn=f"arn:aws:s3:::{bucket_name}"
                    )
                    
                    remediation_steps = [
                        RemediationStep(
                            title="Enable all public access block settings",
                            description="Enable all four public access block settings to prevent public access to the bucket.",
                            code=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                            code_language="bash"
                        )
                    ]
                    
                    remediation = Remediation(
                        summary="Enable all S3 public access block settings",
                        description="S3 buckets should have all public access block settings enabled to provide multiple layers of protection against unintentional public access.",
                        steps=remediation_steps,
                        difficulty=RemediationDifficulty.EASY,
                        links=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                        ]
                    )
                    
                    framework_mappings = [
                        FrameworkMapping(
                            framework="MITRE ATT&CK",
                            id="T1530",
                            name="Data from Cloud Storage",
                            url="https://attack.mitre.org/techniques/T1530/"
                        ),
                        FrameworkMapping(
                            framework="CWE",
                            id="CWE-284",
                            name="Improper Access Control",
                            url="https://cwe.mitre.org/data/definitions/284.html"
                        )
                    ]
                    
                    finding = Finding(
                        title="S3 Bucket Has Incomplete Public Access Block Configuration",
                        description=f"The S3 bucket '{bucket_name}' does not have all public access block settings enabled. This could potentially allow public access to the bucket through various means.",
                        provider="aws",
                        service="s3",
                        severity=Severity.MEDIUM,
                        resources=[resource],
                        remediation=remediation,
                        framework_mappings=framework_mappings,
                        tags={"public_access", "s3", "data_exposure"}
                    )
                    
                    finding.calculate_risk_score()
                    findings.append(finding)
            
            except botocore.exceptions.ClientError as e:
                # If the public access block is not configured, create a finding
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    resource = Resource(
                        id=bucket_name,
                        name=bucket_name,
                        type="s3_bucket",
                        region=region,
                        arn=f"arn:aws:s3:::{bucket_name}"
                    )
                    
                    remediation_steps = [
                        RemediationStep(
                            title="Configure public access block settings",
                            description="Configure public access block settings to prevent public access to the bucket.",
                            code=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                            code_language="bash"
                        )
                    ]
                    
                    remediation = Remediation(
                        summary="Add S3 public access block configuration",
                        description="S3 buckets should have public access block settings configured to protect against unintentional public access.",
                        steps=remediation_steps,
                        difficulty=RemediationDifficulty.EASY,
                        links=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                        ]
                    )
                    
                    framework_mappings = [
                        FrameworkMapping(
                            framework="MITRE ATT&CK",
                            id="T1530",
                            name="Data from Cloud Storage",
                            url="https://attack.mitre.org/techniques/T1530/"
                        ),
                        FrameworkMapping(
                            framework="CWE",
                            id="CWE-284",
                            name="Improper Access Control",
                            url="https://cwe.mitre.org/data/definitions/284.html"
                        )
                    ]
                    
                    finding = Finding(
                        title="S3 Bucket Has No Public Access Block Configuration",
                        description=f"The S3 bucket '{bucket_name}' does not have public access block settings configured. This means the bucket could potentially be made public through bucket policies or ACLs.",
                        provider="aws",
                        service="s3",
                        severity=Severity.MEDIUM,
                        resources=[resource],
                        remediation=remediation,
                        framework_mappings=framework_mappings,
                        tags={"public_access", "s3", "data_exposure"}
                    )
                    
                    finding.calculate_risk_score()
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error checking public access for bucket {bucket_name}: {str(e)}")
        
        return findings

    async def _check_encryption(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if the bucket has default encryption enabled.

        Args:
            s3_client: boto3 S3 client
            bucket_name: Name of the bucket to check
            region: AWS region

        Returns:
            List of findings related to encryption
        """
        findings = []
        try:
            # Check default encryption
            try:
                encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                # If we get here, encryption is enabled
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    # No default encryption
                    resource = Resource(
                        id=bucket_name,
                        name=bucket_name,
                        type="s3_bucket",
                        region=region,
                        arn=f"arn:aws:s3:::{bucket_name}"
                    )
                    
                    remediation_steps = [
                        RemediationStep(
                            title="Enable default encryption",
                            description="Enable default encryption for the S3 bucket using SSE-S3 or KMS.",
                            code=f"aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'",
                            code_language="bash"
                        )
                    ]
                    
                    remediation = Remediation(
                        summary="Enable default encryption for S3 bucket",
                        description="S3 buckets should have default encryption enabled to ensure that all objects are automatically encrypted when uploaded to the bucket.",
                        steps=remediation_steps,
                        difficulty=RemediationDifficulty.EASY,
                        links=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                        ]
                    )
                    
                    framework_mappings = [
                        FrameworkMapping(
                            framework="MITRE ATT&CK",
                            id="T1530",
                            name="Data from Cloud Storage",
                            url="https://attack.mitre.org/techniques/T1530/"
                        ),
                        FrameworkMapping(
                            framework="CWE",
                            id="CWE-311",
                            name="Missing Encryption of Sensitive Data",
                            url="https://cwe.mitre.org/data/definitions/311.html"
                        )
                    ]
                    
                    finding = Finding(
                        title="S3 Bucket Missing Default Encryption",
                        description=f"The S3 bucket '{bucket_name}' does not have default encryption enabled. This means that objects uploaded to the bucket will not be automatically encrypted, potentially exposing sensitive data.",
                        provider="aws",
                        service="s3",
                        severity=Severity.MEDIUM,
                        resources=[resource],
                        remediation=remediation,
                        framework_mappings=framework_mappings,
                        tags={"encryption", "s3", "data_protection"}
                    )
                    
                    finding.calculate_risk_score()
                    findings.append(finding)
                else:
                    # Some other error
                    logger.error(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
        
        return findings

    async def _check_bucket_policy(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if the bucket has a secure bucket policy.

        Args:
            s3_client: boto3 S3 client
            bucket_name: Name of the bucket to check
            region: AWS region

        Returns:
            List of findings related to bucket policy
        """
        findings = []
        try:
            # Check bucket policy
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_json = policy.get('Policy', '{}')
                
                # Simplified policy analysis (in a real tool, this would be more comprehensive)
                if '"Effect": "Allow"' in policy_json and '"Principal": "*"' in policy_json:
                    resource = Resource(
                        id=bucket_name,
                        name=bucket_name,
                        type="s3_bucket",
                        region=region,
                        arn=f"arn:aws:s3:::{bucket_name}"
                    )
                    
                    remediation_steps = [
                        RemediationStep(
                            title="Review and update bucket policy",
                            description="Review the bucket policy and remove any statements that allow public access or restrict to specific principals.",
                            code="# Review policy with:\naws s3api get-bucket-policy --bucket {bucket_name}\n\n# Update policy with a more restrictive one",
                            code_language="bash"
                        )
                    ]
                    
                    remediation = Remediation(
                        summary="Secure S3 bucket policy",
                        description="S3 bucket policies should not allow unrestricted public access. Review and update the policy to only grant necessary permissions to specific principals.",
                        steps=remediation_steps,
                        difficulty=RemediationDifficulty.MODERATE,
                        links=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"
                        ]
                    )
                    
                    framework_mappings = [
                        FrameworkMapping(
                            framework="MITRE ATT&CK",
                            id="T1530",
                            name="Data from Cloud Storage",
                            url="https://attack.mitre.org/techniques/T1530/"
                        ),
                        FrameworkMapping(
                            framework="CWE",
                            id="CWE-284",
                            name="Improper Access Control",
                            url="https://cwe.mitre.org/data/definitions/284.html"
                        )
                    ]
                    
                    finding = Finding(
                        title="S3 Bucket Policy Allows Public Access",
                        description=f"The S3 bucket '{bucket_name}' has a policy that potentially allows public access. The policy includes an Allow effect with a wildcard principal (*), which grants permissions to anonymous users.",
                        provider="aws",
                        service="s3",
                        severity=Severity.HIGH,
                        resources=[resource],
                        remediation=remediation,
                        framework_mappings=framework_mappings,
                        tags={"public_access", "s3", "policy", "data_exposure"}
                    )
                    
                    finding.calculate_risk_score()
                    findings.append(finding)
            
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No bucket policy - this isn't necessarily a problem
                    pass
                else:
                    logger.error(f"Error checking bucket policy for {bucket_name}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error checking bucket policy for {bucket_name}: {str(e)}")
        
        return findings

    async def _check_logging(self, s3_client, bucket_name: str, region: str) -> List[Finding]:
        """Check if the bucket has logging enabled.

        Args:
            s3_client: boto3 S3 client
            bucket_name: Name of the bucket to check
            region: AWS region

        Returns:
            List of findings related to logging
        """
        findings = []
        try:
            # Check bucket logging
            logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging_config:
                # Logging is not enabled
                resource = Resource(
                    id=bucket_name,
                    name=bucket_name,
                    type="s3_bucket",
                    region=region,
                    arn=f"arn:aws:s3:::{bucket_name}"
                )
                
                remediation_steps = [
                    RemediationStep(
                        title="Enable bucket logging",
                        description="Enable access logging for the S3 bucket to track access requests.",
                        code=f"aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status '{{\"LoggingEnabled\": {{\"TargetBucket\": \"log-bucket-name\", \"TargetPrefix\": \"{bucket_name}/\"}}}}'",
                        code_language="bash"
                    )
                ]
                
                remediation = Remediation(
                    summary="Enable S3 bucket access logging",
                    description="S3 bucket access logging should be enabled to track access requests for security and audit purposes.",
                    steps=remediation_steps,
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
                    ]
                )
                
                framework_mappings = [
                    FrameworkMapping(
                        framework="MITRE ATT&CK",
                        id="T1530",
                        name="Data from Cloud Storage",
                        url="https://attack.mitre.org/techniques/T1530/"
                    ),
                    FrameworkMapping(
                        framework="CWE",
                        id="CWE-778",
                        name="Insufficient Logging",
                        url="https://cwe.mitre.org/data/definitions/778.html"
                    )
                ]
                
                finding = Finding(
                    title="S3 Bucket Logging Not Enabled",
                    description=f"The S3 bucket '{bucket_name}' does not have access logging enabled. Without logging, it's difficult to track who is accessing the bucket and what operations are being performed.",
                    provider="aws",
                    service="s3",
                    severity=Severity.LOW,
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    tags={"logging", "s3", "audit"}
                )
                
                finding.calculate_risk_score()
                findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error checking logging for bucket {bucket_name}: {str(e)}")
        
        return findings 