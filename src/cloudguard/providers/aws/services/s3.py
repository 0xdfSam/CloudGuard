"""S3 service scanner implementation."""

import uuid
import logging
from typing import Dict, List, Optional, Any, Set
import boto3
from botocore.exceptions import ClientError

from cloudguard.core.findings import Finding, Severity, Resource, Remediation, RemediationStep, RemediationDifficulty
from cloudguard.frameworks.mapping import get_framework_mappings_from_tags
from cloudguard.providers.aws.scanner import AwsServiceScanner
from cloudguard.utils.logger import get_logger

logger = get_logger(__name__)


class S3Scanner(AwsServiceScanner):
    """S3 service scanner."""
    
    service_name = "s3"
    
    def scan(self) -> List[Finding]:
        """Scan S3 buckets for security issues.
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            buckets = self.client.list_buckets()['Buckets']
            logger.info(f"Found {len(buckets)} S3 buckets")
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                logger.debug(f"Scanning bucket: {bucket_name}")
                
                # Skip excluded resources if configured
                excluded_resources = getattr(self, 'config', {}).get('excluded_resources', [])
                if bucket_name in excluded_resources:
                    logger.info(f"Skipping excluded bucket: {bucket_name}")
                    continue
                
                # Check for public access
                findings.extend(self._check_public_access(bucket_name))
                
                # Check for encryption
                findings.extend(self._check_encryption(bucket_name))
                
                # Check for logging
                findings.extend(self._check_logging(bucket_name))
                
                # Check for versioning
                findings.extend(self._check_versioning(bucket_name))
                
                # Check for secure transport
                findings.extend(self._check_secure_transport(bucket_name))
                
        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {str(e)}")
        
        return findings
    
    def get_resources(self) -> List[Dict[str, Any]]:
        """Get S3 bucket resources.
        
        Returns:
            List of S3 bucket resources
        """
        resources = []
        try:
            buckets = self.client.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket location
                    location = self.client.get_bucket_location(Bucket=bucket_name)
                    region = location.get('LocationConstraint', 'us-east-1')
                    if region is None:
                        region = 'us-east-1'  # Default if None
                    
                    # Get bucket tags if available
                    tags = {}
                    try:
                        tag_response = self.client.get_bucket_tagging(Bucket=bucket_name)
                        if 'TagSet' in tag_response:
                            for tag in tag_response['TagSet']:
                                tags[tag['Key']] = tag['Value']
                    except ClientError:
                        # Bucket may not have tags
                        pass
                    
                    resources.append({
                        'id': bucket_name,
                        'name': bucket_name,
                        'type': 's3_bucket',
                        'region': region,
                        'arn': f"arn:aws:s3:::{bucket_name}",
                        'created': bucket.get('CreationDate'),
                        'tags': tags
                    })
                except Exception as e:
                    logger.warning(f"Error getting details for bucket {bucket_name}: {str(e)}")
        except Exception as e:
            logger.error(f"Error listing S3 buckets: {str(e)}")
        
        return resources
    
    def get_service_tags(self) -> Set[str]:
        """Get tags specific to S3 service.
        
        Returns:
            Set of service-specific tags
        """
        return {"s3", "storage", "data"}
    
    def _check_public_access(self, bucket_name: str) -> List[Finding]:
        """Check for public access to S3 bucket.
        
        Args:
            bucket_name: Name of the bucket to check
            
        Returns:
            List of findings related to public access
        """
        findings = []
        
        try:
            # Check bucket ACLs
            acl = self.client.get_bucket_acl(Bucket=bucket_name)
            is_public = False
            
            for grant in acl.get('Grants', []):
                if 'URI' in grant.get('Grantee', {}) and grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    is_public = True
                    break
            
            # Check bucket policy
            policy_is_public = False
            try:
                policy = self.client.get_bucket_policy(Bucket=bucket_name)
                # Simple check for "Principal": "*" - a more sophisticated check would parse the policy
                if '"Principal": "*"' in policy.get('Policy', ''):
                    policy_is_public = True
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Error checking bucket policy for {bucket_name}: {str(e)}")
            
            # Check Block Public Access settings
            block_public_access = self.client.get_public_access_block(Bucket=bucket_name)
            block_config = block_public_access.get('PublicAccessBlockConfiguration', {})
            
            all_blocked = (
                block_config.get('BlockPublicAcls', False) and
                block_config.get('IgnorePublicAcls', False) and
                block_config.get('BlockPublicPolicy', False) and
                block_config.get('RestrictPublicBuckets', False)
            )
            
            if is_public or policy_is_public or not all_blocked:
                # Create resource
                resource = Resource(
                    id=bucket_name,
                    name=bucket_name,
                    type="s3_bucket",
                    region=self.region,
                    arn=f"arn:aws:s3:::{bucket_name}"
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable Block Public Access for the S3 bucket",
                    description=(
                        "S3 buckets should have Block Public Access enabled to prevent unauthorized access. "
                        "Block Public Access settings override any conflicting bucket policies or ACLs."
                    ),
                    steps=[
                        RemediationStep(
                            title="Enable Block Public Access in AWS Console",
                            description=(
                                "1. Navigate to the S3 console\n"
                                "2. Select the bucket\n"
                                "3. Go to the 'Permissions' tab\n"
                                "4. Under 'Block public access', click 'Edit'\n"
                                "5. Check all four options\n"
                                "6. Save changes"
                            )
                        ),
                        RemediationStep(
                            title="Enable Block Public Access using AWS CLI",
                            description="Run the following AWS CLI command",
                            code="aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                            code_language="bash"
                        ),
                        RemediationStep(
                            title="Enable Block Public Access using CloudFormation",
                            description="Add the following to your CloudFormation template",
                            code=(
                                "Resources:\n"
                                "  BucketPublicAccessBlock:\n"
                                "    Type: AWS::S3::PublicAccessBlock\n"
                                "    Properties:\n"
                                "      BlockPublicAcls: true\n"
                                "      BlockPublicPolicy: true\n"
                                "      IgnorePublicAcls: true\n"
                                "      RestrictPublicBuckets: true\n"
                                "      BucketName: {bucket_name}"
                            ),
                            code_language="yaml"
                        )
                    ],
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                        "https://aws.amazon.com/blogs/aws/amazon-s3-block-public-access-now-available-for-existing-buckets/"
                    ]
                )
                
                # Determine severity based on whether it's actually public or just has incomplete blocks
                severity = Severity.CRITICAL if (is_public or policy_is_public) else Severity.HIGH
                
                # Tags for framework mappings
                tags = {"public_s3_bucket", "public_access", "data_exposure"}
                framework_mappings = get_framework_mappings_from_tags(tags)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"S3 bucket {bucket_name} has public access enabled",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have all Block Public Access settings enabled. "
                        f"Public ACL: {is_public}, Public Policy: {policy_is_public}, Block Public Access: {all_blocked}. "
                        "This could potentially allow unauthorized access to the bucket contents."
                    ),
                    severity=severity,
                    provider="aws",
                    service="s3",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    risk_score=self._calculate_risk_score(severity),
                    tags=tags,
                    metadata={
                        "public_acl": is_public,
                        "public_policy": policy_is_public,
                        "block_public_acls": block_config.get('BlockPublicAcls', False),
                        "ignore_public_acls": block_config.get('IgnorePublicAcls', False),
                        "block_public_policy": block_config.get('BlockPublicPolicy', False),
                        "restrict_public_buckets": block_config.get('RestrictPublicBuckets', False)
                    }
                )
                findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Error checking public access for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    def _check_encryption(self, bucket_name: str) -> List[Finding]:
        """Check for encryption on S3 bucket.
        
        Args:
            bucket_name: Name of the bucket to check
            
        Returns:
            List of findings related to encryption
        """
        findings = []
        
        try:
            # Check bucket encryption
            encryption_enabled = True
            try:
                encryption = self.client.get_bucket_encryption(Bucket=bucket_name)
                # Validate the encryption configuration
                rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                if not rules:
                    encryption_enabled = False
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    encryption_enabled = False
                else:
                    logger.warning(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
            
            if not encryption_enabled:
                # Create resource
                resource = Resource(
                    id=bucket_name,
                    name=bucket_name,
                    type="s3_bucket",
                    region=self.region,
                    arn=f"arn:aws:s3:::{bucket_name}"
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable default encryption for the S3 bucket",
                    description=(
                        "S3 buckets should have default encryption enabled to protect the data at rest. "
                        "This ensures that all objects stored in the bucket are automatically encrypted."
                    ),
                    steps=[
                        RemediationStep(
                            title="Enable default encryption in AWS Console",
                            description=(
                                "1. Navigate to the S3 console\n"
                                "2. Select the bucket\n"
                                "3. Go to the 'Properties' tab\n"
                                "4. Under 'Default encryption', click 'Edit'\n"
                                "5. Select 'Enable' and choose either 'Amazon S3 key (SSE-S3)' or 'AWS Key Management Service key (SSE-KMS)'\n"
                                "6. Save changes"
                            )
                        ),
                        RemediationStep(
                            title="Enable default encryption using AWS CLI",
                            description="Run the following AWS CLI command",
                            code="aws s3api put-bucket-encryption --bucket {bucket_name} --server-side-encryption-configuration '{\"Rules\": [{\"ApplyServerSideEncryptionByDefault\": {\"SSEAlgorithm\": \"AES256\"}}]}'",
                            code_language="bash"
                        )
                    ],
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
                    ]
                )
                
                # Tags for framework mappings
                tags = {"unencrypted_s3_bucket", "unencrypted_data", "data_protection"}
                framework_mappings = get_framework_mappings_from_tags(tags)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"S3 bucket {bucket_name} does not have default encryption enabled",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have default encryption enabled. "
                        "This could potentially expose sensitive data if objects are uploaded without explicit encryption."
                    ),
                    severity=Severity.HIGH,
                    provider="aws",
                    service="s3",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    risk_score=self._calculate_risk_score(Severity.HIGH),
                    tags=tags
                )
                findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Error checking encryption for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    def _check_logging(self, bucket_name: str) -> List[Finding]:
        """Check for logging on S3 bucket.
        
        Args:
            bucket_name: Name of the bucket to check
            
        Returns:
            List of findings related to logging
        """
        findings = []
        
        try:
            # Check bucket logging
            logging_enabled = True
            try:
                log_config = self.client.get_bucket_logging(Bucket=bucket_name)
                if 'LoggingEnabled' not in log_config:
                    logging_enabled = False
            except ClientError as e:
                logger.warning(f"Error checking logging for bucket {bucket_name}: {str(e)}")
                logging_enabled = False
            
            if not logging_enabled:
                # Create resource
                resource = Resource(
                    id=bucket_name,
                    name=bucket_name,
                    type="s3_bucket",
                    region=self.region,
                    arn=f"arn:aws:s3:::{bucket_name}"
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable access logging for the S3 bucket",
                    description=(
                        "S3 bucket access logging provides detailed records for the requests made to a bucket. "
                        "Enabling logging helps with security audits and investigations of potential security incidents."
                    ),
                    steps=[
                        RemediationStep(
                            title="Enable access logging in AWS Console",
                            description=(
                                "1. Navigate to the S3 console\n"
                                "2. Select the bucket\n"
                                "3. Go to the 'Properties' tab\n"
                                "4. Under 'Server access logging', click 'Edit'\n"
                                "5. Select 'Enable' and specify a target bucket for the logs\n"
                                "6. Save changes"
                            )
                        ),
                        RemediationStep(
                            title="Enable access logging using AWS CLI",
                            description="Run the following AWS CLI command",
                            code="aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status '{\"LoggingEnabled\": {\"TargetBucket\": \"log-bucket-name\", \"TargetPrefix\": \"{bucket_name}/\"}}'",
                            code_language="bash"
                        )
                    ],
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
                    ]
                )
                
                # Tags for framework mappings
                tags = {"s3_bucket_logging_disabled", "disabled_logging", "monitoring"}
                framework_mappings = get_framework_mappings_from_tags(tags)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"S3 bucket {bucket_name} does not have access logging enabled",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have access logging enabled. "
                        "This makes it difficult to track access to the bucket and investigate security incidents."
                    ),
                    severity=Severity.MEDIUM,
                    provider="aws",
                    service="s3",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    risk_score=self._calculate_risk_score(Severity.MEDIUM),
                    tags=tags
                )
                findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Error checking logging for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    def _check_versioning(self, bucket_name: str) -> List[Finding]:
        """Check for versioning on S3 bucket.
        
        Args:
            bucket_name: Name of the bucket to check
            
        Returns:
            List of findings related to versioning
        """
        findings = []
        
        try:
            # Check bucket versioning
            versioning = self.client.get_bucket_versioning(Bucket=bucket_name)
            versioning_enabled = versioning.get('Status') == 'Enabled'
            
            if not versioning_enabled:
                # Create resource
                resource = Resource(
                    id=bucket_name,
                    name=bucket_name,
                    type="s3_bucket",
                    region=self.region,
                    arn=f"arn:aws:s3:::{bucket_name}"
                )
                
                # Create remediation
                remediation = Remediation(
                    summary="Enable versioning for the S3 bucket",
                    description=(
                        "S3 bucket versioning helps protect against accidental deletions and modifications. "
                        "It keeps multiple versions of objects to allow recovery from unintended user actions and application failures."
                    ),
                    steps=[
                        RemediationStep(
                            title="Enable versioning in AWS Console",
                            description=(
                                "1. Navigate to the S3 console\n"
                                "2. Select the bucket\n"
                                "3. Go to the 'Properties' tab\n"
                                "4. Under 'Bucket Versioning', click 'Edit'\n"
                                "5. Select 'Enable'\n"
                                "6. Save changes"
                            )
                        ),
                        RemediationStep(
                            title="Enable versioning using AWS CLI",
                            description="Run the following AWS CLI command",
                            code="aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled",
                            code_language="bash"
                        )
                    ],
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
                    ]
                )
                
                # Tags for framework mappings
                tags = {"s3_bucket_versioning_disabled", "data_protection"}
                framework_mappings = get_framework_mappings_from_tags(tags)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"S3 bucket {bucket_name} does not have versioning enabled",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have versioning enabled. "
                        "This increases the risk of data loss due to accidental deletions or modifications."
                    ),
                    severity=Severity.LOW,
                    provider="aws",
                    service="s3",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    risk_score=self._calculate_risk_score(Severity.LOW),
                    tags=tags
                )
                findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Error checking versioning for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    def _check_secure_transport(self, bucket_name: str) -> List[Finding]:
        """Check for secure transport policy on S3 bucket.
        
        Args:
            bucket_name: Name of the bucket to check
            
        Returns:
            List of findings related to secure transport
        """
        findings = []
        
        try:
            # Check bucket policy for secure transport requirement
            secure_transport_required = False
            try:
                policy = self.client.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy.get('Policy', '')
                
                # Simple check for "aws:SecureTransport": "false" - a more sophisticated check would parse the policy
                if 'aws:SecureTransport' in policy_str and 'false' in policy_str:
                    secure_transport_required = True
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    logger.warning(f"Error checking bucket policy for {bucket_name}: {str(e)}")
            
            if not secure_transport_required:
                # Create resource
                resource = Resource(
                    id=bucket_name,
                    name=bucket_name,
                    type="s3_bucket",
                    region=self.region,
                    arn=f"arn:aws:s3:::{bucket_name}"
                )
                
                # Create remediation
                secure_transport_policy = '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonSSLRequests",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::%s",
        "arn:aws:s3:::%s/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}''' % (bucket_name, bucket_name)
                
                remediation = Remediation(
                    summary="Require secure transport for the S3 bucket",
                    description=(
                        "S3 buckets should require secure transport (HTTPS) for all access. "
                        "This ensures data is encrypted in transit, protecting it from eavesdropping."
                    ),
                    steps=[
                        RemediationStep(
                            title="Add secure transport policy in AWS Console",
                            description=(
                                "1. Navigate to the S3 console\n"
                                "2. Select the bucket\n"
                                "3. Go to the 'Permissions' tab\n"
                                "4. Under 'Bucket policy', click 'Edit'\n"
                                "5. Add a policy that denies non-HTTPS requests\n"
                                "6. Save changes"
                            )
                        ),
                        RemediationStep(
                            title="Add secure transport policy using AWS CLI",
                            description="Run the following AWS CLI command",
                            code=f"aws s3api put-bucket-policy --bucket {bucket_name} --policy '{secure_transport_policy}'",
                            code_language="bash"
                        )
                    ],
                    difficulty=RemediationDifficulty.EASY,
                    links=[
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
                    ]
                )
                
                # Tags for framework mappings
                tags = {"no_encryption_in_transit", "data_protection"}
                framework_mappings = get_framework_mappings_from_tags(tags)
                
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title=f"S3 bucket {bucket_name} does not require secure transport",
                    description=(
                        f"The S3 bucket '{bucket_name}' does not have a policy requiring secure transport (HTTPS). "
                        "This could potentially allow data to be transmitted unencrypted, exposing it to eavesdropping."
                    ),
                    severity=Severity.MEDIUM,
                    provider="aws",
                    service="s3",
                    resources=[resource],
                    remediation=remediation,
                    framework_mappings=framework_mappings,
                    risk_score=self._calculate_risk_score(Severity.MEDIUM),
                    tags=tags
                )
                findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Error checking secure transport for bucket {bucket_name}: {str(e)}")
        
        return findings
    
    def _calculate_risk_score(self, severity: Severity) -> float:
        """Calculate a normalized risk score based on severity.
        
        Args:
            severity: Finding severity
            
        Returns:
            Risk score between 0.0 and 10.0
        """
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0
        }
        return severity_scores.get(severity, 1.0) 