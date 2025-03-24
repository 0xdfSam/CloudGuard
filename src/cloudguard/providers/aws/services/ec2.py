"""
EC2 service scanner implementation for AWS.

This module provides functionality to scan EC2 resources for security issues.
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

class Ec2Scanner(AwsServiceScanner):
    """Scanner for AWS EC2 service to detect security issues."""

    service_name = "ec2"

    def __init__(self, session: boto3.Session, region: str):
        """Initialize the EC2 scanner with AWS session and region.

        Args:
            session: boto3 Session object
            region: AWS region name
        """
        super().__init__(session, region)
        self.ec2_client = session.client('ec2', region_name=region)

    def scan(self) -> List[Finding]:
        """Scan EC2 resources for security issues.

        Returns:
            List of findings detected during the scan
        """
        findings = []
        logger.info(f"Scanning EC2 resources in {self.region} for security issues")

        try:
            # Check security groups for issues
            findings.extend(self._check_security_groups())
            
            # Check EC2 instances for issues
            findings.extend(self._check_instances())
            
            # Check EBS volumes for encryption
            findings.extend(self._check_ebs_encryption())
            
            # Check for public AMIs
            findings.extend(self._check_public_amis())
            
            # Check for default VPCs
            findings.extend(self._check_default_vpcs())

            logger.info(f"EC2 scan completed in {self.region}, found {len(findings)} issues")
            return findings
        except ClientError as e:
            logger.error(f"Error scanning EC2 resources in {self.region}: {str(e)}")
            return []

    def get_resources(self) -> List[Dict[str, Any]]:
        """Get EC2 resources.

        Returns:
            List of EC2 resources with their details
        """
        resources = []
        
        try:
            # Get EC2 instances
            instances_response = self.ec2_client.describe_instances()
            for reservation in instances_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_resource = {
                        'id': instance.get('InstanceId'),
                        'name': self._get_name_from_tags(instance.get('Tags', [])),
                        'arn': f"arn:aws:ec2:{self.region}:{self._get_account_id()}:instance/{instance.get('InstanceId')}",
                        'resource_type': 'ec2_instance',
                        'state': instance.get('State', {}).get('Name'),
                        'instance_type': instance.get('InstanceType'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'subnet_id': instance.get('SubnetId'),
                        'vpc_id': instance.get('VpcId'),
                        'ami_id': instance.get('ImageId'),
                        'launch_time': instance.get('LaunchTime'),
                        'tags': self._tags_to_dict(instance.get('Tags', []))
                    }
                    resources.append(instance_resource)
            
            # Get Security Groups
            sg_response = self.ec2_client.describe_security_groups()
            for sg in sg_response.get('SecurityGroups', []):
                sg_resource = {
                    'id': sg.get('GroupId'),
                    'name': sg.get('GroupName'),
                    'arn': f"arn:aws:ec2:{self.region}:{self._get_account_id()}:security-group/{sg.get('GroupId')}",
                    'resource_type': 'security_group',
                    'vpc_id': sg.get('VpcId'),
                    'description': sg.get('Description'),
                    'tags': self._tags_to_dict(sg.get('Tags', []))
                }
                resources.append(sg_resource)
            
            # Get EBS Volumes
            volumes_response = self.ec2_client.describe_volumes()
            for volume in volumes_response.get('Volumes', []):
                volume_resource = {
                    'id': volume.get('VolumeId'),
                    'name': self._get_name_from_tags(volume.get('Tags', [])),
                    'arn': f"arn:aws:ec2:{self.region}:{self._get_account_id()}:volume/{volume.get('VolumeId')}",
                    'resource_type': 'ebs_volume',
                    'size': volume.get('Size'),
                    'state': volume.get('State'),
                    'type': volume.get('VolumeType'),
                    'encrypted': volume.get('Encrypted'),
                    'availability_zone': volume.get('AvailabilityZone'),
                    'tags': self._tags_to_dict(volume.get('Tags', []))
                }
                resources.append(volume_resource)
            
            return resources
        except ClientError as e:
            logger.error(f"Error retrieving EC2 resources in {self.region}: {str(e)}")
            return []

    def get_service_tags(self) -> Set[str]:
        """Get tags specific to EC2 service.

        Returns:
            Set of tags for EC2 service
        """
        return {"aws", "ec2", "compute", "virtual machine", "instance"}

    def _get_account_id(self) -> str:
        """Get AWS account ID from session.

        Returns:
            AWS account ID
        """
        try:
            sts_client = self.session.client('sts')
            return sts_client.get_caller_identity().get('Account')
        except ClientError as e:
            logger.error(f"Error retrieving AWS account ID: {str(e)}")
            return "unknown"

    def _get_name_from_tags(self, tags: List[Dict[str, str]]) -> Optional[str]:
        """Extract Name tag value from a list of tags.

        Args:
            tags: List of AWS resource tags

        Returns:
            Name tag value or None if not present
        """
        for tag in tags:
            if tag.get('Key') == 'Name':
                return tag.get('Value')
        return None

    def _tags_to_dict(self, tags: List[Dict[str, str]]) -> Dict[str, str]:
        """Convert AWS tags list to a dictionary.

        Args:
            tags: List of AWS resource tags

        Returns:
            Dictionary of tag key-value pairs
        """
        return {tag.get('Key'): tag.get('Value') for tag in tags} if tags else {}

    def _check_security_groups(self) -> List[Finding]:
        """Check security groups for security issues.

        Returns:
            List of findings related to security groups
        """
        findings = []
        try:
            security_groups = self.ec2_client.describe_security_groups().get('SecurityGroups', [])
            
            for sg in security_groups:
                sg_id = sg.get('GroupId')
                sg_name = sg.get('GroupName')
                vpc_id = sg.get('VpcId')
                
                # Check for security groups allowing all traffic from anywhere
                for rule in sg.get('IpPermissions', []):
                    ip_protocol = rule.get('IpProtocol')
                    
                    # Check for all protocols allowed (-1)
                    if ip_protocol == '-1':
                        for ip_range in rule.get('IpRanges', []):
                            cidr = ip_range.get('CidrIp')
                            if cidr == '0.0.0.0/0':
                                finding = Finding(
                                    title=f"Security group {sg_name} allows all traffic from anywhere",
                                    description=f"The security group {sg_name} ({sg_id}) allows all traffic from any source (0.0.0.0/0). This is a security risk and should be restricted to specific sources.",
                                    severity=Severity.HIGH,
                                    resource_id=sg_id,
                                    resource_type="security_group",
                                    service="ec2",
                                    region=self.region,
                                    risk_score=RiskScore.HIGH,
                                    remediation_steps=[
                                        f"1. Review the security group {sg_name} ({sg_id})",
                                        "2. Remove overly permissive inbound rules",
                                        "3. Replace with more restrictive rules that only allow necessary traffic",
                                        "4. Consider using a security group reference instead of CIDR for internal traffic"
                                    ],
                                    compliance={
                                        "CIS AWS Foundations": "4.1",
                                        "AWS Well-Architected Framework": "SEC06-BP03"
                                    }
                                )
                                findings.append(finding)
                    
                    # Check for SSH (port 22) allowed from anywhere
                    elif ip_protocol == 'tcp' and rule.get('FromPort') <= 22 and rule.get('ToPort') >= 22:
                        for ip_range in rule.get('IpRanges', []):
                            cidr = ip_range.get('CidrIp')
                            if cidr == '0.0.0.0/0':
                                finding = Finding(
                                    title=f"Security group {sg_name} allows SSH from anywhere",
                                    description=f"The security group {sg_name} ({sg_id}) allows SSH (port 22) from any source (0.0.0.0/0). SSH access should be restricted to specific trusted IPs.",
                                    severity=Severity.HIGH,
                                    resource_id=sg_id,
                                    resource_type="security_group",
                                    service="ec2",
                                    region=self.region,
                                    risk_score=RiskScore.HIGH,
                                    remediation_steps=[
                                        f"1. Edit the security group {sg_name} ({sg_id})",
                                        "2. Remove the rule allowing SSH from 0.0.0.0/0",
                                        "3. Add a new rule that restricts SSH access to specific IP addresses",
                                        "4. Consider using AWS Systems Manager Session Manager for secure shell access"
                                    ],
                                    compliance={
                                        "CIS AWS Foundations": "4.1",
                                        "AWS Well-Architected Framework": "SEC06-BP04"
                                    }
                                )
                                findings.append(finding)
                    
                    # Check for RDP (port 3389) allowed from anywhere
                    elif ip_protocol == 'tcp' and rule.get('FromPort') <= 3389 and rule.get('ToPort') >= 3389:
                        for ip_range in rule.get('IpRanges', []):
                            cidr = ip_range.get('CidrIp')
                            if cidr == '0.0.0.0/0':
                                finding = Finding(
                                    title=f"Security group {sg_name} allows RDP from anywhere",
                                    description=f"The security group {sg_name} ({sg_id}) allows RDP (port 3389) from any source (0.0.0.0/0). RDP access should be restricted to specific trusted IPs.",
                                    severity=Severity.HIGH,
                                    resource_id=sg_id,
                                    resource_type="security_group",
                                    service="ec2",
                                    region=self.region,
                                    risk_score=RiskScore.HIGH,
                                    remediation_steps=[
                                        f"1. Edit the security group {sg_name} ({sg_id})",
                                        "2. Remove the rule allowing RDP from 0.0.0.0/0",
                                        "3. Add a new rule that restricts RDP access to specific IP addresses",
                                        "4. Consider using AWS Systems Manager Session Manager for secure access"
                                    ],
                                    compliance={
                                        "CIS AWS Foundations": "4.2",
                                        "AWS Well-Architected Framework": "SEC06-BP04"
                                    }
                                )
                                findings.append(finding)
        
        except ClientError as e:
            logger.error(f"Error checking security groups in {self.region}: {str(e)}")
        
        return findings

    def _check_instances(self) -> List[Finding]:
        """Check EC2 instances for security issues.

        Returns:
            List of findings related to EC2 instances
        """
        findings = []
        try:
            # Get all instances
            instances_response = self.ec2_client.describe_instances()
            
            for reservation in instances_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    instance_name = self._get_name_from_tags(instance.get('Tags', []))
                    instance_state = instance.get('State', {}).get('Name')
                    
                    # Skip terminated instances
                    if instance_state == 'terminated':
                        continue
                    
                    # Check for instances with public IP addresses
                    if instance.get('PublicIpAddress'):
                        # Check if instance is in a public subnet
                        subnet_id = instance.get('SubnetId')
                        if self._is_public_subnet(subnet_id):
                            finding = Finding(
                                title=f"EC2 instance {instance_name or instance_id} has a public IP in a public subnet",
                                description=f"The EC2 instance {instance_name or instance_id} has a public IP address {instance.get('PublicIpAddress')} and is in a public subnet. This increases the attack surface of the instance.",
                                severity=Severity.MEDIUM,
                                resource_id=instance_id,
                                resource_type="ec2_instance",
                                service="ec2",
                                region=self.region,
                                risk_score=RiskScore.MEDIUM,
                                remediation_steps=[
                                    "1. If possible, move the instance to a private subnet",
                                    "2. Use a NAT gateway for outbound internet connectivity",
                                    "3. Remove the public IP address if direct internet access is not required",
                                    "4. Ensure security groups are properly configured to restrict inbound traffic"
                                ],
                                compliance={
                                    "AWS Well-Architected Framework": "SEC06-BP01"
                                }
                            )
                            findings.append(finding)
                    
                    # Check for instances without IMDSv2
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        finding = Finding(
                            title=f"EC2 instance {instance_name or instance_id} is not using IMDSv2",
                            description=f"The EC2 instance {instance_name or instance_id} is not configured to use IMDSv2 (Instance Metadata Service v2). IMDSv2 provides additional security against SSRF attacks.",
                            severity=Severity.MEDIUM,
                            resource_id=instance_id,
                            resource_type="ec2_instance",
                            service="ec2",
                            region=self.region,
                            risk_score=RiskScore.MEDIUM,
                            remediation_steps=[
                                "1. Modify the instance metadata options to require IMDSv2",
                                "2. Use the EC2 console or AWS CLI to set HttpTokens to 'required'",
                                "3. For future instances, include this setting in your launch templates or user data scripts"
                            ],
                            compliance={
                                "AWS Well-Architected Framework": "SEC06-BP02"
                            }
                        )
                        findings.append(finding)
                    
                    # Check instance types for outdated or vulnerable instances
                    instance_type = instance.get('InstanceType')
                    if self._is_outdated_instance_type(instance_type):
                        finding = Finding(
                            title=f"EC2 instance {instance_name or instance_id} uses an outdated instance type",
                            description=f"The EC2 instance {instance_name or instance_id} uses {instance_type}, which is an older generation instance type. Newer generation instances offer better security, performance, and cost-effectiveness.",
                            severity=Severity.LOW,
                            resource_id=instance_id,
                            resource_type="ec2_instance",
                            service="ec2",
                            region=self.region,
                            risk_score=RiskScore.LOW,
                            remediation_steps=[
                                "1. Stop the instance",
                                "2. Change the instance type to a newer generation",
                                "3. Start the instance",
                                "4. Verify that the application works correctly on the new instance type"
                            ],
                            compliance={
                                "AWS Well-Architected Framework": "OPS08-BP01"
                            }
                        )
                        findings.append(finding)
        
        except ClientError as e:
            logger.error(f"Error checking EC2 instances in {self.region}: {str(e)}")
        
        return findings

    def _check_ebs_encryption(self) -> List[Finding]:
        """Check EBS volumes for encryption.

        Returns:
            List of findings related to EBS encryption
        """
        findings = []
        try:
            # Get all volumes
            volumes_response = self.ec2_client.describe_volumes()
            
            for volume in volumes_response.get('Volumes', []):
                volume_id = volume.get('VolumeId')
                volume_name = self._get_name_from_tags(volume.get('Tags', []))
                
                # Check if volume is encrypted
                if not volume.get('Encrypted'):
                    # Get instance details if attached
                    attached_instances = []
                    for attachment in volume.get('Attachments', []):
                        instance_id = attachment.get('InstanceId')
                        if instance_id:
                            attached_instances.append(instance_id)
                    
                    instance_info = ""
                    if attached_instances:
                        instance_info = f" attached to instances: {', '.join(attached_instances)}"
                    
                    finding = Finding(
                        title=f"EBS volume {volume_name or volume_id} is not encrypted",
                        description=f"The EBS volume {volume_name or volume_id}{instance_info} is not encrypted. Unencrypted volumes can lead to data exposure if compromised.",
                        severity=Severity.MEDIUM,
                        resource_id=volume_id,
                        resource_type="ebs_volume",
                        service="ec2",
                        region=self.region,
                        risk_score=RiskScore.MEDIUM,
                        remediation_steps=[
                            "1. Create a snapshot of the unencrypted volume",
                            "2. Create a new encrypted volume from the snapshot",
                            "3. Detach the unencrypted volume from the instance",
                            "4. Attach the new encrypted volume to the instance",
                            "5. Verify data integrity and functionality",
                            "6. Delete the unencrypted volume and snapshot when no longer needed"
                        ],
                        compliance={
                            "CIS AWS Foundations": "2.2.1",
                            "AWS Well-Architected Framework": "SEC07-BP01"
                        }
                    )
                    findings.append(finding)
        
        except ClientError as e:
            logger.error(f"Error checking EBS volumes in {self.region}: {str(e)}")
        
        return findings

    def _check_public_amis(self) -> List[Finding]:
        """Check for public AMIs owned by the account.

        Returns:
            List of findings related to public AMIs
        """
        findings = []
        try:
            # Get account ID
            account_id = self._get_account_id()
            
            # Get AMIs owned by this account
            owned_images = self.ec2_client.describe_images(Owners=[account_id])
            
            for image in owned_images.get('Images', []):
                image_id = image.get('ImageId')
                image_name = image.get('Name')
                
                # Check if the AMI is public
                if image.get('Public'):
                    finding = Finding(
                        title=f"AMI {image_name or image_id} is publicly accessible",
                        description=f"The AMI {image_name or image_id} owned by your account is publicly accessible. Public AMIs can expose sensitive data and configurations.",
                        severity=Severity.HIGH,
                        resource_id=image_id,
                        resource_type="ami",
                        service="ec2",
                        region=self.region,
                        risk_score=RiskScore.HIGH,
                        remediation_steps=[
                            f"1. Make the AMI {image_id} private by modifying its launch permissions",
                            "2. Use AWS CLI: aws ec2 modify-image-attribute --image-id {image_id} --launch-permission '{\"Remove\":[{\"Group\":\"all\"}]}'",
                            "3. Review all AMIs for sensitive data or configurations",
                            "4. Implement a process for reviewing AMI permissions before sharing"
                        ],
                        compliance={
                            "AWS Well-Architected Framework": "SEC06-BP05"
                        }
                    )
                    findings.append(finding)
        
        except ClientError as e:
            logger.error(f"Error checking public AMIs in {self.region}: {str(e)}")
        
        return findings

    def _check_default_vpcs(self) -> List[Finding]:
        """Check for default VPCs.

        Returns:
            List of findings related to default VPCs
        """
        findings = []
        try:
            # Get all VPCs
            vpcs_response = self.ec2_client.describe_vpcs()
            
            for vpc in vpcs_response.get('Vpcs', []):
                vpc_id = vpc.get('VpcId')
                
                # Check if this is a default VPC
                if vpc.get('IsDefault'):
                    # Check if the default VPC is in use
                    vpc_in_use = self._is_vpc_in_use(vpc_id)
                    
                    severity = Severity.LOW
                    risk_score = RiskScore.LOW
                    
                    if vpc_in_use:
                        severity = Severity.MEDIUM
                        risk_score = RiskScore.MEDIUM
                    
                    finding = Finding(
                        title=f"Default VPC {vpc_id} exists in the account",
                        description=f"The default VPC {vpc_id} exists in the region {self.region}. " +
                                 ("It appears to be in use. " if vpc_in_use else "It does not appear to be in use. ") +
                                 "Default VPCs have overly permissive configurations that may not align with security best practices.",
                        severity=severity,
                        resource_id=vpc_id,
                        resource_type="vpc",
                        service="ec2",
                        region=self.region,
                        risk_score=risk_score,
                        remediation_steps=[
                            "1. Create custom VPCs with appropriate network segmentation",
                            "2. Migrate resources from the default VPC to custom VPCs" if vpc_in_use else "2. No migration needed as VPC appears unused",
                            "3. Delete the default VPC once no longer needed",
                            "4. Use AWS CloudFormation or Terraform to manage network infrastructure as code"
                        ],
                        compliance={
                            "AWS Well-Architected Framework": "SEC06-BP01"
                        }
                    )
                    findings.append(finding)
        
        except ClientError as e:
            logger.error(f"Error checking default VPCs in {self.region}: {str(e)}")
        
        return findings

    def _is_public_subnet(self, subnet_id: str) -> bool:
        """Check if a subnet is public (has a route to an internet gateway).

        Args:
            subnet_id: ID of the subnet to check

        Returns:
            True if the subnet is public, False otherwise
        """
        try:
            # Get subnet details
            subnet = self.ec2_client.describe_subnets(SubnetIds=[subnet_id])['Subnets'][0]
            vpc_id = subnet['VpcId']
            
            # Get route tables associated with this subnet
            route_tables = self.ec2_client.describe_route_tables(
                Filters=[
                    {
                        'Name': 'association.subnet-id',
                        'Values': [subnet_id]
                    }
                ]
            )['RouteTables']
            
            # If no explicit association, get the main route table for the VPC
            if not route_tables:
                route_tables = self.ec2_client.describe_route_tables(
                    Filters=[
                        {
                            'Name': 'vpc-id',
                            'Values': [vpc_id]
                        },
                        {
                            'Name': 'association.main',
                            'Values': ['true']
                        }
                    ]
                )['RouteTables']
            
            # Check for route to internet gateway
            for rt in route_tables:
                for route in rt.get('Routes', []):
                    if route.get('DestinationCidrBlock') == '0.0.0.0/0' and route.get('GatewayId', '').startswith('igw-'):
                        return True
            
            return False
        except ClientError as e:
            logger.error(f"Error checking if subnet {subnet_id} is public: {str(e)}")
            # Assume private in case of error
            return False

    def _is_outdated_instance_type(self, instance_type: str) -> bool:
        """Check if an instance type is outdated.

        Args:
            instance_type: EC2 instance type

        Returns:
            True if the instance type is outdated, False otherwise
        """
        # List of older-generation instance types
        outdated_families = ['t1', 'm1', 'm2', 'c1', 'cc1', 'cc2', 'cr1', 'cg1', 'hi1', 'hs1', 'g1']
        
        # Check if instance type belongs to outdated family
        for family in outdated_families:
            if instance_type.startswith(family + '.'):
                return True
        
        return False

    def _is_vpc_in_use(self, vpc_id: str) -> bool:
        """Check if a VPC has any resources.

        Args:
            vpc_id: ID of the VPC to check

        Returns:
            True if the VPC has resources, False otherwise
        """
        try:
            # Check for instances in the VPC
            instances_response = self.ec2_client.describe_instances(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            
            for reservation in instances_response.get('Reservations', []):
                if reservation.get('Instances'):
                    # Only count running or stopped instances, not terminated
                    for instance in reservation.get('Instances'):
                        state = instance.get('State', {}).get('Name')
                        if state in ['running', 'stopped', 'pending', 'stopping']:
                            return True
            
            # Check for other resources like subnets, security groups, etc.
            # Count non-default security groups as a sign of use
            sg_response = self.ec2_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    }
                ]
            )
            
            for sg in sg_response.get('SecurityGroups', []):
                # If there are security groups other than the default one
                if sg.get('GroupName') != 'default':
                    return True
            
            return False
        except ClientError as e:
            logger.error(f"Error checking if VPC {vpc_id} is in use: {str(e)}")
            # Assume not in use in case of error
            return False

    def get_client_name(self) -> str:
        """Get the name of the boto3 client to use.
        
        Returns:
            Boto3 client name
        """
        return "ec2"
    
    def is_global_service(self) -> bool:
        """Determine if this is a global service.
        
        Returns:
            False as EC2 is a regional service
        """
        return False 