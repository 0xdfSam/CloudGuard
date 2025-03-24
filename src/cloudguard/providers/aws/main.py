"""
Main AWS scanner module.

This module provides the main AWS scanner functionality that coordinates 
scanning across all AWS services using the service registry.
"""

import logging
import concurrent.futures
from typing import Dict, List, Any, Optional, Set

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from cloudguard.core.findings import Finding
from cloudguard.providers.aws.registry import AwsServiceRegistry

logger = logging.getLogger(__name__)

class AwsScanner:
    """Main AWS scanner that coordinates scanning across all registered services."""

    def __init__(self, 
                 aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 aws_session_token: Optional[str] = None,
                 profile_name: Optional[str] = None,
                 regions: Optional[List[str]] = None,
                 services: Optional[List[str]] = None,
                 max_workers: int = 10):
        """Initialize the AWS scanner.
        
        Args:
            aws_access_key_id: AWS access key ID
            aws_secret_access_key: AWS secret access key
            aws_session_token: AWS session token for temporary credentials
            profile_name: AWS profile name to use
            regions: List of AWS regions to scan (None for all regions)
            services: List of AWS services to scan (None for all registered services)
            max_workers: Maximum number of worker threads to use for concurrent scanning
        """
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.aws_session_token = aws_session_token
        self.profile_name = profile_name
        self.regions = regions
        self.services = services
        self.max_workers = max_workers
        
        # Initialize the service registry
        self.registry = AwsServiceRegistry()
        
        # Create a boto3 session
        self.session = self._create_session()
        
        # Determine regions to scan
        self.regions_to_scan = self._get_regions_to_scan()
        
        # Determine services to scan
        self.services_to_scan = self._get_services_to_scan()
        
        logger.info(f"Initialized AWS scanner with {len(self.regions_to_scan)} regions "
                    f"and {len(self.services_to_scan)} services")

    def _create_session(self) -> boto3.Session:
        """Create a boto3 session with the provided credentials.
        
        Returns:
            boto3 Session object
            
        Raises:
            NoCredentialsError: If no valid credentials are found
        """
        try:
            if self.profile_name:
                session = boto3.Session(profile_name=self.profile_name)
                logger.info(f"Created boto3 session using profile: {self.profile_name}")
            elif self.aws_access_key_id and self.aws_secret_access_key:
                session = boto3.Session(
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                    aws_session_token=self.aws_session_token
                )
                logger.info("Created boto3 session using provided access keys")
            else:
                # Use default credentials (environment variables, credential file, instance profile)
                session = boto3.Session()
                logger.info("Created boto3 session using default credentials")
            
            # Validate the session by making a simple call
            account_id = session.client('sts').get_caller_identity().get('Account')
            logger.info(f"Successfully authenticated with AWS account: {account_id}")
            
            return session
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"Failed to create AWS session: {str(e)}")
            raise NoCredentialsError("Failed to authenticate with AWS. Please check your credentials.")

    def _get_regions_to_scan(self) -> List[str]:
        """Get the list of regions to scan.
        
        Returns:
            List of AWS region names to scan
        """
        if self.regions:
            return self.regions
        
        try:
            # Get all available regions
            ec2 = self.session.client('ec2', region_name='us-east-1')
            available_regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
            logger.info(f"Discovered {len(available_regions)} available AWS regions")
            return available_regions
        except ClientError as e:
            logger.error(f"Failed to get AWS regions: {str(e)}")
            # Fall back to common regions
            fallback_regions = [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 
                'eu-west-1', 'eu-west-2', 'eu-central-1', 
                'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2'
            ]
            logger.warning(f"Using fallback list of {len(fallback_regions)} AWS regions")
            return fallback_regions

    def _get_services_to_scan(self) -> List[str]:
        """Get the list of services to scan.
        
        Returns:
            List of AWS service names to scan
        """
        if self.services:
            # Validate that all requested services are registered
            registered_services = self.registry.get_registered_services()
            for service in self.services:
                if service not in registered_services:
                    logger.warning(f"Requested service '{service}' is not registered, it will be skipped")
            
            # Return the intersection of requested and registered services
            valid_services = [s for s in self.services if s in registered_services]
            if len(valid_services) < len(self.services):
                logger.warning(f"Only {len(valid_services)} of {len(self.services)} requested services are registered")
            return valid_services
        else:
            # Return all registered services
            return self.registry.get_registered_services()

    def scan(self) -> List[Finding]:
        """Perform a security scan across all specified AWS services and regions.
        
        Returns:
            List of findings from all services and regions
        """
        all_findings = []
        
        logger.info(f"Starting AWS security scan with {len(self.services_to_scan)} "
                    f"services across {len(self.regions_to_scan)} regions")
        
        # Use thread pool to scan services and regions in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_scan = {}
            
            # Submit all service/region combinations as separate tasks
            for service in self.services_to_scan:
                for region in self.regions_to_scan:
                    future = executor.submit(self._scan_service_in_region, service, region)
                    future_to_scan[future] = (service, region)
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_scan):
                service, region = future_to_scan[future]
                try:
                    service_findings = future.result()
                    all_findings.extend(service_findings)
                    logger.info(f"Completed scan of {service} in {region}, found {len(service_findings)} issues")
                except Exception as e:
                    logger.error(f"Scan of {service} in {region} failed: {str(e)}")
        
        logger.info(f"AWS security scan completed, found {len(all_findings)} issues in total")
        return all_findings

    def _scan_service_in_region(self, service: str, region: str) -> List[Finding]:
        """Scan a specific AWS service in a specific region.
        
        Args:
            service: AWS service name
            region: AWS region name
            
        Returns:
            List of findings for the service in the region
        """
        try:
            logger.info(f"Scanning {service} in {region}")
            
            # Create a regional session
            regional_session = boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                profile_name=self.profile_name,
                region_name=region
            )
            
            # Get the scanner for this service
            scanner = self.registry.get_scanner(service, regional_session, region)
            
            # Perform the scan
            findings = scanner.scan()
            
            return findings
        except Exception as e:
            logger.error(f"Error scanning {service} in {region}: {str(e)}")
            return []

    def get_resources(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all resources from all services and regions.
        
        Returns:
            Dictionary mapping service names to lists of resources
        """
        all_resources = {}
        
        logger.info(f"Retrieving resources from {len(self.services_to_scan)} "
                    f"services across {len(self.regions_to_scan)} regions")
        
        # Use thread pool to retrieve resources in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_resource = {}
            
            # Submit all service/region combinations as separate tasks
            for service in self.services_to_scan:
                for region in self.regions_to_scan:
                    future = executor.submit(self._get_service_resources_in_region, service, region)
                    future_to_resource[future] = (service, region)
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_resource):
                service, region = future_to_resource[future]
                try:
                    resources = future.result()
                    
                    # Initialize the service entry if it doesn't exist
                    if service not in all_resources:
                        all_resources[service] = []
                    
                    # Add the resources for this service/region
                    all_resources[service].extend(resources)
                    
                    logger.info(f"Retrieved {len(resources)} resources for {service} in {region}")
                except Exception as e:
                    logger.error(f"Failed to retrieve resources for {service} in {region}: {str(e)}")
        
        logger.info("Resource retrieval completed")
        return all_resources

    def _get_service_resources_in_region(self, service: str, region: str) -> List[Dict[str, Any]]:
        """Get resources for a specific AWS service in a specific region.
        
        Args:
            service: AWS service name
            region: AWS region name
            
        Returns:
            List of resources for the service in the region
        """
        try:
            logger.info(f"Getting resources for {service} in {region}")
            
            # Create a regional session
            regional_session = boto3.Session(
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                profile_name=self.profile_name,
                region_name=region
            )
            
            # Get the scanner for this service
            scanner = self.registry.get_scanner(service, regional_session, region)
            
            # Get the resources
            resources = scanner.get_resources()
            
            # Add region to each resource
            for resource in resources:
                resource['region'] = region
            
            return resources
        except Exception as e:
            logger.error(f"Error getting resources for {service} in {region}: {str(e)}")
            return []

    def get_service_tags(self) -> Dict[str, Set[str]]:
        """Get tags for all registered services.
        
        Returns:
            Dictionary mapping service names to sets of tags
        """
        return self.registry.get_service_tags() 