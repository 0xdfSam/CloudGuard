"""
AWS service registry module.

This module registers all available AWS service scanners.
"""

import logging
from typing import Dict, Type, List, Set

import boto3

from cloudguard.providers.aws.scanner import AwsServiceScanner
from cloudguard.providers.aws.services.s3 import S3Scanner
from cloudguard.providers.aws.services.iam import IamScanner
from cloudguard.providers.aws.services.ec2 import Ec2Scanner

logger = logging.getLogger(__name__)

class AwsServiceRegistry:
    """Registry for AWS service scanners."""

    def __init__(self):
        """Initialize the registry with all available scanners."""
        self._scanners: Dict[str, Type[AwsServiceScanner]] = {}
        self._register_scanners()

    def _register_scanners(self) -> None:
        """Register all available AWS service scanners."""
        self._register_scanner("s3", S3Scanner)
        self._register_scanner("iam", IamScanner)
        self._register_scanner("ec2", Ec2Scanner)
        # Register additional scanners here as they are implemented
        
        logger.info(f"Registered {len(self._scanners)} AWS service scanners")
        
    def _register_scanner(self, service_name: str, scanner_class: Type[AwsServiceScanner]) -> None:
        """Register a single service scanner.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'ec2')
            scanner_class: Scanner class for the service
        """
        self._scanners[service_name] = scanner_class
        logger.debug(f"Registered scanner for service: {service_name}")

    def get_scanner(self, service_name: str, session: boto3.Session, region: str) -> AwsServiceScanner:
        """Get a scanner instance for a specific service.
        
        Args:
            service_name: Name of the AWS service
            session: boto3 Session object
            region: AWS region name
            
        Returns:
            Instance of the scanner for the requested service
            
        Raises:
            ValueError: If service scanner is not found
        """
        scanner_class = self._scanners.get(service_name)
        if not scanner_class:
            raise ValueError(f"Scanner for service '{service_name}' is not registered")
        
        return scanner_class(session, region)
    
    def get_registered_services(self) -> List[str]:
        """Get the list of registered service names.
        
        Returns:
            List of registered service names
        """
        return list(self._scanners.keys())
    
    def get_service_tags(self) -> Dict[str, Set[str]]:
        """Get all tags for registered services.
        
        Returns:
            Dictionary of service name to set of tags
        """
        # Create a dummy session for instantiating scanners to get their tags
        # We don't actually make API calls for tags
        dummy_session = boto3.Session()
        dummy_region = "us-east-1"
        
        tags = {}
        for service_name, scanner_class in self._scanners.items():
            scanner = scanner_class(dummy_session, dummy_region)
            tags[service_name] = scanner.get_service_tags()
        
        return tags 