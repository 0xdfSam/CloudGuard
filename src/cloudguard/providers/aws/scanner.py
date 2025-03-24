"""AWS service scanner base class.

This module provides the base class for all AWS service scanners.
"""

import abc
import logging
from typing import Dict, List, Optional, Any, Set
import boto3

from cloudguard.core.findings import Finding

class AwsServiceScanner(abc.ABC):
    """Base class for AWS service scanners."""
    
    service_name = "aws_service"  # Override in subclasses
    
    def __init__(self, session: boto3.Session, region: str):
        """Initialize service scanner.
        
        Args:
            session: Boto3 session for AWS API calls
            region: AWS region
        """
        self.session = session
        self.region = region
        self.client = self.session.client(self.get_client_name(), region_name=region)
        self.account_id = self.session.client('sts').get_caller_identity()['Account']
        
    def get_client_name(self) -> str:
        """Get the name of the boto3 client to use.
        
        Override in subclasses if the client name is different from service name.
        
        Returns:
            Boto3 client name
        """
        return self.service_name
    
    @abc.abstractmethod
    def scan(self) -> List[Finding]:
        """Scan the AWS service for security findings.
        
        Returns:
            List of findings
        """
        pass
    
    def get_resources(self) -> List[Dict[str, Any]]:
        """Get resources for this service.
        
        Override in subclasses to retrieve resources for the service.
        
        Returns:
            List of resource dictionaries
        """
        return []
    
    def is_global_service(self) -> bool:
        """Determine if this is a global service.
        
        Override in subclasses for global services.
        
        Returns:
            True if this is a global service, False otherwise
        """
        return False
    
    def get_service_tags(self) -> Set[str]:
        """Get tags specific to this service for mapping findings to frameworks.
        
        Override in subclasses to provide service-specific tags.
        
        Returns:
            Set of service-specific tags
        """
        return set()
    
    def get_resource_arn(self, resource_id: str) -> str:
        """Generate ARN for a resource.
        
        Args:
            resource_id: Resource ID
            
        Returns:
            ARN for the resource
        """
        if self.is_global_service():
            return f"arn:aws:{self.service_name}::{self.account_id}:{resource_id}"
        return f"arn:aws:{self.service_name}:{self.region}:{self.account_id}:{resource_id}" 