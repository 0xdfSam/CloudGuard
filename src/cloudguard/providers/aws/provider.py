"""AWS provider scanner implementation."""

import asyncio
import logging
from typing import Dict, List, Optional, Set, Type

import boto3
import botocore.exceptions

from ...core.findings import Finding
from ...utils.config import AwsConfig
from ..base import BaseProvider
from .s3 import S3Scanner

logger = logging.getLogger(__name__)


class AwsProvider(BaseProvider):
    """AWS cloud provider scanner."""

    name = "aws"

    def __init__(self, config: AwsConfig):
        """Initialize the AWS provider scanner.

        Args:
            config: AWS-specific configuration
        """
        super().__init__(config)
        self.aws_config = config
        self.sessions: Dict[str, boto3.Session] = {}
        self._supported_services = {
            "s3", "iam", "ec2", "kms", "apigateway", "lambda", "rds"
        }
        self.scanners = {}

    async def authenticate(self) -> bool:
        """Authenticate with AWS.

        Returns:
            True if authentication succeeded, False otherwise
        """
        try:
            # Create a session for each configured region
            for region in self.aws_config.regions:
                logger.debug(f"Creating AWS session for region {region}")
                session = boto3.Session(
                    region_name=region,
                    profile_name=self.aws_config.profile
                )
                
                # Verify we can access the account
                sts = session.client('sts')
                identity = sts.get_caller_identity()
                account_id = identity['Account']
                logger.info(f"Authenticated to AWS account {account_id} in region {region}")
                
                self.sessions[region] = session
            
            return True
        except botocore.exceptions.ClientError as e:
            logger.error(f"AWS authentication error: {str(e)}")
            return False
        except botocore.exceptions.NoCredentialsError:
            logger.error("AWS credentials not found")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during AWS authentication: {str(e)}")
            return False

    async def scan(self) -> List[Finding]:
        """Run security scans for AWS services.

        Returns:
            List of security findings
        """
        if not self.sessions:
            success = await self.authenticate()
            if not success:
                logger.error("AWS authentication failed, cannot perform scan")
                return []

        # Initialize scanners for enabled services
        self._init_scanners()
        
        # Run all scanners concurrently
        tasks = []
        for service, scanner in self.scanners.items():
            if service in self.aws_config.services:
                logger.info(f"Starting AWS {service} scan")
                tasks.append(scanner.scan())
        
        # Gather results
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        findings = []
        for i, result in enumerate(scan_results):
            service = list(self.scanners.keys())[i]
            if isinstance(result, Exception):
                logger.error(f"Error scanning AWS {service}: {str(result)}")
            else:
                logger.info(f"Completed AWS {service} scan, found {len(result)} issues")
                findings.extend(result)
        
        return findings

    async def get_resources(self) -> Dict[str, List[Dict]]:
        """Get a list of resources from AWS.

        Returns:
            Dictionary mapping resource types to lists of resources
        """
        if not self.sessions:
            success = await self.authenticate()
            if not success:
                logger.error("AWS authentication failed, cannot get resources")
                return {}

        # Initialize scanners if not already done
        self._init_scanners()
        
        # Get resources from all scanners
        resources = {}
        for service, scanner in self.scanners.items():
            if service in self.aws_config.services:
                service_resources = await scanner.get_resources()
                resources.update(service_resources)
        
        return resources

    @property
    def supported_services(self) -> Set[str]:
        """Get the set of services supported by this provider.

        Returns:
            Set of service names
        """
        return self._supported_services

    def _init_scanners(self) -> None:
        """Initialize service-specific scanners."""
        
        # Only initialize scanners that haven't been initialized yet
        if not self.scanners:
            enabled_services = set(self.aws_config.services).intersection(self._supported_services)
            
            # Initialize scanners for enabled services
            for service in enabled_services:
                if service == "s3":
                    self.scanners["s3"] = S3Scanner(self.sessions, self.aws_config)
                # Add other service scanners as they're implemented
                # elif service == "iam":
                #     self.scanners["iam"] = IamScanner(self.sessions, self.aws_config)
                # etc.
            
            logger.debug(f"Initialized AWS scanners for services: {', '.join(self.scanners.keys())}")