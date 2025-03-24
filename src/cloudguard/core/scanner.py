"""Core scanner implementation for CloudGuard."""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Type

from ..providers.base import BaseProvider
from ..utils.config import ScanConfig
from .findings import Finding, Severity

logger = logging.getLogger(__name__)


class Scanner:
    """Main scanner class that coordinates the scanning process."""

    def __init__(self, config: ScanConfig):
        """Initialize the scanner with configuration.

        Args:
            config: Scanner configuration settings
        """
        self.config = config
        self.providers: List[BaseProvider] = []
        self.findings: List[Finding] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def register_provider(self, provider: BaseProvider) -> None:
        """Register a cloud provider scanner.

        Args:
            provider: Provider scanner instance
        """
        self.providers.append(provider)
        logger.debug(f"Registered provider: {provider.name}")

    async def run(self) -> List[Finding]:
        """Run the scanning process across all registered providers.

        Returns:
            List of findings from the scan
        """
        self.start_time = datetime.utcnow()
        logger.info(f"Starting scan at {self.start_time.isoformat()}")

        # Run all provider scans concurrently
        tasks = [self._scan_provider(provider) for provider in self.providers]
        all_findings = await asyncio.gather(*tasks)
        
        # Flatten the list of findings
        self.findings = [finding for sublist in all_findings for finding in sublist]
        
        self.end_time = datetime.utcnow()
        duration = (self.end_time - self.start_time).total_seconds()
        logger.info(f"Scan completed at {self.end_time.isoformat()}")
        logger.info(f"Scan duration: {duration:.2f} seconds")
        logger.info(f"Total findings: {len(self.findings)}")
        
        # Summary by severity
        severity_counts = self._count_by_severity()
        for severity, count in severity_counts.items():
            logger.info(f"{severity.name}: {count}")
        
        return self.findings

    async def _scan_provider(self, provider: BaseProvider) -> List[Finding]:
        """Run scan for a specific provider.

        Args:
            provider: The provider scanner to run

        Returns:
            List of findings from this provider
        """
        logger.info(f"Starting scan for provider: {provider.name}")
        try:
            findings = await provider.scan()
            logger.info(f"Completed scan for provider: {provider.name}, "
                        f"found {len(findings)} issues")
            return findings
        except Exception as e:
            logger.error(f"Error scanning provider {provider.name}: {str(e)}", 
                         exc_info=True)
            return []

    def _count_by_severity(self) -> Dict[Severity, int]:
        """Count findings by severity level.

        Returns:
            Dictionary mapping severity levels to counts
        """
        result = {level: 0 for level in Severity}
        for finding in self.findings:
            result[finding.severity] += 1
        return result

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Filter findings by severity level.

        Args:
            severity: Severity level to filter by

        Returns:
            List of findings with the specified severity
        """
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_service(self, service: str) -> List[Finding]:
        """Filter findings by cloud service.

        Args:
            service: Service name to filter by

        Returns:
            List of findings for the specified service
        """
        return [f for f in self.findings if f.service == service]

    def get_finding_statistics(self) -> Dict[str, Any]:
        """Generate statistics about the scan findings.

        Returns:
            Dictionary with statistical information
        """
        stats = {
            "total_findings": len(self.findings),
            "by_severity": self._count_by_severity(),
            "by_provider": {},
            "by_service": {},
            "scan_duration": None
        }
        
        if self.start_time and self.end_time:
            stats["scan_duration"] = (self.end_time - self.start_time).total_seconds()
        
        # Count by provider
        provider_counts = {}
        for finding in self.findings:
            provider_counts[finding.provider] = provider_counts.get(finding.provider, 0) + 1
        stats["by_provider"] = provider_counts
        
        # Count by service
        service_counts = {}
        for finding in self.findings:
            service_counts[finding.service] = service_counts.get(finding.service, 0) + 1
        stats["by_service"] = service_counts
        
        return stats 