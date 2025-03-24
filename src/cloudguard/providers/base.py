"""Base class for cloud provider scanners."""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Type

from ..core.findings import Finding
from ..utils.config import ProviderConfig

logger = logging.getLogger(__name__)


class BaseProvider(ABC):
    """Base class for all cloud provider scanners."""

    name: str = "base"
    """Name of the provider."""

    def __init__(self, config: ProviderConfig):
        """Initialize the provider scanner.

        Args:
            config: Provider-specific configuration
        """
        self.config = config
        logger.debug(f"Initialized {self.name} provider scanner")

    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the cloud provider.

        Returns:
            True if authentication succeeded, False otherwise
        """
        pass

    @abstractmethod
    async def scan(self) -> List[Finding]:
        """Run a security scan for this provider.

        Returns:
            List of security findings
        """
        pass

    @abstractmethod
    async def get_resources(self) -> Dict[str, List[Dict]]:
        """Get a list of resources from this provider.

        Returns:
            Dictionary mapping resource types to lists of resources
        """
        pass

    @property
    @abstractmethod
    def supported_services(self) -> Set[str]:
        """Get the set of services supported by this provider.

        Returns:
            Set of service names
        """
        pass 