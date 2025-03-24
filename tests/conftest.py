"""
Configuration and fixtures for pytest.
"""

import pytest
from cloudguard.core.findings import Finding, Severity, Resource


@pytest.fixture
def mock_resource():
    """Return a mock resource for testing."""
    return Resource(
        id="test-resource",
        name="Test Resource",
        type="test-type",
        region="us-east-1",
        service="s3",
        arn="arn:aws:s3:::test-bucket",
    )


@pytest.fixture
def mock_finding(mock_resource):
    """Return a mock finding for testing."""
    return Finding(
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        resource=mock_resource,
        remediation="Fix this issue",
    ) 