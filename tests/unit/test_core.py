"""
Unit tests for the core module.
"""

import pytest
from cloudguard.core.findings import Finding, Severity, Resource


def test_severity_enum():
    """Test the Severity enum."""
    assert Severity.LOW.value < Severity.MEDIUM.value
    assert Severity.MEDIUM.value < Severity.HIGH.value
    assert Severity.HIGH.value < Severity.CRITICAL.value


def test_finding_creation():
    """Test creating a Finding object."""
    resource = Resource(
        id="test-resource",
        name="Test Resource",
        type="test-type",
        region="us-east-1",
        arn="arn:aws:s3:::test-bucket",
    )
    
    finding = Finding(
        title="Test Finding",
        description="This is a test finding",
        severity=Severity.MEDIUM,
        service="s3",
        provider="aws",
        resources=[resource],
        remediation="Fix this issue",
    )
    
    assert finding.title == "Test Finding"
    assert finding.description == "This is a test finding"
    assert finding.severity == Severity.MEDIUM
    assert finding.resources[0] == resource
    assert finding.remediation == "Fix this issue" 