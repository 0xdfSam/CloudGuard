"""
Unit tests for the AWS scanner.
"""

import pytest
from unittest.mock import patch, MagicMock
from cloudguard.cli.aws import main as aws_main
from cloudguard.core.findings import Severity


@patch('cloudguard.cli.aws.AwsScanner')
def test_aws_scanner_mock_mode(mock_scanner):
    """Test AWS scanner in mock mode."""
    # Mock the scanner instance
    scanner_instance = MagicMock()
    mock_scanner.return_value = scanner_instance
    
    # Mock the scan_all method to return some findings
    scanner_instance.scan_all.return_value = [
        {
            "title": "Mock AWS S3 Finding",
            "description": "This is a mock finding for testing purposes",
            "severity": Severity.HIGH,
            "service": "s3",
            "resource": {
                "id": "mock-bucket",
                "name": "mock-bucket",
                "type": "s3_bucket",
                "region": "us-east-1",
                "service": "s3",
                "arn": "arn:aws:s3:::mock-bucket"
            }
        },
        {
            "title": "Mock AWS IAM Finding",
            "description": "This is a mock finding for testing purposes",
            "severity": Severity.MEDIUM,
            "service": "iam",
            "resource": {
                "id": "mock-user",
                "name": "mock-user",
                "type": "iam_user",
                "region": "global",
                "service": "iam",
                "arn": "arn:aws:iam::123456789012:user/mock-user"
            }
        }
    ]
    
    # Run the CLI with mock mode
    with pytest.raises(SystemExit) as e:
        aws_main(["--mock"])
    
    # Check that the exit code is 0 (success)
    assert e.value.code == 0
    
    # Verify that scan_all was called
    scanner_instance.scan_all.assert_called_once() 