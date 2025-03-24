"""
Unit tests for the Azure scanner.
"""

import pytest
from unittest.mock import patch, MagicMock
from cloudguard.cli.azure import main as azure_main
from cloudguard.core.findings import Severity


@patch('cloudguard.cli.azure.AzureScanner')
def test_azure_scanner_mock_mode(mock_scanner):
    """Test Azure scanner in mock mode."""
    # Mock the scanner instance
    scanner_instance = MagicMock()
    mock_scanner.return_value = scanner_instance
    
    # Mock the scan_all method to return some findings
    scanner_instance.scan_all.return_value = [
        {
            "title": "Mock Azure Storage Finding",
            "description": "This is a mock finding for testing purposes",
            "severity": Severity.HIGH.value,
            "service": "storage",
            "resource": {
                "id": "mock-storage-account",
                "name": "mockstorageaccount",
                "type": "storage_account",
                "region": "eastus",
                "service": "storage",
                "arn": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mock-rg/providers/Microsoft.Storage/storageAccounts/mockstorageaccount"
            }
        },
        {
            "title": "Mock Azure Key Vault Finding",
            "description": "This is a mock finding for testing purposes",
            "severity": Severity.MEDIUM.value,
            "service": "keyvault",
            "resource": {
                "id": "mock-keyvault",
                "name": "mock-keyvault",
                "type": "keyvault",
                "region": "westus",
                "service": "keyvault",
                "arn": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mock-rg/providers/Microsoft.KeyVault/vaults/mock-keyvault"
            }
        }
    ]
    
    # Run the CLI with mock mode
    with pytest.raises(SystemExit) as e:
        azure_main(["--mock"])
    
    # Check that the exit code is 0 (success)
    assert e.value.code == 0
    
    # Verify that scan_all was called
    scanner_instance.scan_all.assert_called_once() 