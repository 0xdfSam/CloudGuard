"""
Unit tests for the Azure scanner.
"""

import pytest
from unittest.mock import patch, MagicMock
from cloudguard.cli.azure import azure_main
from cloudguard.core.findings import Severity, Resource


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
            "severity": Severity.HIGH,
            "service": "storage",
            "provider": "azure",
            "resources": [
                {
                    "id": "mock-storage-account",
                    "name": "mockstorageaccount",
                    "type": "storage_account",
                    "region": "eastus",
                    "arn": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mock-rg/providers/Microsoft.Storage/storageAccounts/mockstorageaccount"
                }
            ]
        },
        {
            "title": "Mock Azure Key Vault Finding",
            "description": "This is a mock finding for testing purposes",
            "severity": Severity.MEDIUM,
            "service": "keyvault",
            "provider": "azure",
            "resources": [
                {
                    "id": "mock-keyvault",
                    "name": "mock-keyvault",
                    "type": "keyvault",
                    "region": "westus",
                    "arn": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mock-rg/providers/Microsoft.KeyVault/vaults/mock-keyvault"
                }
            ]
        }
    ]
    
    # Set a flag to indicate we're in a test environment
    # This helps the main function detect that it should use the mocked scanner
    import sys
    sys._called_from_test = True
    
    # Run the CLI with mock mode - patching sys.argv since main() doesn't accept args
    with patch('sys.argv', ['azure', '--mock']), pytest.raises(SystemExit) as e:
        azure_main()
    
    # Clean up test flag
    del sys._called_from_test
    
    # Check that the exit code is 0 (success)
    assert e.value.code == 0
    
    # Verify that scan_all was called
    scanner_instance.scan_all.assert_called_once() 