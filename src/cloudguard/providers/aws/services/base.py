"""Base class for AWS service scanners (compatibility module).

This module imports the AwsServiceScanner from the main scanner module for compatibility.
"""

from cloudguard.providers.aws.scanner import AwsServiceScanner

# This file exists for backwards compatibility
# New scanners should inherit from cloudguard.providers.aws.scanner.AwsServiceScanner directly 