"""
Command-line interface for AWS scanner.

This module provides a command-line interface for the AWS scanner.
"""

import argparse
import json
import logging
import sys
import csv
import asyncio
from io import StringIO
from typing import Dict, List, Any, Optional

from cloudguard.providers.aws.main import AwsScanner
from cloudguard.core.findings import Finding, Severity, Resource
from cloudguard.utils.logger import CloudGuardLogger, get_logger

logger = get_logger(__name__)


def configure_parser() -> argparse.ArgumentParser:
    """Configure the command-line argument parser.
    
    Returns:
        Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="CloudGuard - AWS Security Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # AWS Authentication Options
    auth_group = parser.add_argument_group("AWS Authentication Options")
    auth_group.add_argument(
        "--access-key-id",
        help="AWS access key ID",
        dest="aws_access_key_id",
        default=None
    )
    auth_group.add_argument(
        "--secret-access-key",
        help="AWS secret access key",
        dest="aws_secret_access_key",
        default=None
    )
    auth_group.add_argument(
        "--session-token",
        help="AWS session token for temporary credentials",
        dest="aws_session_token",
        default=None
    )
    auth_group.add_argument(
        "--profile",
        help="AWS profile name to use",
        dest="profile_name",
        default=None
    )
    auth_group.add_argument(
        "--mock",
        help="Use mock data instead of connecting to AWS (for testing)",
        dest="use_mock",
        action="store_true",
        default=False
    )
    
    # Scan Options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument(
        "--regions",
        help="Comma-separated list of AWS regions to scan (default: all regions)",
        dest="regions",
        default=None
    )
    scan_group.add_argument(
        "--services",
        help="Comma-separated list of AWS services to scan (default: all supported services)",
        dest="services",
        default=None
    )
    scan_group.add_argument(
        "--max-workers",
        help="Maximum number of worker threads for parallel scanning",
        dest="max_workers",
        type=int,
        default=10
    )
    
    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output",
        help="Output file path (default: stdout)"
    )
    output_group.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format"
    )
    output_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    output_group.add_argument(
        "--summary",
        action="store_true",
        help="Display only summary information"
    )
    output_group.add_argument(
        "--resources",
        action="store_true",
        help="Include resources information in the output"
    )
    
    return parser


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = configure_parser()
    return parser.parse_args()


def run_scan(args: argparse.Namespace) -> Dict[str, Any]:
    """Run the AWS security scan.
    
    Args:
        args: Command-line arguments
        
    Returns:
        Dictionary with scan results
    """
    # Configure logging
    log_level = "DEBUG" if args.verbose else "INFO"
    CloudGuardLogger.setup({"level": log_level})
    
    # Parse regions
    regions = None
    if args.regions:
        regions = args.regions.split(",")
    
    # Parse services
    services = None
    if args.services:
        services = args.services.split(",")
    
    if args.use_mock:
        # Create a mock finder with sample findings
        logger.info("Using mock mode, returning mock findings")
        
        # Create mock findings
        mock_findings = [
            Finding(
                title="Mock AWS S3 Finding",
                description="This is a mock finding for testing purposes",
                provider="aws",
                service="s3",
                severity=Severity.HIGH,
                resources=[
                    Resource(
                        id="mock-bucket",
                        name="mock-bucket",
                        type="s3_bucket",
                        region="us-east-1",
                        arn="arn:aws:s3:::mock-bucket"
                    )
                ]
            ),
            Finding(
                title="Mock AWS IAM Finding",
                description="This is a mock finding for testing purposes",
                provider="aws",
                service="iam",
                severity=Severity.MEDIUM,
                resources=[
                    Resource(
                        id="AKIA1234567890EXAMPLE",
                        name="mock-user",
                        type="iam_user",
                        region="global",
                        arn="arn:aws:iam::123456789012:user/mock-user"
                    )
                ]
            )
        ]
        
        # Create mock resources
        mock_resources = {
            "s3": [
                {
                    "id": "mock-bucket",
                    "name": "mock-bucket",
                    "type": "s3_bucket",
                    "region": "us-east-1",
                    "arn": "arn:aws:s3:::mock-bucket",
                    "created": "2025-03-24T12:00:00Z",
                    "tags": {
                        "Environment": "Development",
                        "Project": "CloudGuard"
                    }
                }
            ],
            "iam": [
                {
                    "id": "AKIA1234567890EXAMPLE",
                    "name": "mock-user",
                    "type": "iam_user",
                    "region": "global",
                    "arn": "arn:aws:iam::123456789012:user/mock-user",
                    "created": "2025-03-24T12:00:00Z",
                    "tags": {
                        "Department": "Security",
                        "Project": "CloudGuard"
                    }
                }
            ]
        }
        
        # Generate summary
        summary = generate_summary(mock_findings)
        
        # Prepare results
        results = {
            "summary": summary
        }
        
        if not args.summary:
            results["findings"] = [finding.to_dict() for finding in mock_findings]
        
        if args.resources:
            results["resources"] = mock_resources
        
        logger.info(f"Mock scan completed, found {len(mock_findings)} issues")
        return results
    
    # Create scanner
    scanner = AwsScanner(
        aws_access_key_id=args.aws_access_key_id,
        aws_secret_access_key=args.aws_secret_access_key,
        aws_session_token=args.aws_session_token,
        profile_name=args.profile_name,
        regions=regions,
        services=services,
        max_workers=args.max_workers
    )
    
    # Run scan
    logger.info("Starting AWS security scan")
    findings = scanner.scan()
    
    # Get resources if requested
    resources = {}
    if args.resources:
        logger.info("Retrieving AWS resources")
        resources = scanner.get_resources()
    
    # Generate summary
    summary = generate_summary(findings)
    
    # Prepare results
    results = {
        "summary": summary
    }
    
    if not args.summary:
        results["findings"] = [finding.to_dict() for finding in findings]
    
    if args.resources:
        results["resources"] = resources
    
    logger.info(f"Scan completed, found {len(findings)} issues")
    return results


def generate_summary(findings: List[Finding]) -> Dict[str, Any]:
    """Generate a summary of findings.
    
    Args:
        findings: List of findings
        
    Returns:
        Summary dictionary
    """
    total_findings = len(findings)
    findings_by_service = {}
    findings_by_severity = {}
    findings_by_region = {}
    
    for finding in findings:
        # Count by service
        service = finding.service
        findings_by_service[service] = findings_by_service.get(service, 0) + 1
        
        # Count by severity
        if hasattr(finding.severity, 'name'):
            # Handle Severity enum objects
            severity = finding.severity.name
        else:
            # Handle integer severity values
            severity_map = {
                0: "INFO",
                1: "LOW",
                2: "MEDIUM",
                3: "HIGH",
                4: "CRITICAL"
            }
            severity = severity_map.get(finding.severity, "UNKNOWN")
            
        findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
        
        # Count by region
        for resource in finding.resources:
            if resource.region:
                region = resource.region
                findings_by_region[region] = findings_by_region.get(region, 0) + 1
    
    return {
        "total_findings": total_findings,
        "findings_by_service": findings_by_service,
        "findings_by_severity": findings_by_severity,
        "findings_by_region": findings_by_region
    }


def output_results(results: Dict[str, Any], args: argparse.Namespace) -> None:
    """Output scan results.
    
    Args:
        results: Scan results
        args: Command-line arguments
    """
    # Convert findings to dictionaries for serialization
    if 'findings' in results and isinstance(results['findings'], list):
        results['findings'] = [
            finding.to_dict() if hasattr(finding, 'to_dict') else finding
            for finding in results['findings']
        ]
    
    if args.format == "json":
        output = json.dumps(results, indent=2, default=lambda o: str(o))
    elif args.format == "csv":
        output = convert_to_csv(results)
    else:
        output = str(results)
    
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        logger.info(f"Results written to {args.output}")
    else:
        print(output)


def convert_to_csv(results: Dict[str, Any]) -> str:
    """Convert results to CSV format.
    
    Args:
        results: Scan results
        
    Returns:
        CSV-formatted string
    """
    output = StringIO()
    writer = csv.writer(output)
    
    # Write summary
    writer.writerow(["Summary"])
    writer.writerow(["Total Findings", results["summary"]["total_findings"]])
    
    # Write findings by service
    writer.writerow([])
    writer.writerow(["Findings by Service"])
    for service, count in results["summary"]["findings_by_service"].items():
        writer.writerow([service, count])
    
    # Write findings by severity
    writer.writerow([])
    writer.writerow(["Findings by Severity"])
    for severity, count in results["summary"]["findings_by_severity"].items():
        writer.writerow([severity, count])
    
    # Write findings by region
    writer.writerow([])
    writer.writerow(["Findings by Region"])
    for region, count in results["summary"]["findings_by_region"].items():
        writer.writerow([region, count])
    
    # Write findings if available
    if "findings" in results:
        writer.writerow([])
        writer.writerow(["Findings"])
        writer.writerow(["Title", "Service", "Severity", "Description", "Remediation"])
        
        for finding in results["findings"]:
            # Get remediation summary if available
            remediation_summary = "Not available"
            if finding.get("remediation") and finding["remediation"].get("summary"):
                remediation_summary = finding["remediation"]["summary"]
            
            writer.writerow([
                finding["title"],
                finding["service"],
                finding["severity"],
                finding["description"],
                remediation_summary
            ])
    
    # Write resources if available
    if "resources" in results:
        writer.writerow([])
        writer.writerow(["Resources"])
        writer.writerow(["Service", "Name", "Type", "Region", "ARN"])
        
        for service, resources in results["resources"].items():
            for resource in resources:
                writer.writerow([
                    service,
                    resource.get("name", "N/A"),
                    resource.get("type", "N/A"),
                    resource.get("region", "N/A"),
                    resource.get("arn", "N/A")
                ])
    
    return output.getvalue()


def main() -> int:
    """Main entry point for the AWS CLI.
    
    Returns:
        Exit code
    """
    try:
        args = parse_args()
        results = run_scan(args)
        
        if "error" in results:
            logger.error(results["error"])
            return 1
        
        output_results(results, args)
        return 0
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Error running scan: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main()) 