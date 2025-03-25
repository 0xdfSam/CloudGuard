"""Main command-line interface for CloudGuard."""

import os
import sys
import click
import time
import logging
import asyncio
from typing import List, Optional, Dict, Any, Set
from datetime import datetime

from cloudguard.core.scanner import Scanner
from cloudguard.core.findings import Severity
from cloudguard.core.reporting import generate_reports
from cloudguard.utils.logger import CloudGuardLogger, LoggingConfig
from cloudguard.utils.config import load_config, ScanConfig
from cloudguard.providers.aws import AwsProvider
from cloudguard.providers.azure import AzureProvider

# Define version
__version__ = "0.1.0"


def setup_logging(config: ScanConfig) -> None:
    """Set up logging based on configuration.
    
    Args:
        config: Scan configuration
    """
    log_config = LoggingConfig(
        level=config.log_level,
        log_file=config.log_file
    )
    CloudGuardLogger.setup(log_config)


def get_scanner(config: ScanConfig) -> Scanner:
    """Create and configure a scanner based on configuration.
    
    Args:
        config: Scan configuration
        
    Returns:
        Configured scanner
    """
    scanner = Scanner(config=config)
    
    # Get mock mode from config
    mock_mode = getattr(config, "mock", False)
    
    # Register providers based on configuration
    if "aws" in config.providers and config.aws.enabled:
        aws_provider = AwsProvider(config.aws, mock=mock_mode)
        scanner.register_provider(aws_provider)
    
    # Azure provider will be added in future version
    if "azure" in config.providers and getattr(config.azure, "enabled", False):
        azure_provider = AzureProvider(config.azure, mock=mock_mode)
        scanner.register_provider(azure_provider)
    
    return scanner


def get_severity_as_int(severity: str) -> int:
    """Convert severity string to numeric value for comparison.
    
    Args:
        severity: Severity string
        
    Returns:
        Numeric severity value (higher is more severe)
    """
    severity_map = {
        "INFO": 1,
        "LOW": 2,
        "MEDIUM": 3,
        "HIGH": 4,
        "CRITICAL": 5
    }
    return severity_map.get(severity.upper(), 0)


def should_fail_scan(fail_on_severity: Optional[str], findings_by_severity: Dict[str, int]) -> bool:
    """Determine if scan should fail based on findings and threshold.
    
    Args:
        fail_on_severity: Severity threshold for failing scan
        findings_by_severity: Dictionary of finding counts by severity
        
    Returns:
        True if scan should fail, False otherwise
    """
    if not fail_on_severity or fail_on_severity.upper() == "NONE":
        return False
    
    threshold = get_severity_as_int(fail_on_severity)
    
    # Check if any findings exist at or above the threshold
    for severity, count in findings_by_severity.items():
        if get_severity_as_int(severity) >= threshold and count > 0:
            return True
    
    return False


@click.group()
@click.version_option(version=__version__)
@click.option(
    "--mock",
    is_flag=True,
    help="Run in mock mode without connecting to cloud providers."
)
@click.pass_context
def cli(ctx, mock: bool = False):
    """CloudGuard: Automated Vulnerability Scanner for Cloud Services."""
    # Store mock flag in context for subcommands
    ctx.obj = {'mock': mock}


@cli.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to configuration file."
)
@click.option(
    "--output-dir", "-o",
    type=click.Path(),
    help="Directory to store scan results."
)
@click.option(
    "--scan-name", "-n",
    type=str,
    help="Name for the scan."
)
@click.option(
    "--providers",
    type=str,
    help="Comma-separated list of cloud providers to scan (aws, azure)."
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                      case_sensitive=False),
    help="Log level."
)
@click.option(
    "--log-file",
    type=click.Path(),
    help="Log file path."
)
@click.option(
    "--fail-on-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"],
                      case_sensitive=False),
    help="Fail the scan if findings at or above this severity are found."
)
@click.pass_context
def scan(
    ctx,
    config: Optional[str],
    output_dir: Optional[str],
    scan_name: Optional[str],
    providers: Optional[str],
    log_level: Optional[str],
    log_file: Optional[str],
    fail_on_severity: Optional[str]
) -> None:
    """Run a security scan against cloud providers."""
    start_time = time.time()
    
    # Get mock flag from context
    mock = ctx.obj.get('mock', False) if ctx.obj else False
    
    # Parse CLI args
    cli_args: Dict[str, Any] = {}
    if output_dir:
        cli_args["output_dir"] = output_dir
    if scan_name:
        cli_args["scan_name"] = scan_name
    if providers:
        cli_args["providers"] = providers.split(",")
    if log_level:
        cli_args["log_level"] = log_level
    if log_file:
        cli_args["log_file"] = log_file
    if fail_on_severity:
        cli_args["fail_on_severity"] = fail_on_severity
    # Add mock flag to CLI args
    cli_args["mock"] = mock
    
    # Load configuration
    try:
        scan_config = load_config(config, cli_args)
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)
    
    # Set up logging
    setup_logging(scan_config)
    logger = logging.getLogger(__name__)
    logger.info(f"Starting CloudGuard scan: {scan_config.scan_name}")
    
    # Create scanner
    scanner = get_scanner(scan_config)
    
    # Run scan
    try:
        # Use asyncio.run to execute the coroutine
        findings = asyncio.run(scanner.run())
        logger.info(f"Scan completed with {len(findings)} findings")
    except Exception as e:
        logger.error(f"Error during scan: {e}", exc_info=True)
        click.echo(f"Error during scan: {e}", err=True)
        sys.exit(1)
    
    # Generate timestamp for report filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    if not os.path.exists(scan_config.output_dir):
        os.makedirs(scan_config.output_dir)
    
    # Generate reports
    try:
        report_files = generate_reports(
            findings=findings,
            config=scan_config.report
        )
        
        for report_path in report_files:
            logger.info(f"Generated report: {report_path}")
            click.echo(f"Generated report: {report_path}")
    except Exception as e:
        logger.error(f"Error generating reports: {e}", exc_info=True)
        click.echo(f"Error generating reports: {e}", err=True)
        sys.exit(1)
    
    # Calculate scan statistics
    statistics = scanner.get_finding_statistics()
    findings_by_severity = statistics["by_severity"]
    
    # Print summary
    click.echo("\nScan Summary:")
    click.echo(f"Total findings: {len(findings)}")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = findings_by_severity.get(severity, 0)
        click.echo(f"{severity}: {count}")
    
    elapsed_time = time.time() - start_time
    click.echo(f"\nScan completed in {elapsed_time:.2f} seconds")
    
    # Check if scan should fail
    if scan_config.fail_on_severity and should_fail_scan(scan_config.fail_on_severity, findings_by_severity):
        logger.warning(f"Scan failed: Findings at or above {scan_config.fail_on_severity} severity detected")
        click.echo(f"Scan failed: Findings at or above {scan_config.fail_on_severity} severity detected", err=True)
        sys.exit(1)


@cli.command()
@click.option(
    "--aws",
    is_flag=True,
    help="Verify AWS credentials."
)
@click.option(
    "--azure",
    is_flag=True,
    help="Verify Azure credentials."
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to configuration file."
)
def verify(aws: bool, azure: bool, config: Optional[str]) -> None:
    """Verify cloud provider credentials."""
    # Load configuration
    try:
        scan_config = load_config(config)
    except Exception as e:
        click.echo(f"Error loading configuration: {e}", err=True)
        sys.exit(1)
    
    # Set up logging
    setup_logging(scan_config)
    logger = logging.getLogger(__name__)
    
    # If no provider specified, check all enabled providers
    if not (aws or azure):
        aws = "aws" in scan_config.providers
        azure = "azure" in scan_config.providers
    
    # Verify AWS credentials
    if aws:
        try:
            logger.info("Verifying AWS credentials")
            click.echo("Verifying AWS credentials...")
            aws_provider = AwsProvider(scan_config.aws)
            aws_provider.authenticate()
            click.echo("AWS credentials verified successfully!")
        except Exception as e:
            logger.error(f"AWS credential verification failed: {e}", exc_info=True)
            click.echo(f"AWS credential verification failed: {e}", err=True)
            sys.exit(1)
    
    # Verify Azure credentials (to be implemented in future version)
    if azure:
        click.echo("Azure provider verification not yet implemented")
    
    click.echo("All specified credentials verified successfully!")


def main():
    """Run the CloudGuard CLI."""
    cli(obj={})


if __name__ == "__main__":
    main() 