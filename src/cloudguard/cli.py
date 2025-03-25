"""Command-line interface for CloudGuard scanner."""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

import click

from .core.scanner import Scanner
from .core.findings import Finding, Severity
from .core.reporting import generate_reports
from .providers.aws.provider import AwsProvider
from .utils.config import ScanConfig, load_config, get_env_config, merge_configs

# Configure logging
logger = logging.getLogger("cloudguard")


def setup_logging(log_level: str) -> None:
    """Configure logging for the application.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")
    
    # Configure root logger
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    
    # Set more restrictive levels for noisy third-party libraries
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("azure").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


@click.group()
@click.version_option()
def cli():
    """CloudGuard - Cloud Security Scanner.
    
    Automated vulnerability scanner for AWS and Azure cloud services.
    """
    pass


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to configuration file.")
@click.option("--output-dir", "-o", type=click.Path(), help="Directory to store scan results.")
@click.option("--providers", help="Comma-separated list of cloud providers to scan (aws, azure).")
@click.option("--aws-profile", help="AWS profile name")
@click.option("--aws-region", help="AWS region")
@click.option("--aws-services", help="AWS services to scan (comma-separated)")
@click.option("--azure/--no-azure", default=False, help="Enable/disable Azure scan")
@click.option("--all-providers", is_flag=True, help="Scan all supported providers")
@click.option(
    "--report-format", "-f",
    type=click.Choice(["json", "html", "csv", "console", "all"], case_sensitive=False),
    default="console",
    help="Report format"
)
@click.option(
    "--min-severity", "-s",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    default="LOW",
    help="Minimum severity level to include in report"
)
@click.option(
    "--fail-on", "-F",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"], case_sensitive=False),
    default="HIGH",
    help="Minimum severity level that causes a non-zero exit code"
)
@click.option("--log-level", "-l", default="INFO", help="Logging level")
@click.option("--scan-id", help="Custom scan identifier")
@click.option("--mock", is_flag=True, help="Use mock data instead of connecting to cloud providers")
def scan(
    config: Optional[str],
    output_dir: Optional[str],
    providers: Optional[str],
    aws_profile: Optional[str],
    aws_region: Optional[str],
    aws_services: Optional[str],
    azure: bool,
    all_providers: bool,
    report_format: str,
    min_severity: str,
    fail_on: str,
    log_level: str,
    scan_id: Optional[str],
    mock: bool,
):
    """Scan cloud providers for security vulnerabilities."""
    # Load configuration
    if config:
        try:
            scan_config = load_config_from_file(config)
        except Exception as e:
            click.echo(f"Error loading configuration file: {e}", err=True)
            sys.exit(1)
    else:
        scan_config = load_config()
    
    # Override with environment variables
    env_config = get_env_config()
    if env_config:
        scan_config = merge_configs(scan_config, env_config)
    
    # Override with command-line options
    cli_config = {}
    
    if output_dir:
        cli_config["output_dir"] = output_dir
        cli_config["report"] = {"output_dir": output_dir}
    
    if providers:
        cli_config["providers"] = providers
    
    if aws_profile:
        if not "aws" in cli_config:
            cli_config["aws"] = {}
        cli_config["aws"]["profile_name"] = aws_profile
    
    if aws_region:
        if not "aws" in cli_config:
            cli_config["aws"] = {}
        cli_config["aws"]["regions"] = [r.strip() for r in aws_region.split(",")]
    
    if aws_services:
        if not "aws" in cli_config:
            cli_config["aws"] = {}
        cli_config["aws"]["services"] = set(s.strip() for s in aws_services.split(","))
    
    if report_format != "console":
        if not "report" in cli_config:
            cli_config["report"] = {}
        
        if report_format == "all":
            cli_config["report"]["formats"] = {"json", "html", "csv", "console"}
        else:
            cli_config["report"]["formats"] = {report_format}
    
    if min_severity:
        if not "report" in cli_config:
            cli_config["report"] = {}
        cli_config["report"]["min_severity"] = min_severity
    
    if fail_on:
        cli_config["fail_on_severity"] = fail_on
    
    if log_level:
        cli_config["log_level"] = log_level
    
    if scan_id:
        cli_config["scan_id"] = scan_id
    else:
        # Generate scan ID if not provided
        cli_config["scan_id"] = f"scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    if mock:
        cli_config["mock"] = True
    
    # Merge command-line options with config
    scan_config = merge_configs(scan_config, cli_config)
    
    # Set up logging
    setup_logging(scan_config.log_level)
    
    # Make sure output directory exists
    os.makedirs(scan_config.output_dir, exist_ok=True)
    
    # Run the scan
    logger.info(f"Starting scan with ID: {scan_config.scan_id}")
    
    try:
        asyncio.run(run_scan(scan_config, azure, all_providers))
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Error during scan: {e}")
        sys.exit(1)


async def run_scan(scan_config: ScanConfig, azure: bool, all_providers: bool) -> None:
    """Run the scan with the provided configuration.
    
    Args:
        scan_config: Scan configuration
        azure: Whether to scan Azure resources
        all_providers: Whether to scan all supported providers
    """
    # Initialize scanner
    scanner = Scanner(scan_id=scan_config.scan_id)
    
    # Process providers
    providers_to_scan = []
    
    # Check --providers CLI option
    if "providers" in scan_config.__dict__ and scan_config.providers:
        providers_to_scan = [p.strip().lower() for p in scan_config.providers.split(",")]
    
    # Add AWS if flag is set
    if aws:
        providers_to_scan.append("aws")
    
    # Add all providers if flag is set
    if all_providers:
        providers_to_scan.extend(["aws", "azure"])
    
    # Remove duplicates
    providers_to_scan = list(set(providers_to_scan))
    
    logger.info(f"Scanning providers: {', '.join(providers_to_scan) if providers_to_scan else 'none'}")
    
    # Register providers
    if "aws" in providers_to_scan:
        aws_config = scan_config.aws if hasattr(scan_config, "aws") else {}
        if scan_config.get("mock", False):
            aws_config["use_mock"] = True
        aws_provider = AwsProvider(config=aws_config)
        scanner.register_provider(aws_provider)
    
    if "azure" in providers_to_scan:
        # Azure provider would be registered here when implemented
        logger.info("Azure provider is not fully implemented yet")
    
    # Run scan
    start_time = datetime.now()
    logger.info(f"Scan started at {start_time}")
    
    findings = await scanner.run()
    
    end_time = datetime.now()
    duration = end_time - start_time
    logger.info(f"Scan completed at {end_time} (duration: {duration})")
    
    # Generate report
    logger.info("Generating reports...")
    if findings:
        generate_reports(findings, scan_config.report)
        
        # Count findings by severity
        severity_counts = scanner.get_finding_statistics()
        
        logger.info("Scan summary:")
        logger.info(f"Total findings: {len(findings)}")
        for severity in Severity:
            count = severity_counts.get(severity.name, 0)
            logger.info(f"{severity.name}: {count}")
        
        # Determine exit code based on findings and fail_on_severity
        fail_level = getattr(Severity, scan_config.fail_on_severity, Severity.HIGH)
        highest_severity = max((f.severity for f in findings), default=Severity.INFO)
        
        if highest_severity >= fail_level and fail_level != Severity.NONE:
            logger.info(f"Scan failed due to findings with severity {highest_severity.name} >= {fail_level.name}")
            sys.exit(1)
        else:
            logger.info("Scan completed successfully")
    else:
        logger.info("No findings detected")


@cli.command()
@click.option("--aws", is_flag=True, help="Generate AWS configuration template")
@click.option("--azure", is_flag=True, help="Generate Azure configuration template")
@click.option("--all", "all_providers", is_flag=True, help="Generate template for all providers")
@click.option("--output", "-o", type=click.Path(dir_okay=False), default=".cloudguard.yml", help="Output file")
def init(aws: bool, azure: bool, all_providers: bool, output: str):
    """Initialize a configuration file template."""
    if not (aws or azure or all_providers):
        aws = True  # Default to AWS if no provider specified
    
    if all_providers:
        aws = azure = True
    
    # Generate configuration template
    config = {
        "scan_name": "Cloud Security Scan",
        "output_dir": "reports",
        "log_level": "INFO",
        "fail_on_severity": "HIGH",
        "report": {
            "formats": ["json", "html", "console"],
            "include_remediation": True,
            "include_framework_mappings": True,
            "min_severity": "LOW",
            "group_by": "severity"
        }
    }
    
    if aws:
        config["aws"] = {
            "profile_name": "default",
            "region": "us-east-1",
            "regions": ["us-east-1", "us-west-2", "eu-west-1"],
            "services": ["s3", "iam", "ec2", "lambda", "rds", "apigateway", "kms"],
            "excluded_resources": [],
            "max_concurrent_scans": 5
        }
    
    if azure:
        config["azure"] = {
            "subscription_id": "<subscription-id>",
            "services": ["storage", "keyvault", "network", "compute", "database", "webapp", "container"],
            "resource_groups": [],
            "excluded_resources": [],
            "max_concurrent_scans": 5
        }
    
    # Write configuration to file
    import yaml
    
    try:
        with open(output, "w") as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)
        
        click.echo(f"Configuration template created at {output}")
    except Exception as e:
        click.echo(f"Error creating configuration file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("report_file", type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True))
@click.option("--output", "-o", type=click.Choice(["console", "html", "json", "csv"]), default="console", help="Output format")
@click.option("--output-file", "-f", type=click.Path(dir_okay=False), help="Output file (if not console)")
@click.option("--min-severity", "-s", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), default="LOW", help="Minimum severity to include")
def convert(report_file: str, output: str, output_file: Optional[str], min_severity: str):
    """Convert a report from one format to another."""
    # Load report
    try:
        with open(report_file, "r") as f:
            report_data = json.load(f)
        
        if not isinstance(report_data, dict) or "findings" not in report_data:
            click.echo("Invalid report format", err=True)
            sys.exit(1)
        
        # Extract findings
        findings_data = report_data["findings"]
        findings = [Finding.from_dict(f) for f in findings_data]
        
        # Filter by severity
        min_sev = getattr(Severity, min_severity)
        findings = [f for f in findings if f.severity >= min_sev]
        
        # Generate report in requested format
        from .core.reporting import (
            JsonReportGenerator,
            HtmlReportGenerator,
            ConsoleReportGenerator,
        )
        
        from .utils.config import ReportConfig
        
        config = ReportConfig()
        config.min_severity = min_severity
        
        if output == "console":
            generator = ConsoleReportGenerator(findings, config)
            result = generator.generate()
            click.echo(result)
        else:
            if not output_file:
                output_file = f"converted_report.{output}"
            
            if output == "json":
                generator = JsonReportGenerator(findings, config)
                result = generator.generate()
                with open(output_file, "w") as f:
                    f.write(result)
            elif output == "html":
                generator = HtmlReportGenerator(findings, config)
                result = generator.generate()
                with open(output_file, "w") as f:
                    f.write(result)
            elif output == "csv":
                # Simple CSV export
                import csv
                
                with open(output_file, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["ID", "Title", "Provider", "Service", "Severity", "Resources", "Description"])
                    
                    for finding in findings:
                        resources = ", ".join([r.id for r in finding.resources])
                        writer.writerow([
                            finding.id,
                            finding.title,
                            finding.provider,
                            finding.service,
                            finding.severity.name,
                            resources,
                            finding.description
                        ])
            
            click.echo(f"Report converted and saved to {output_file}")
    
    except Exception as e:
        click.echo(f"Error converting report: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli() 