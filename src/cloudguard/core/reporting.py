"""Reporting functionality for CloudGuard."""

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import jinja2
from rich.console import Console
from rich.table import Table

from ..utils.config import ReportConfig
from .findings import Finding, Severity

logger = logging.getLogger(__name__)


class ReportGenerator(ABC):
    """Base class for report generators."""

    def __init__(self, findings: List[Finding], config: ReportConfig):
        """Initialize the report generator.

        Args:
            findings: List of findings to include in the report
            config: Report configuration
        """
        self.findings = findings
        self.config = config
        self.timestamp = datetime.utcnow()

    @abstractmethod
    def generate(self) -> str:
        """Generate the report.

        Returns:
            Path to the generated report
        """
        pass


class JsonReportGenerator(ReportGenerator):
    """Generate reports in JSON format."""

    def generate(self) -> str:
        """Generate a JSON report with all findings.

        Returns:
            Path to the generated report
        """
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp_str = self.timestamp.strftime("%Y%m%d-%H%M%S")
        output_file = output_dir / f"cloudguard-report-{timestamp_str}.json"
        
        # Convert findings to dictionaries
        findings_dicts = [finding.to_dict() for finding in self.findings]
        
        # Add report metadata
        report_data = {
            "report_id": timestamp_str,
            "report_timestamp": self.timestamp.isoformat(),
            "tool_version": "0.1.0",  # TODO: Get from package
            "total_findings": len(self.findings),
            "findings": findings_dicts,
            # Include summary statistics
            "summary": {
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.findings if f.severity == Severity.INFO]),
                "by_provider": self._count_by_provider(),
                "by_service": self._count_by_service()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=self._json_serialize)
        
        logger.info(f"JSON report generated: {output_file}")
        return str(output_file)
    
    def _json_serialize(self, obj: Any) -> Any:
        """Handle serialization of special types.

        Args:
            obj: Object to serialize

        Returns:
            JSON-serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Severity):
            return obj.name
        raise TypeError(f"Type {type(obj)} not serializable")
    
    def _count_by_provider(self) -> Dict[str, int]:
        """Count findings by provider.

        Returns:
            Dictionary mapping providers to counts
        """
        result: Dict[str, int] = {}
        for finding in self.findings:
            result[finding.provider] = result.get(finding.provider, 0) + 1
        return result
    
    def _count_by_service(self) -> Dict[str, int]:
        """Count findings by service.

        Returns:
            Dictionary mapping services to counts
        """
        result: Dict[str, int] = {}
        for finding in self.findings:
            result[finding.service] = result.get(finding.service, 0) + 1
        return result


class HtmlReportGenerator(ReportGenerator):
    """Generate reports in HTML format with visualizations."""

    def generate(self) -> str:
        """Generate an HTML report with findings and visualizations.

        Returns:
            Path to the generated report
        """
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp_str = self.timestamp.strftime("%Y%m%d-%H%M%S")
        output_file = output_dir / f"cloudguard-report-{timestamp_str}.html"
        
        # Load Jinja2 template
        template_dir = Path(__file__).parent.parent / "templates"
        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        template = env.get_template("report.html")
        
        # Prepare data for the template
        severity_counts = {
            "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
            "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
            "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
            "low": len([f for f in self.findings if f.severity == Severity.LOW]),
            "info": len([f for f in self.findings if f.severity == Severity.INFO])
        }
        
        # Render the template
        html_content = template.render(
            findings=self.findings,
            timestamp=self.timestamp,
            severity_counts=severity_counts,
            providers=self._count_by_provider(),
            services=self._count_by_service(),
            total_findings=len(self.findings)
        )
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_file}")
        return str(output_file)
    
    def _count_by_provider(self) -> Dict[str, int]:
        """Count findings by provider.

        Returns:
            Dictionary mapping providers to counts
        """
        result: Dict[str, int] = {}
        for finding in self.findings:
            result[finding.provider] = result.get(finding.provider, 0) + 1
        return result
    
    def _count_by_service(self) -> Dict[str, int]:
        """Count findings by service.

        Returns:
            Dictionary mapping services to counts
        """
        result: Dict[str, int] = {}
        for finding in self.findings:
            result[finding.service] = result.get(finding.service, 0) + 1
        return result


class ConsoleReportGenerator(ReportGenerator):
    """Generate text-based reports for console output."""

    def generate(self) -> str:
        """Generate a console report.

        Returns:
            String with the report content
        """
        console = Console()
        
        # Create summary table
        table = Table(title="CloudGuard Scan Results Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        
        severity_counts = {
            Severity.CRITICAL: len([f for f in self.findings if f.severity == Severity.CRITICAL]),
            Severity.HIGH: len([f for f in self.findings if f.severity == Severity.HIGH]),
            Severity.MEDIUM: len([f for f in self.findings if f.severity == Severity.MEDIUM]),
            Severity.LOW: len([f for f in self.findings if f.severity == Severity.LOW]),
            Severity.INFO: len([f for f in self.findings if f.severity == Severity.INFO])
        }
        
        severity_styles = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
            Severity.INFO: "blue"
        }
        
        for severity, count in severity_counts.items():
            table.add_row(
                severity.name,
                str(count),
                style=severity_styles[severity]
            )
        
        # Add totals
        table.add_row("TOTAL", str(len(self.findings)), style="bold")
        
        # Capture the output
        with console.capture() as capture:
            console.print(f"\n=== CloudGuard Scan Report - {self.timestamp} ===\n")
            console.print(table)
            
            # Print findings by provider
            provider_counts = self._count_by_provider()
            if provider_counts:
                console.print("\n[bold]Findings by Provider:[/bold]")
                for provider, count in provider_counts.items():
                    console.print(f"  {provider}: {count}")
            
            # Print findings by service
            service_counts = self._count_by_service()
            if service_counts:
                console.print("\n[bold]Findings by Service:[/bold]")
                for service, count in service_counts.items():
                    console.print(f"  {service}: {count}")
        
        return capture.get()
    
    def _count_by_provider(self) -> Dict[str, int]:
        """Count findings by provider.

        Returns:
            Dictionary mapping providers to counts
        """
        result: Dict[str, int] = {}
        for finding in self.findings:
            result[finding.provider] = result.get(finding.provider, 0) + 1
        return result
    
    def _count_by_service(self) -> Dict[str, int]:
        """Count findings by service.

        Returns:
            Dictionary mapping services to counts
        """
        result: Dict[str, int] = {}
        for finding in self.findings:
            result[finding.service] = result.get(finding.service, 0) + 1
        return result


def create_report_generator(findings: List[Finding], 
                           config: ReportConfig, 
                           format: str) -> ReportGenerator:
    """Factory function to create report generators.

    Args:
        findings: List of findings to include in the report
        config: Report configuration
        format: Report format (json, html, console)

    Returns:
        Appropriate report generator instance

    Raises:
        ValueError: If an unsupported format is specified
    """
    format = format.lower()
    if format == 'json':
        return JsonReportGenerator(findings, config)
    elif format == 'html':
        return HtmlReportGenerator(findings, config)
    elif format == 'console':
        return ConsoleReportGenerator(findings, config)
    else:
        raise ValueError(f"Unsupported report format: {format}")


def generate_reports(findings: List[Finding], config: ReportConfig) -> List[str]:
    """Generate multiple report formats.

    Args:
        findings: List of findings to include in the reports
        config: Report configuration

    Returns:
        List of paths to generated reports
    """
    reports = []
    formats = config.formats if config.formats else ['json']
    
    for format in formats:
        generator = create_report_generator(findings, config, format)
        report_path = generator.generate()
        reports.append(report_path)
    
    return reports 