"""Configuration utilities for CloudGuard."""

import os
import yaml
from typing import Dict, Any, Optional, List, Set, Union
from dataclasses import dataclass, field
import logging

from cloudguard.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ProviderConfig:
    """Base configuration for a cloud provider."""
    enabled: bool = True
    services: Optional[List[str]] = None
    excluded_services: List[str] = field(default_factory=list)
    rate_limit: int = 20
    
    def get_enabled_services(self, supported_services: Set[str]) -> Set[str]:
        """Get the set of enabled services for scanning.
        
        Args:
            supported_services: Set of services supported by the provider
            
        Returns:
            Set of enabled services
        """
        if self.services is None:
            # If services is None, use all supported services
            enabled = set(supported_services)
        else:
            # Otherwise, only use specified services that are supported
            enabled = {svc for svc in self.services if svc in supported_services}
        
        # Remove excluded services
        for excluded in self.excluded_services:
            if excluded in enabled:
                enabled.remove(excluded)
        
        return enabled


@dataclass
class AwsConfig(ProviderConfig):
    """AWS provider configuration."""
    profile: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    session_token: Optional[str] = None
    regions: List[str] = field(default_factory=lambda: ["us-east-1"])
    assume_role_arn: Optional[str] = None
    excluded_regions: List[str] = field(default_factory=list)
    excluded_resources: List[str] = field(default_factory=list)


@dataclass
class AzureConfig(ProviderConfig):
    """Azure provider configuration."""
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    subscription_ids: Optional[List[str]] = None
    use_managed_identity: bool = False
    excluded_resources: List[str] = field(default_factory=list)


@dataclass
class ReportConfig:
    """Report generation configuration."""
    formats: List[str] = field(default_factory=lambda: ["json", "console"])
    output_dir: str = "reports"
    report_name_prefix: str = "cloudguard_scan"
    include_passing: bool = False
    include_resources: bool = True
    include_metadata: bool = True
    include_summary: bool = True
    include_remediation: bool = True
    include_framework_mappings: bool = True


@dataclass
class ScanConfig:
    """Main configuration for CloudGuard scans."""
    scan_name: str = "cloudguard_scan"
    aws: AwsConfig = field(default_factory=AwsConfig)
    azure: AzureConfig = field(default_factory=AzureConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    providers: List[str] = field(default_factory=lambda: ["aws"])
    output_dir: str = "reports"
    log_level: str = "INFO"
    log_file: Optional[str] = None
    fail_on_severity: Optional[str] = None
    excluded_checks: List[str] = field(default_factory=list)
    included_checks: Optional[List[str]] = None
    concurrency: int = 10
    disable_progress_bar: bool = False
    no_color: bool = False
    mock: bool = False


def load_config_file(config_path: str) -> Dict[str, Any]:
    """Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Configuration dictionary
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        logger.error(f"Error parsing configuration file: {e}")
        raise
    
    if config is None:
        # Empty config file
        return {}
        
    return config


def merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Merge configuration dictionaries recursively.
    
    Args:
        base: Base configuration dictionary
        override: Override configuration dictionary
        
    Returns:
        Merged configuration dictionary
    """
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge dictionaries
            result[key] = merge_configs(result[key], value)
        else:
            # Replace or add values
            result[key] = value
            
    return result


def load_config(config_path: Optional[str] = None, cli_args: Optional[Dict[str, Any]] = None) -> ScanConfig:
    """Load and merge configuration from file and CLI arguments.
    
    Args:
        config_path: Path to the configuration file
        cli_args: Dictionary of CLI arguments
        
    Returns:
        ScanConfig object
    """
    # Start with an empty config
    config_dict: Dict[str, Any] = {}
    
    # Load from file if provided
    if config_path:
        try:
            file_config = load_config_file(config_path)
            config_dict = merge_configs(config_dict, file_config)
        except Exception as e:
            logger.warning(f"Failed to load config file, using defaults: {e}")
    
    # Merge CLI arguments if provided
    if cli_args:
        # Filter out None values (unspecified CLI args)
        cli_config = {k: v for k, v in cli_args.items() if v is not None}
        config_dict = merge_configs(config_dict, cli_config)
    
    # Create nested configs for providers
    aws_config = config_dict.get('aws', {})
    azure_config = config_dict.get('azure', {})
    report_config = config_dict.get('report', {})
    
    # Create and return ScanConfig
    return ScanConfig(
        scan_name=config_dict.get('scan_name', 'cloudguard_scan'),
        aws=AwsConfig(**aws_config) if aws_config else AwsConfig(),
        azure=AzureConfig(**azure_config) if azure_config else AzureConfig(),
        report=ReportConfig(**report_config) if report_config else ReportConfig(),
        providers=config_dict.get('providers', ['aws']),
        output_dir=config_dict.get('output_dir', 'reports'),
        log_level=config_dict.get('log_level', 'INFO'),
        log_file=config_dict.get('log_file'),
        fail_on_severity=config_dict.get('fail_on_severity'),
        excluded_checks=config_dict.get('excluded_checks', []),
        included_checks=config_dict.get('included_checks'),
        concurrency=config_dict.get('concurrency', 10),
        disable_progress_bar=config_dict.get('disable_progress_bar', False),
        no_color=config_dict.get('no_color', False),
        mock=config_dict.get('mock', False)
    ) 