"""Logging utility for CloudGuard."""

import logging
import os
import sys
from typing import Optional, Dict, Any, Union


class LoggingConfig:
    """Configuration for the CloudGuard logger."""
    
    def __init__(
        self,
        level: str = "INFO",
        log_file: Optional[str] = None,
        log_format: Optional[str] = None,
        include_timestamp: bool = True,
        include_level: bool = True,
        include_name: bool = True,
    ):
        """Initialize logging configuration.
        
        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file (if None, logs to console only)
            log_format: Custom log format string (overrides other format settings)
            include_timestamp: Include timestamp in log messages
            include_level: Include log level in log messages
            include_name: Include logger name in log messages
        """
        self.level = self._parse_level(level)
        self.log_file = log_file
        self.log_format = log_format
        self.include_timestamp = include_timestamp
        self.include_level = include_level
        self.include_name = include_name
    
    def _parse_level(self, level: str) -> int:
        """Parse string log level to logging constant.
        
        Args:
            level: String log level
            
        Returns:
            Logging level constant
        """
        level_upper = level.upper()
        if level_upper == "DEBUG":
            return logging.DEBUG
        elif level_upper == "INFO":
            return logging.INFO
        elif level_upper == "WARNING":
            return logging.WARNING
        elif level_upper == "ERROR":
            return logging.ERROR
        elif level_upper == "CRITICAL":
            return logging.CRITICAL
        else:
            # Default to INFO
            return logging.INFO
    
    def get_format_string(self) -> str:
        """Generate log format string based on configuration.
        
        Returns:
            Log format string
        """
        if self.log_format:
            return self.log_format
        
        parts = []
        if self.include_timestamp:
            parts.append("%(asctime)s")
        if self.include_level:
            parts.append("%(levelname)s")
        if self.include_name:
            parts.append("%(name)s")
        
        parts.append("%(message)s")
        return " - ".join(parts)


class CloudGuardLogger:
    """Custom logger for CloudGuard."""
    
    # Cache for loggers to avoid creating duplicates
    _loggers: Dict[str, logging.Logger] = {}
    
    # Default configuration
    _default_config = LoggingConfig()
    
    @classmethod
    def setup(cls, config: Union[LoggingConfig, Dict[str, Any]]) -> None:
        """Configure the logging system.
        
        Args:
            config: Logger configuration
        """
        if isinstance(config, dict):
            config = LoggingConfig(**config)
        
        cls._default_config = config
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(config.level)
        
        # Remove any existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Add console handler
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(config.level)
        console.setFormatter(logging.Formatter(config.get_format_string()))
        root_logger.addHandler(console)
        
        # Add file handler if log file is specified
        if config.log_file:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(config.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                
            file_handler = logging.FileHandler(config.log_file)
            file_handler.setLevel(config.level)
            file_handler.setFormatter(logging.Formatter(config.get_format_string()))
            root_logger.addHandler(file_handler)
    
    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """Get a logger with the specified name.
        
        Args:
            name: Logger name
            
        Returns:
            Logger instance
        """
        if name not in cls._loggers:
            logger = logging.getLogger(name)
            logger.setLevel(cls._default_config.level)
            cls._loggers[name] = logger
        
        return cls._loggers[name]


# Convenience function to get a logger
def get_logger(name: str) -> logging.Logger:
    """Get a logger with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return CloudGuardLogger.get_logger(name) 