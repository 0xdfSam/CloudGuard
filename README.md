# CloudGuard

CloudGuard is a comprehensive cloud security scanning tool designed to identify security vulnerabilities and misconfigurations in cloud infrastructure across multiple providers like AWS and Azure.

## Features

- Multi-cloud support (currently AWS and Azure)
- Extensible architecture for adding new providers and security checks
- Detailed findings with severity ratings and remediation guidance
- Multiple output formats (JSON, HTML, CSV, console)
- Mock mode for testing and development without cloud credentials
- Flexible configuration via command-line options, config files, or environment variables

## Installation

### Prerequisites

- Python 3.8 or higher
- AWS credentials (if scanning AWS resources)
- Azure credentials (if scanning Azure resources)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/0xdfSam/CloudGuard.git
   cd CloudGuard
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the package and its dependencies:
   ```bash
   pip install -e .
   ```

## Usage

### Basic Usage

```bash
# Scan AWS resources with default profile
python -m cloudguard scan --providers aws

# Scan Azure resources
python -m cloudguard scan --providers azure

# Scan all supported providers
python -m cloudguard scan --all-providers
```

### Mock Mode

For testing or demo purposes, you can use the mock mode which doesn't require cloud credentials:

```bash
# AWS mock scan
python -m cloudguard.cli.aws --mock

# Azure mock scan
python -m cloudguard.cli.azure --mock
```

### Configuration

You can configure CloudGuard using a YAML configuration file:

1. Generate a configuration template:
   ```bash
   python -m cloudguard init --all -o .cloudguard.yml
   ```

2. Edit the generated file with your settings

3. Run a scan using the configuration file:
   ```bash
   python -m cloudguard scan -c .cloudguard.yml
   ```

### Output Options

```bash
# Generate JSON report
python -m cloudguard scan --providers aws --report-format json --output-dir reports

# Generate HTML report
python -m cloudguard scan --providers aws --report-format html --output-dir reports

# Generate comprehensive report with all formats
python -m cloudguard scan --providers aws --report-format all --output-dir reports
```

## Development

### Running Tests

```bash
# Run all tests
python -m pytest

# Run specific test
python -m pytest tests/unit/test_aws_scanner.py
```

### Adding New Checks

The scanning system is designed to be extensible. You can add new security checks by:

1. Creating a new service module in the appropriate provider directory
2. Implementing the required check methods
3. Registering the service with the provider's scanner

## License

This project is licensed under the MIT License - see the LICENSE file for details.
