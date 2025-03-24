# Quick Start Guide

This quick start guide will help you get up and running with CloudGuard quickly.

## Installation

Install CloudGuard using pip:

```bash
pip install cloudguard
```

## AWS Security Scanning

### Basic Scan

Run a basic scan of your AWS environment:

```bash
cloudguard-aws
```

This will use your default AWS credentials to scan all supported services in all available regions.

### Scan Specific Services

To scan only specific services:

```bash
cloudguard-aws --services s3,iam
```

### Scan Specific Regions

To scan only specific regions:

```bash
cloudguard-aws --regions us-east-1,us-west-2
```

### Output Options

Save the results to a file in JSON format:

```bash
cloudguard-aws --output aws-findings.json
```

Generate a CSV report:

```bash
cloudguard-aws --format csv --output aws-findings.csv
```

Show only a summary of findings:

```bash
cloudguard-aws --summary
```

Include detailed resource information:

```bash
cloudguard-aws --resources
```

## Azure Security Scanning

### Basic Scan

Run a basic scan of your Azure environment:

```bash
cloudguard-azure
```

This will use your default Azure credentials to scan all supported services in all accessible subscriptions.

### Scan Specific Services

To scan only specific services:

```bash
cloudguard-azure --services storage,keyvault
```

### Scan Specific Subscriptions

To scan only specific subscriptions:

```bash
cloudguard-azure --subscriptions "sub-id-1,sub-id-2"
```

### Output Options

Azure supports the same output options as AWS:

```bash
cloudguard-azure --output azure-findings.json
cloudguard-azure --format csv --output azure-findings.csv
cloudguard-azure --summary
cloudguard-azure --resources
```

## Testing Without Cloud Credentials

Both AWS and Azure scanners support a mock mode for testing:

```bash
cloudguard-aws --mock
cloudguard-azure --mock
```

This will generate sample findings without making any API calls to cloud providers.

## Next Steps

- Read the [detailed usage instructions](usage/index.md) for more advanced usage
- Configure [custom scanning options](configuration.md)
- Learn about [integrating with other tools](integration.md)
- See the [contributing guide](development/contributing.md) if you want to contribute to CloudGuard 