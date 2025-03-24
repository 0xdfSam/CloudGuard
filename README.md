# CloudGuard - Cloud Security Scanner

CloudGuard is a security scanning tool that performs automated security assessments of your cloud resources to identify potential security risks and compliance issues.

![CloudGuard Logo](docs/images/cloudguard-logo.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Multi-Cloud Support**: Scan both AWS and Azure environments
- **Multi-Service Scanning**: Scan multiple services like S3, IAM, EC2, Azure Storage, Key Vault, etc.
- **Comprehensive Checks**: Identifies issues based on security best practices and compliance frameworks
- **Detailed Findings**: Each finding includes detailed information, severity rating, and remediation steps
- **Parallel Scanning**: Scans multiple services and regions/subscriptions simultaneously
- **Flexible Output**: JSON or CSV output format, with summary reporting options
- **No External Dependencies**: All scanning is performed using official cloud provider SDKs

## Services Supported

### AWS Services

- **S3**: Checks for bucket public access, encryption, logging, versioning, and secure transport
- **IAM**: Checks for root access keys, MFA, password policies, and overly permissive policies
- **EC2**: Checks for security group issues, EBS encryption, public AMIs, instance metadata settings, and more

### Azure Services

- **Storage**: Checks for public access, encryption, secure transfer, network access, and logging
- **Key Vault**: Checks for network access, purge protection, soft delete, key expiration, and logging

## Installation

### Prerequisites

- Python 3.7 or higher
- For AWS: AWS credentials with read access to the services you want to scan
- For Azure: Azure credentials with read access to the services you want to scan

### Install from PyPI

```bash
pip install cloudguard
```

### Install from Source

```bash
git clone https://github.com/cloudguard-project/cloudguard.git
cd cloudguard
pip install -e .
```

### Setting Up a Virtual Environment (Recommended)

```bash
# Create a virtual environment
python -m venv cloudguard-env

# Activate the virtual environment
# On Windows
cloudguard-env\Scripts\activate
# On macOS/Linux
source cloudguard-env/bin/activate

# Install CloudGuard
pip install -r requirements.txt
```

## Configuration

### AWS Configuration

CloudGuard uses AWS credentials for authentication. You can provide credentials in several ways:

1. **AWS credentials file**: Configure your AWS credentials using the AWS CLI
   ```bash
   aws configure
   ```

2. **Environment variables**:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_SESSION_TOKEN="your-session-token"  # If using temporary credentials
   ```

3. **CLI parameters**: Provide credentials via command-line arguments
   ```bash
   python -m cloudguard.cli.aws --access-key-id YOUR_ACCESS_KEY --secret-access-key YOUR_SECRET_KEY
   ```

### Azure Configuration

CloudGuard uses Azure credentials for authentication. You can provide credentials in several ways:

1. **Azure CLI**: Sign in using the Azure CLI
   ```bash
   az login
   ```

2. **Service Principal**: Create a service principal and use its credentials
   ```bash
   # Create a service principal
   az ad sp create-for-rbac --name "CloudGuard" --role "Reader" --scopes "/subscriptions/your-subscription-id"
   ```

3. **Environment variables**:
   ```bash
   export AZURE_TENANT_ID="your-tenant-id"
   export AZURE_CLIENT_ID="your-client-id"
   export AZURE_CLIENT_SECRET="your-client-secret"
   ```

## Real-World Usage Examples

### AWS Security Assessment Workflow

#### 1. Initial Assessment

Run a full scan across all regions and services to get a baseline:

```bash
python -m cloudguard.cli.aws --output initial-assessment.json --format json --resources
```

#### 2. Regular Monitoring

Schedule a daily scan with summary output for quick review:

```bash
python -m cloudguard.cli.aws --output daily-scan-$(date +%Y-%m-%d).json --summary
```

#### 3. Focused Service Audit

When you need to do a deep dive into specific services:

```bash
python -m cloudguard.cli.aws --services s3,iam --regions us-east-1,us-west-2 --output s3-iam-audit.json --resources --verbose
```

#### 4. Pre-deployment Security Check

Before deploying new resources, check your current state:

```bash
python -m cloudguard.cli.aws --profile staging --services ec2,s3 --output pre-deploy-check.csv --format csv
```

### Azure Security Assessment Workflow

#### 1. Subscription Audit

Audit specific subscriptions:

```bash
python -m cloudguard.cli.azure --subscriptions "sub-id-1,sub-id-2" --output subscription-audit.json --resources
```

#### 2. Storage Security Evaluation

Focus on storage accounts:

```bash
python -m cloudguard.cli.azure --services storage --output storage-security.json
```

#### 3. Continuous Integration Checks

For CI/CD pipelines, use the summary mode to fail builds on critical issues:

```bash
python -m cloudguard.cli.azure --services keyvault,storage --summary --output ci-check.json
```

#### 4. Compliance Reporting

Generate CSV reports for compliance needs:

```bash
python -m cloudguard.cli.azure --format csv --output compliance-report.csv --resources
```

## Integration with Security Tools

### SIEM Integration

CloudGuard output can be forwarded to SIEM systems for centralized security monitoring:

```bash
# Example: Sending findings to Splunk
python -m cloudguard.cli.aws --format json | curl -X POST -H "Authorization: Splunk ${SPLUNK_TOKEN}" -d @- https://splunk-instance/services/collector
```

### Notification Systems

Integrate with notification systems to alert on critical findings:

```bash
# Example: Send critical findings to Slack
python -m cloudguard.cli.aws --format json | jq '.findings[] | select(.severity=="CRITICAL")' | curl -X POST -H 'Content-type: application/json' --data @- $SLACK_WEBHOOK_URL
```

## Output Options (Both AWS and Azure)

```bash
# Output to file
python -m cloudguard.cli.[aws|azure] --output report.json

# Output as CSV
python -m cloudguard.cli.[aws|azure] --format csv

# Display only summary
python -m cloudguard.cli.[aws|azure] --summary

# Include resource details
python -m cloudguard.cli.[aws|azure] --resources

# Enable verbose logging
python -m cloudguard.cli.[aws|azure] --verbose
```

## Sample Output

### JSON Output

```json
{
  "findings": [
    {
      "title": "Public access enabled for storage account 'examplestorage'",
      "description": "The storage account 'examplestorage' has public access enabled, which could lead to unauthorized access to data.",
      "severity": "HIGH",
      "provider": "azure",
      "service": "storage",
      "resources": [
        {
          "id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.Storage/storageAccounts/examplestorage",
          "name": "examplestorage",
          "type": "storage_account",
          "region": "eastus"
        }
      ],
      "remediation": {
        "summary": "Disable public access to the storage account",
        "steps": [
          "1. Go to the Azure portal",
          "2. Navigate to the storage account",
          "3. Under 'Security + networking', select 'Networking'",
          "4. Set 'Public network access' to 'Disabled'"
        ]
      },
      "risk_score": 8.5,
      "tags": ["public_storage_account", "storage", "access_control"]
    }
  ],
  "summary": {
    "total_findings": 1,
    "findings_by_service": {
      "storage": 1
    },
    "findings_by_severity": {
      "HIGH": 1
    },
    "findings_by_subscription": {
      "00000000-0000-0000-0000-000000000000": 1
    }
  }
}
```

## Security Best Practices

When using CloudGuard, consider these security best practices:

1. **Principle of Least Privilege**: Create dedicated service accounts with read-only permissions for scanning
2. **Credential Rotation**: Regularly rotate credentials used for scanning
3. **Output Security**: Treat scan results as sensitive information, as they contain details about your security posture
4. **Secure Storage**: Store historical scan results in encrypted storage
5. **Regular Scanning**: Set up recurring scans to detect new issues quickly
6. **Change Tracking**: Compare scan results over time to identify changes in your security posture

## Extending CloudGuard

### Adding AWS Scanners

To add support for additional AWS services, create a new scanner class that inherits from `AwsServiceScanner`:

1. Create a new file in `src/cloudguard/providers/aws/services/`
2. Implement the scanner class with `scan()`, `get_resources()`, and other required methods
3. Register the scanner in `src/cloudguard/providers/aws/registry.py`

Example scanner class structure:

```python
from cloudguard.providers.aws.scanner import AwsServiceScanner
from cloudguard.core.findings import Finding, Severity, Resource

class NewServiceScanner(AwsServiceScanner):
    service_name = "new_service"
    
    def scan(self) -> List[Finding]:
        findings = []
        # Implement scanning logic
        return findings
    
    def get_resources(self) -> List[Dict[str, Any]]:
        resources = []
        # Implement resource discovery
        return resources
        
    def get_service_tags(self) -> Set[str]:
        return {"aws", "new_service"}
```

### Adding Azure Scanners

To add support for additional Azure services, create a new scanner class that inherits from `AzureServiceScanner`:

1. Create a new file in `src/cloudguard/providers/azure/services/`
2. Implement the scanner class with `scan()`, `get_resources()`, and other required methods
3. Register the scanner in `src/cloudguard/providers/azure/registry.py`

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature-name`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit your changes (`git commit -m 'Add your feature'`)
6. Push to the branch (`git push origin feature/your-feature-name`)
7. Open a Pull Request

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

CloudGuard is not a substitute for professional security advice or a comprehensive security assessment. It is designed to help identify common security issues, but may not detect all potential security vulnerabilities in your cloud environment. Always combine automated scanning with manual review and professional security assessments. 