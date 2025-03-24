# Contributing to CloudGuard

Thank you for your interest in contributing to CloudGuard! This document provides guidelines and instructions for contributing to this project.

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the issue tracker to see if the problem has already been reported. If it has and the issue is still open, add a comment to the existing issue instead of opening a new one.

When you are creating a bug report, please include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Describe the behavior you observed and what you expected to see
- Include any error messages or logs
- Specify your operating system and version of CloudGuard
- If possible, provide a code sample or test case that demonstrates the issue

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- A clear and descriptive title
- A detailed description of the proposed feature
- Explain why this enhancement would be useful to CloudGuard users
- Provide examples of how the feature would be used

### Adding New Cloud Service Scanners

CloudGuard is designed to be extensible with new service scanners. If you want to add support for a new cloud service:

1. Check existing issues to see if someone is already working on it
2. Create a new issue describing the service you plan to add
3. Follow the implementation guidelines below

#### For AWS Services:

1. Create a new file in `src/cloudguard/providers/aws/services/`
2. Implement a class that inherits from `AwsServiceScanner`
3. Implement the required methods:
   - `scan()`: Perform security checks and return findings
   - `get_resources()`: Return a list of resources for this service
   - `get_service_tags()`: Return tags for this service
4. Register your scanner in `src/cloudguard/providers/aws/registry.py`
5. Add tests in `tests/providers/aws/services/`

#### For Azure Services:

1. Create a new file in `src/cloudguard/providers/azure/services/`
2. Implement a class that inherits from `AzureServiceScanner`
3. Implement the required methods:
   - `scan()`: Perform security checks and return findings
   - `get_resources()`: Return a list of resources for this service
   - `get_service_tags()`: Return tags for this service
4. Register your scanner in `src/cloudguard/providers/azure/registry.py`
5. Add tests in `tests/providers/azure/services/`

### Pull Requests

The process described here has several goals:

- Maintain CloudGuard's quality
- Fix problems that are important to users
- Engage the community in working toward the best possible tool
- Enable a sustainable system for CloudGuard's maintainers to review contributions

Please follow these steps to have your contribution considered by the maintainers:

1. Follow all instructions in the PR template
2. Follow the [styleguides](#styleguides)
3. After you submit your PR, verify that all status checks are passing

## Styleguides

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- When only changing documentation, include `[docs]` in the commit title

### Python Styleguide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use 4 spaces for indentation
- Use docstrings for all public classes, methods, and functions
- Format docstrings according to the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings)
- Include type hints where appropriate
- Use meaningful variable and function names
- Write tests for all new functionality

### Documentation Styleguide

- Use Markdown for documentation
- Include code examples where appropriate
- Update the README.md if your changes affect how users interact with the project
- Add docstrings to all functions and classes

## Development Environment Setup

1. Fork the repository
2. Clone your fork locally
   ```bash
   git clone https://github.com/your-username/cloudguard.git
   cd cloudguard
   ```
3. Create a virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install development dependencies
   ```bash
   pip install -e ".[dev]"
   ```
5. Set up pre-commit hooks
   ```bash
   pre-commit install
   ```

## Testing

Before submitting a PR, make sure all tests pass:

```bash
pytest
```

To run tests with coverage:

```bash
pytest --cov=cloudguard
```

## Additional Notes

### Issue and Pull Request Labels

This section lists the labels we use to help track and manage issues and pull requests.

#### Type of Issue and PR

- `bug`: Indicates an unexpected problem or unintended behavior
- `enhancement`: New feature requests or improvements to existing functionality
- `documentation`: Improvements or additions to documentation
- `good first issue`: Good for newcomers to the project
- `help wanted`: Extra attention is needed

#### Process Status

- `under investigation`: Still determining the cause or solution
- `in progress`: Currently being worked on
- `needs review`: Ready for review by maintainers
- `discussion`: Needs further discussion

Thank you for contributing to CloudGuard! 