# CloudGuard Documentation

This directory contains the documentation for CloudGuard.

## Building the Documentation

To build the documentation, you'll need to install the required dependencies:

```bash
pip install -e ".[docs]"
```

Then, you can build the documentation using Sphinx:

```bash
cd docs
make html
```

The built documentation will be available in the `_build/html` directory.

## Documentation Structure

- `index.rst`: Main entry point for the documentation
- `installation.rst`: Installation instructions
- `usage/`: Directory containing usage instructions
  - `aws.rst`: AWS scanning usage
  - `azure.rst`: Azure scanning usage
- `configuration.rst`: Configuration options
- `development/`: Directory containing development information
  - `contributing.rst`: Contributing guidelines
  - `adding_scanners.rst`: How to add new scanners
- `api/`: Directory containing API documentation 