import os
from setuptools import setup, find_packages

# Read the contents of README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements.txt
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="cloudguard",
    version="0.1.0",
    author="CloudGuard Contributors",
    author_email="opensource@cloudguard-project.org",
    description="A security scanning tool for AWS and Azure cloud environments",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/0xdfSam/CloudGuard",
    project_urls={
        "Bug Tracker": "https://github.com/0xdfSam/CloudGuard/issues",
        "Documentation": "https://github.com/0xdfSam/CloudGuard",
        "Source Code": "https://github.com/0xdfSam/CloudGuard",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Internet :: WWW/HTTP",
    ],
    keywords="security, cloud, aws, azure, scanner, compliance",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.7",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.3.1",
            "pytest-cov>=4.1.0",
            "black>=23.1.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.3.1",
            "typing-extensions>=4.0.0",
            "importlib-metadata>=4.6.0",
        ],
        "docs": [
            "sphinx>=6.1.3",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "cloudguard-aws=cloudguard.cli.aws:main",
            "cloudguard-azure=cloudguard.cli.azure:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
) 