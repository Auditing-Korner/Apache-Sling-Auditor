---
layout: default
title: Installation
permalink: /installation
---

# Installation Guide

This guide will help you install and set up the Apache Sling Auditor on your system.

## Prerequisites

Before installing, ensure you have:

- **Python 3.7 or higher** - Check your version:
  ```bash
  python --version
  # or
  python3 --version
  ```

- **pip** - Python package manager (usually included with Python)
  ```bash
  pip --version
  ```

- **Git** - For cloning the repository (optional if downloading as ZIP)

## Installation Methods

### Method 1: Clone from GitHub (Recommended)

```bash
# Clone the repository
git clone https://github.com/Auditing-Korner/Apache-Sling-Auditor.git

# Navigate to the directory
cd Apache-Sling-Auditor
```

### Method 2: Download ZIP

1. Download the repository as a ZIP file from GitHub
2. Extract it to your desired location
3. Navigate to the extracted directory

## Virtual Environment Setup (Recommended)

Using a virtual environment is highly recommended to avoid conflicts with system packages.

### On Linux/macOS:

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation (prompt should show (venv))
which python  # Should point to venv/bin/python
```

### On Windows:

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate

# Verify activation (prompt should show (venv))
where python  # Should point to venv\Scripts\python.exe
```

## Install Dependencies

Once your virtual environment is activated:

```bash
# Upgrade pip (recommended)
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt
```

### Dependencies Installed

The following packages will be installed:

- **aiohttp** - Asynchronous HTTP client/server framework
- **requests** - HTTP library for synchronous requests
- **pyyaml** - YAML parser and emitter
- **beautifulsoup4** - HTML/XML parser
- **colorama** - Cross-platform colored terminal output
- **rich** - Rich text and beautiful formatting in the terminal
- **tqdm** - Fast, extensible progress bar

## Verify Installation

Test that everything is installed correctly:

```bash
# Check Python version
python --version

# Verify main script is executable
python auditor.py --help

# You should see the help message with all available options
```

## Configuration

The auditor uses a YAML configuration file located at `config/audit_config.yaml`. This file contains:

- Scan mode settings
- CVE definitions
- Test paths and payloads
- Default credentials
- Brute force settings

You can customize this file to suit your needs. See the [Configuration Guide]({{ site.baseurl }}/configuration) for details.

## Wordlists

The `wordlists/` directory contains several wordlists:

- `usernames.txt` - Username wordlist for brute force
- `passwords.txt` - Password wordlist for brute force
- `sling_paths.txt` - Base path enumeration wordlist
- `sling_paths_extended.txt` - Extended path wordlist

You can use these as-is or provide your own custom wordlists.

## Troubleshooting

### Common Issues

#### Issue: `python: command not found`

**Solution**: Use `python3` instead:
```bash
python3 --version
python3 -m venv venv
```

#### Issue: `pip: command not found`

**Solution**: Install pip or use `python -m pip`:
```bash
python -m pip install -r requirements.txt
```

#### Issue: Permission errors on Linux/macOS

**Solution**: Use `sudo` (not recommended) or better, use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Issue: SSL certificate errors

**Solution**: Use the `-k` or `--insecure` flag when scanning:
```bash
python auditor.py -t https://target.com:4503 -k
```

#### Issue: Module not found errors

**Solution**: Ensure virtual environment is activated and dependencies are installed:
```bash
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```

## Next Steps

Once installation is complete:

1. **[Quick Start Guide]({{ site.baseurl }}/quick-start)** - Run your first scan
2. **[Usage Guide]({{ site.baseurl }}/usage)** - Learn how to use all features
3. **[Configuration]({{ site.baseurl }}/configuration)** - Customize the auditor

## System Requirements

### Minimum Requirements

- **OS**: Linux, macOS, or Windows
- **Python**: 3.7 or higher
- **RAM**: 512 MB minimum
- **Disk Space**: 100 MB for installation

### Recommended Requirements

- **OS**: Linux or macOS
- **Python**: 3.9 or higher
- **RAM**: 2 GB or more
- **Disk Space**: 500 MB for installation and scan results
- **Network**: Stable internet connection for scanning

## Updating

To update to the latest version:

```bash
# Navigate to the repository directory
cd Apache-Sling-Auditor

# Pull latest changes
git pull origin main

# Update dependencies (if requirements.txt changed)
pip install -r requirements.txt --upgrade
```

## Uninstallation

To remove the auditor:

```bash
# Simply delete the directory
rm -rf Apache-Sling-Auditor  # Linux/macOS
# or
rmdir /s Apache-Sling-Auditor  # Windows

# If using virtual environment, deactivate first
deactivate
```

---

**Ready to start?** Check out the [Quick Start Guide]({{ site.baseurl }}/quick-start)!

