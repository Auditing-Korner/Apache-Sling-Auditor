---
layout: default
title: Contributing
permalink: /contributing
---

# Contributing Guide

Thank you for your interest in contributing to Apache Sling Auditor!

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a branch** for your changes
4. **Make your changes**
5. **Test thoroughly**
6. **Submit a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/Auditing-Korner/Apache-Sling-Auditor.git
cd Apache-Sling-Auditor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Contribution Guidelines

### Code Style

- Follow **PEP 8** Python style guidelines
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

### Testing

- Test your changes before submitting
- Test on authorized systems only
- Verify no scan results are committed
- Check for linting errors

### Documentation

- Update README.md for new features
- Add docstrings to new functions
- Update configuration documentation
- Include usage examples

## What to Contribute

### Bug Fixes

- Fix bugs in existing code
- Improve error handling
- Add input validation

### New Features

- Add new CVE detections
- Implement new security checks
- Add new exploitation capabilities
- Improve reporting

### Documentation

- Improve existing documentation
- Add examples
- Fix typos and errors
- Add tutorials

### Configuration

- Add new default credentials
- Add new test paths
- Improve wordlists
- Add new CVE definitions

## Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clean, tested code
   - Update documentation
   - Follow code style

3. **Test your changes**
   ```bash
   python auditor.py -t http://test-target.com:4502 --mode quick
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "Description of changes"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**
   - Provide clear description
   - Reference related issues
   - Include screenshots if applicable

## Important Reminders

### Never Commit Scan Results

**CRITICAL**: Never commit scan results, reports, or extracted data.

- All outputs are gitignored
- Verify with `git status` before committing
- Check `.gitignore` is working

### Security Considerations

- Never commit credentials or API keys
- Review code for security issues
- Test responsibly
- Follow responsible disclosure

## Code Review Process

1. Maintainers review PRs
2. Feedback may be provided
3. Changes may be requested
4. PR is merged when approved

## Questions?

- Open an issue for questions
- Check existing issues first
- Be respectful and professional

Thank you for contributing!

