---
layout: default
title: Usage Guide
permalink: /usage
description: Complete usage guide for Apache Sling Auditor. Learn scan modes, command-line options, authentication, wordlist enumeration, exploitation, and brute force testing.
keywords: Apache Sling Auditor usage, scan modes, command line options, security scanning guide, penetration testing guide
related:
  - title: Quick Start
    url: /quick-start
    description: Get started quickly
  - title: API Reference
    url: /api-reference
    description: Complete command reference
  - title: Examples
    url: /examples
    description: Practical usage examples
  - title: Configuration
    url: /configuration
    description: Configure scan behavior
---

# Usage Guide

Complete guide to using Apache Sling Auditor effectively.

## Basic Usage

### Command Structure

```bash
python auditor.py -t <target_url> [options]
```

### Required Arguments

- **`-t, --target`**: Target URL (e.g., `http://example.com:4502`)

### Example

```bash
python auditor.py -t http://target.com:4502
```

## Scan Modes

### Quick Mode

Fast security assessment focusing on critical vulnerabilities:

```bash
python auditor.py -t http://target.com:4502 --mode quick
```

**Characteristics:**
- Maximum 10 requests per second
- 3 concurrent requests
- Critical vulnerabilities only
- Basic version detection
- Estimated duration: 1-3 minutes

### Full Mode (Default)

Comprehensive security audit with all checks:

```bash
python auditor.py -t http://target.com:4502 --mode full
# or simply
python auditor.py -t http://target.com:4502
```

**Characteristics:**
- Maximum 20 requests per second
- 5 concurrent requests
- All vulnerability checks
- Complete version detection
- All security checks enabled
- Estimated duration: 5-15 minutes

### Stealth Mode

Low-profile scanning with minimal footprint:

```bash
python auditor.py -t http://target.com:4502 --mode stealth
```

**Characteristics:**
- Maximum 5 requests per second
- 2 concurrent requests
- Passive detection only
- Safe, non-intrusive checks
- Estimated duration: 10-30 minutes

## Authentication

### Basic Authentication

```bash
python auditor.py -t http://target.com:4502 \
  -u admin \
  -p password
```

**Note**: When credentials are provided via `-u` and `-p`, they are used for authenticated requests. However, default credential testing (from `config/audit_config.yaml`) only occurs if authentication-required paths are detected first during the scan.

### Form-Based Authentication

The auditor automatically detects and handles form-based authentication when testing protected endpoints. Both form-based and HTTP Basic authentication are supported.

## Wordlist Enumeration

### Basic Wordlist Usage

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist wordlists/sling_paths.txt
```

### Extended Wordlist

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist wordlists/sling_paths_extended.txt
```

**Performance Note**: Large wordlists (thousands of paths) are loaded entirely into memory. For very large wordlists, consider:
- Using smaller, focused wordlists
- Reducing `--threads` to manage memory usage
- Processing wordlists in batches

### Custom Wordlist

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist /path/to/custom/wordlist.txt
```

**Wordlist Format:**
- One path per line
- Supports relative paths (e.g., `/system/console`)
- Comments with `#` are ignored
- Paths must start with `/` to be processed

## Exploitation Mode

### Enable Exploitation

```bash
python auditor.py -t http://target.com:4502 --exploit
```

**What it does:**
- Actively exploits detected vulnerabilities
- Generates PoC files for XSS
- Attempts file reading for Path Traversal
- Tests SSRF with internal resources
- Extracts sensitive information

### Exploit Outputs

Exploit outputs are saved to:
```
scan_results/<timestamp>/exploits/
├── CVE-2021-44228/
├── CVE-2018-12809/
│   └── xss_poc_*.html
└── CVE-2017-12617/
    └── extracted_*.txt
```

## Brute Force Testing

### Basic Brute Force

```bash
python auditor.py -t http://target.com:4502 --brute-force
```

Uses default wordlists from `wordlists/` directory.

### Custom Wordlists

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --username-wordlist /path/to/usernames.txt \
  --password-wordlist /path/to/passwords.txt
```

### Combined with Authentication

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force \
  -u admin -p admin  # Test default first
```

## Advanced Options

### Proxy Support

```bash
python auditor.py -t http://target.com:4502 \
  --proxy http://127.0.0.1:8080
```

### Custom User-Agent

```bash
python auditor.py -t http://target.com:4502 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

### Custom Cookies

```bash
python auditor.py -t http://target.com:4502 \
  --cookies "session=abc123; token=xyz789"
```

### Timeout Configuration

```bash
python auditor.py -t http://target.com:4502 \
  --timeout 30  # 30 seconds
```

### Concurrent Threads

```bash
python auditor.py -t http://target.com:4502 \
  --threads 10  # 10 concurrent requests
```

### SSL/TLS Options

```bash
python auditor.py -t https://target.com:4503 \
  -k  # Allow insecure SSL connections
```

### Verbose Output

```bash
python auditor.py -t http://target.com:4502 -v
```

Shows detailed information about:
- Request/response details
- Detection logic
- Error messages
- Progress information

### Custom Output Directory

```bash
python auditor.py -t http://target.com:4502 \
  -o /path/to/output
```

## Complete Examples

### Example 1: Comprehensive Audit

```bash
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths_extended.txt \
  --exploit \
  --brute-force \
  --verbose \
  --threads 10 \
  --timeout 15
```

### Example 2: Covert Assessment

```bash
python auditor.py -t https://target.com:4503 \
  --mode stealth \
  --proxy http://127.0.0.1:8080 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --cookies "session=abc123" \
  -k
```

### Example 3: Quick Security Check

```bash
python auditor.py -t http://target.com:4502 \
  --mode quick \
  -v
```

### Example 4: Credential Testing

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --username-wordlist wordlists/aem_usernames.txt \
  --password-wordlist wordlists/common_passwords.txt \
  --threads 3  # Lower threads for brute force
```

### Example 5: Path Discovery

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist wordlists/sling_paths.txt \
  --threads 10 \
  -v
```

## Understanding Output

### Console Output

The auditor provides real-time feedback:

```
[INFO] Starting scan...
[INFO] Target: http://target.com:4502
[INFO] Mode: full
[INFO] Version detection...
[CRITICAL] Found CRITICAL severity issue: Log4Shell
  Path: /system/console
  Description: Potential Log4Shell vulnerability detected
  CVE: CVE-2021-44228
[HIGH] Found HIGH severity issue: Exposed OSGI Console
  Path: /system/console
  Description: OSGI Console is publicly accessible
```

### Report Files

After scanning, reports are saved to:

```
scan_results/YYYYMMDD_HHMMSS/
└── detailed_report.json
```

**Note**: Currently, only JSON reports are generated. HTML and text summary reports are planned for future releases. The JSON report contains all scan results and findings in a structured format.

### Report Structure

The JSON report contains:

- **scan_info**: Target, mode, duration, statistics
- **findings**: All discovered vulnerabilities
- **version_info**: Detected versions
- **authentication_results**: Auth test results
- **vulnerability_results**: CVE detection results
- **api_results**: Exposed API endpoints
- **configuration_results**: Misconfigurations
- **content_security_results**: Sensitive path exposure
- **wordlist_results**: Enumeration findings
- **brute_force_results**: Credential testing results
- **exploit_results**: Exploitation outcomes

## Best Practices

### 1. Start with Quick Mode

```bash
python auditor.py -t http://target.com:4502 --mode quick
```

Get an overview before running comprehensive scans.

### 2. Use Verbose Mode for Debugging

```bash
python auditor.py -t http://target.com:4502 -v
```

See detailed information about detection logic.

### 3. Save Reports

Reports are automatically saved, but you can specify a custom location:

```bash
python auditor.py -t http://target.com:4502 -o /path/to/reports
```

### 4. Adjust Threads Based on Target

- **Fast targets**: Higher threads (10-20)
- **Slow targets**: Lower threads (3-5)
- **Brute force**: Lower threads (2-3)

### 5. Use Stealth Mode for Production

```bash
python auditor.py -t http://target.com:4502 --mode stealth
```

Minimize impact on production systems.

### 6. Combine Features Strategically

```bash
# Initial reconnaissance
python auditor.py -t http://target.com:4502 --mode quick

# Comprehensive audit
python auditor.py -t http://target.com:4502 --mode full --wordlist wordlists/sling_paths.txt

# Exploitation
python auditor.py -t http://target.com:4502 --exploit
```

## Troubleshooting

### Common Issues

**Issue**: Scan takes too long
- **Solution**: Use `--mode quick` or reduce `--threads`

**Issue**: Too many false positives
- **Solution**: Use `--mode stealth` for more accurate results

**Issue**: Connection errors
- **Solution**: Check network, increase `--timeout`, use `-k` for SSL issues

**Issue**: Memory usage high
- **Solution**: Reduce `--threads`, use smaller wordlists, process wordlists in batches

**Issue**: Default credentials not being tested
- **Solution**: Ensure authentication-required paths are detected first (use `--mode full`), or manually test credentials with `-u` and `-p` flags

**Issue**: Rate limiting detected
- **Solution**: Use `--mode stealth`, increase delays in config

## Command-Line Reference

See [API Reference]({{ site.baseurl }}/api-reference) for complete command-line options.

---

**Need help?** Check out the [Examples]({{ site.baseurl }}/examples) or [Configuration Guide]({{ site.baseurl }}/configuration)!

