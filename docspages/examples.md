---
layout: default
title: Examples
permalink: /examples
description: Practical usage examples for Apache Sling Auditor. Real-world scenarios, command examples, and use cases for security auditing, penetration testing, and vulnerability assessment.
keywords: Apache Sling Auditor examples, security scanning examples, penetration testing examples, vulnerability assessment examples
related:
  - title: Quick Start
    url: /quick-start
    description: Basic examples
  - title: Usage Guide
    url: /usage
    description: Detailed usage
  - title: API Reference
    url: /api-reference
    description: Command reference
---

# Usage Examples

Practical examples for common use cases with Apache Sling Auditor.

## Basic Examples

### Example 1: Initial Reconnaissance

Quick scan to identify obvious security issues:

```bash
python auditor.py -t http://target.com:4502 --mode quick -v
```

**What it does:**
- Fast scan focusing on critical vulnerabilities
- Basic version detection
- Authentication checks
- Verbose output for details

**Use case**: Initial security assessment

---

### Example 2: Comprehensive Security Audit

Full scan with all features enabled:

```bash
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths_extended.txt \
  --exploit \
  --verbose
```

**What it does:**
- Comprehensive security audit
- Path enumeration with extended wordlist
- Active exploitation and PoC generation
- Detailed verbose output

**Use case**: Complete security assessment

---

### Example 3: Covert Assessment

Stealth scan through proxy:

```bash
python auditor.py -t https://target.com:4503 \
  --mode stealth \
  --proxy http://127.0.0.1:8080 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --cookies "session=abc123" \
  -k
```

**What it does:**
- Low-profile scanning
- Routes traffic through proxy
- Custom User-Agent and cookies
- Allows insecure SSL

**Use case**: Covert security testing

---

## Authentication Examples

### Example 4: Authenticated Scan

Scan with credentials:

```bash
python auditor.py -t http://target.com:4502 \
  -u admin \
  -p password \
  --mode full \
  -v
```

**What it does:**
- Uses provided credentials
- Tests authenticated endpoints
- Full scan mode
- Verbose output

**Use case**: Testing authenticated areas

---

### Example 5: Default Credential Testing

Test common default credentials:

```bash
python auditor.py -t http://target.com:4502 \
  --mode quick
```

**What it does:**
- Tests default credentials from config
- Quick scan for fast results
- Reports successful authentications

**Use case**: Checking for default credentials

---

## Exploitation Examples

### Example 6: Vulnerability Exploitation

Generate PoCs for detected vulnerabilities:

```bash
python auditor.py -t http://target.com:4502 \
  --exploit \
  --verbose
```

**What it does:**
- Detects vulnerabilities
- Generates PoC files
- Attempts exploitation
- Saves exploit outputs

**Use case**: Vulnerability validation

---

### Example 7: XSS Exploitation

Focus on XSS vulnerabilities:

```bash
python auditor.py -t http://target.com:4502 \
  --exploit \
  --mode full \
  -v
```

**Output**: HTML PoC files in `scan_results/<timestamp>/exploits/CVE-2018-12809/`

**Use case**: XSS vulnerability validation

---

### Example 8: SSRF Exploitation

Test for SSRF vulnerabilities:

```bash
python auditor.py -t http://target.com:4502 \
  --exploit \
  --mode full
```

**Output**: SSRF test results showing internal resource access

**Use case**: SSRF vulnerability testing

---

## Brute Force Examples

### Example 9: Basic Brute Force

Test login credentials:

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force
```

**What it does:**
- Uses default wordlists
- Tests form-based and Basic auth
- Includes rate limiting
- Reports valid credentials

**Use case**: Credential testing

---

### Example 10: Custom Wordlist Brute Force

Use custom wordlists:

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --username-wordlist /path/to/usernames.txt \
  --password-wordlist /path/to/passwords.txt \
  --threads 3
```

**What it does:**
- Uses custom wordlists
- Lower thread count for brute force
- Tests all combinations
- Reports findings

**Use case**: Targeted credential testing

---

### Example 11: AEM-Specific Brute Force

Use AEM-specific wordlists:

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --username-wordlist wordlists/aem_usernames.txt \
  --password-wordlist wordlists/common_passwords.txt
```

**What it does:**
- Uses AEM-specific usernames
- Common password wordlist
- Optimized for AEM environments

**Use case**: AEM credential testing

---

## Path Enumeration Examples

### Example 12: Basic Path Enumeration

Discover accessible paths:

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist wordlists/sling_paths.txt \
  --threads 10
```

**What it does:**
- Tests all paths in wordlist
- High concurrency for speed
- Categorizes responses

**Use case**: Path discovery

---

### Example 13: Extended Path Enumeration

Use extended wordlist:

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist wordlists/sling_paths_extended.txt \
  --threads 10 \
  -v
```

**What it does:**
- Tests extended wordlist
- More comprehensive coverage
- Verbose output for details

**Use case**: Comprehensive path discovery

---

## Advanced Examples

### Example 14: Production Environment Scan

Safe scanning of production:

```bash
python auditor.py -t https://production.aem.com:4503 \
  --mode stealth \
  --timeout 30 \
  --threads 2 \
  -u admin -p password \
  -k
```

**What it does:**
- Stealth mode for minimal impact
- Longer timeout for slow systems
- Low concurrency
- Authenticated access

**Use case**: Production security audit

---

### Example 15: Development Environment

Comprehensive development scan:

```bash
python auditor.py -t http://dev.aem.local:4502 \
  --mode full \
  --wordlist wordlists/sling_paths_extended.txt \
  --exploit \
  --brute-force \
  --threads 10 \
  -v
```

**What it does:**
- Full scan with all features
- Exploitation enabled
- Brute force testing
- High performance

**Use case**: Development security testing

---

### Example 16: Through Burp Suite

Route traffic through Burp Suite:

```bash
python auditor.py -t http://target.com:4502 \
  --proxy http://127.0.0.1:8080 \
  --mode full \
  -v
```

**What it does:**
- All traffic through Burp
- Can intercept and modify requests
- Full scan mode
- Verbose output

**Use case**: Manual request analysis

---

### Example 17: Custom Output Location

Save results to custom location:

```bash
python auditor.py -t http://target.com:4502 \
  -o /path/to/custom/output \
  --mode full
```

**What it does:**
- Saves reports to custom directory
- Full scan mode
- All results in specified location

**Use case**: Organized result storage

---

## Real-World Scenarios

### Scenario 1: Pre-Deployment Security Check

```bash
# Quick check before deployment
python auditor.py -t http://staging.aem.com:4502 \
  --mode quick \
  -v
```

### Scenario 2: Compliance Audit

```bash
# Comprehensive audit for compliance
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths_extended.txt \
  --exploit \
  -o compliance_audit_$(date +%Y%m%d)
```

### Scenario 3: Vulnerability Research

```bash
# Focus on exploitation
python auditor.py -t http://target.com:4502 \
  --exploit \
  --mode full \
  -v \
  -o research_results
```

### Scenario 4: Penetration Testing

```bash
# Complete penetration test
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths_extended.txt \
  --exploit \
  --brute-force \
  --username-wordlist wordlists/aem_usernames.txt \
  --password-wordlist wordlists/common_passwords.txt \
  --proxy http://127.0.0.1:8080 \
  -v \
  -o pentest_$(date +%Y%m%d)
```

---

## Tips and Best Practices

### 1. Start Small

```bash
# Always start with quick mode
python auditor.py -t http://target.com:4502 --mode quick
```

### 2. Increase Scope Gradually

```bash
# Then expand to full scan
python auditor.py -t http://target.com:4502 --mode full

# Add wordlist enumeration
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths.txt

# Finally, add exploitation
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths.txt \
  --exploit
```

### 3. Use Appropriate Threads

```bash
# Fast target - high threads
python auditor.py -t http://fast-target.com:4502 --threads 10

# Slow target - low threads
python auditor.py -t http://slow-target.com:4502 --threads 3

# Brute force - very low threads
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --threads 2
```

### 4. Save Results

```bash
# Use date-based output directories
python auditor.py -t http://target.com:4502 \
  -o scan_$(date +%Y%m%d_%H%M%S)
```

---

**Need more help?** Check out the [Usage Guide]({{ site.baseurl }}/usage) or [Configuration]({{ site.baseurl }}/configuration)!

