---
layout: default
title: Features
permalink: /features
---

# Features

Apache Sling Auditor provides a comprehensive set of security auditing features for Apache Sling and AEM instances.

## Core Features

### 🔍 Multi-Mode Scanning

Three distinct scan modes optimized for different scenarios:

- **Quick Mode**: Fast security assessment (1-3 minutes)
- **Full Mode**: Comprehensive audit (5-15 minutes)
- **Stealth Mode**: Low-profile scanning (10-30 minutes)

See [Usage Guide]({{ site.baseurl }}/usage) for details on each mode.

### ⚡ High-Performance Scanning

- **Asynchronous I/O**: Uses `asyncio` and `aiohttp` for concurrent requests
- **Configurable Concurrency**: Adjust thread count for optimal performance
- **Rate Limiting**: Built-in delays to prevent overwhelming targets
- **Connection Pooling**: Efficient HTTP connection management

### 🎯 Comprehensive CVE Detection

Automated detection of 10+ known CVEs:

- **CVE-2021-44228** (Log4Shell) - Critical RCE
- **CVE-2017-12617** (Path Traversal) - Critical
- **CVE-2020-11987** (SSRF) - High
- **CVE-2018-12809** (XSS) - Medium-High
- **CVE-2019-8086** (Info Disclosure) - Medium
- And more...

See [CVE Detection]({{ site.baseurl }}/cve-detection) for complete list.

### 💥 Active Exploitation

When `--exploit` flag is enabled:

- **XSS Exploitation**: Generates HTML PoC files
- **SSRF Exploitation**: Tests internal resource access
- **Path Traversal**: Attempts file reading
- **Info Disclosure**: Extracts sensitive data

See [Exploitation Guide]({{ site.baseurl }}/exploitation) for details.

### 🔐 Brute Force Testing

Automated credential testing:

- **Multiple Auth Methods**: Form-based and HTTP Basic
- **Custom Wordlists**: Username and password wordlists
- **Rate Limiting**: Prevents account lockouts
- **Lockout Detection**: Identifies rate limiting

### 📋 Path Enumeration

Wordlist-based discovery:

- **Concurrent Enumeration**: Fast parallel requests
- **Response Categorization**: 200, 401, 403, 404
- **Custom Wordlists**: Use your own wordlists
- **Path Filtering**: Automatic validation

### 📊 Detailed Reporting

Multiple output formats:

- **Console Output**: Real-time color-coded results
- **JSON Reports**: Comprehensive machine-readable reports
- **Exploit Outputs**: PoC files and extracted data

## Security Checks

### 1. Version Detection

**Active Detection:**
- Queries version-specific endpoints
- Analyzes product information
- Extracts AEM/Sling version

**Passive Detection:**
- Examines HTTP headers
- Analyzes error messages
- Identifies version indicators

**Vulnerability Correlation:**
- Matches versions against known CVEs
- Reports affected versions
- Identifies potential vulnerabilities

### 2. Authentication Testing

**Default Credentials:**
- Tests common default credentials
- Configurable credential list
- Tests against authenticated endpoints

**Authentication Requirements:**
- Identifies protected paths
- Maps authentication mechanisms
- Analyzes access controls

**Brute Force:**
- Automated credential testing
- Custom wordlist support
- Rate limiting and lockout detection

### 3. Vulnerability Scanning

**CVE Detection:**
- Automated testing for known CVEs
- Specialized detection methods
- Response analysis and pattern matching

**Custom Vulnerabilities:**
- Configurable via YAML
- Custom test paths and payloads
- Severity-based prioritization

### 4. API Endpoint Enumeration

**Discovery:**
- Checks exposed API endpoints
- Tests common Sling/AEM APIs
- Identifies publicly accessible APIs

**Common Endpoints:**
- Query Builder API
- Content API
- OSGI Console
- CRXDE Lite
- And more...

### 5. Configuration Auditing

**OSGI Console:**
- Checks for exposed Felix Console
- Tests OSGI configuration endpoints
- Identifies misconfigurations

**Dispatcher:**
- Tests cache invalidation endpoints
- Checks configuration exposure
- Identifies security issues

**System Configuration:**
- Analyzes system properties
- Checks debug mode
- Identifies development configs

### 6. Content Security Analysis

**Sensitive Paths:**
- Tests exposed sensitive content
- Checks `/etc/passwords`, `/etc/keys`
- Identifies data exposure

**JCR Structure:**
- Analyzes node accessibility
- Checks replication agents
- Identifies permission issues

## Advanced Features

### Proxy Support

Route traffic through HTTP/HTTPS proxies:

```bash
python auditor.py -t http://target.com:4502 --proxy http://127.0.0.1:8080
```

### Custom Headers

Set custom User-Agent, cookies, and headers:

```bash
python auditor.py -t http://target.com:4502 \
  --user-agent "Custom Agent" \
  --cookies "session=abc123"
```

### SSL/TLS Options

Configure SSL verification:

```bash
python auditor.py -t https://target.com:4503 -k  # Allow insecure SSL
```

### Configurable Timeouts

Adjust request timeouts:

```bash
python auditor.py -t http://target.com:4502 --timeout 30
```

### Concurrent Threads

Control concurrency:

```bash
python auditor.py -t http://target.com:4502 --threads 10
```

## Feature Comparison

| Feature | Quick Mode | Full Mode | Stealth Mode |
|---------|-----------|-----------|--------------|
| Request Rate | 10/sec | 20/sec | 5/sec |
| Concurrent Requests | 3 | 5 | 2 |
| Version Detection | Basic | Full | Passive |
| Vulnerability Checks | Critical only | All | Safe only |
| API Enumeration | ❌ | ✅ | ❌ |
| Configuration Audit | ❌ | ✅ | ❌ |
| Content Security | ❌ | ✅ | ❌ |
| Estimated Duration | 1-3 min | 5-15 min | 10-30 min |

## Use Cases

### Security Auditing
- Comprehensive security assessment
- Vulnerability identification
- Misconfiguration detection

### Penetration Testing
- Active exploitation
- PoC generation
- Vulnerability validation

### Compliance Checking
- Automated compliance verification
- Security policy enforcement
- Risk assessment

### Reconnaissance
- Information gathering
- Path enumeration
- API discovery

### Vulnerability Research
- CVE detection and analysis
- Exploit development
- Security research

## Performance

- **Fast Scanning**: Asynchronous I/O for high performance
- **Efficient**: Connection pooling and reuse
- **Scalable**: Configurable concurrency
- **Resource-Friendly**: Low memory footprint

## Extensibility

- **YAML Configuration**: Easy customization
- **Custom CVEs**: Add your own vulnerability checks
- **Wordlist Support**: Use custom wordlists
- **Modular Design**: Easy to extend

---

**Want to learn more?** Check out the [Usage Guide]({{ site.baseurl }}/usage) or [Configuration]({{ site.baseurl }}/configuration)!

