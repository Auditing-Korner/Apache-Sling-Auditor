---
layout: default
title: Home
permalink: /
---

# Apache Sling / AEM Security Auditor

<div class="hero">
  <h1>Comprehensive Security Auditing for Apache Sling & AEM</h1>
  <p class="lead">A powerful, feature-rich security auditing tool designed to identify misconfigurations, vulnerabilities, and security weaknesses in Apache Sling and Adobe Experience Manager (AEM) instances.</p>
  <p style="margin-top: 1rem;"><strong>Author:</strong> <a href="https://www.linkedin.com/in/ruben-silva85/" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline;">Ruben Silva</a> | <a href="https://github.com/Auditing-Korner" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline;">GitHub</a> | <a href="https://www.patreon.com/cw/rfs85" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline;">Patreon</a></p>
</div>

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Auditing-Korner/Apache-Sling-Auditor.git
cd Apache-Sling-Auditor

# Install dependencies
pip install -r requirements.txt

# Run a scan
python auditor.py -t http://target.com:4502
```

## ✨ Key Features

<div class="features-grid">
  <div class="feature-card">
    <h3>🔍 Multi-Mode Scanning</h3>
    <p>Quick, Full, and Stealth modes optimized for different scenarios</p>
  </div>
  <div class="feature-card">
    <h3>⚡ High Performance</h3>
    <p>Asynchronous scanning with concurrent requests for fast results</p>
  </div>
  <div class="feature-card">
    <h3>🎯 CVE Detection</h3>
    <p>Automated detection of 10+ known CVEs including Log4Shell, XSS, SSRF</p>
  </div>
  <div class="feature-card">
    <h3>💥 Active Exploitation</h3>
    <p>Generate PoCs and validate vulnerabilities with exploitation mode</p>
  </div>
  <div class="feature-card">
    <h3>🔐 Brute Force Testing</h3>
    <p>Automated credential testing with configurable wordlists</p>
  </div>
  <div class="feature-card">
    <h3>📊 Detailed Reporting</h3>
    <p>Rich console output and comprehensive JSON reports</p>
  </div>
</div>

## 📚 Documentation

- **[Installation Guide]({{ site.baseurl }}/installation)** - Get started with installation
- **[Quick Start]({{ site.baseurl }}/quick-start)** - Run your first scan
- **[Features]({{ site.baseurl }}/features)** - Complete feature list
- **[Usage Guide]({{ site.baseurl }}/usage)** - Detailed usage instructions
- **[Configuration]({{ site.baseurl }}/configuration)** - Configure the auditor
- **[CVE Detection]({{ site.baseurl }}/cve-detection)** - Supported vulnerabilities
- **[Exploitation]({{ site.baseurl }}/exploitation)** - Exploitation capabilities
- **[API Reference]({{ site.baseurl }}/api-reference)** - Command-line options
- **[Examples]({{ site.baseurl }}/examples)** - Usage examples

## 🎯 Use Cases

- **Security Auditing**: Comprehensive security assessment of Sling/AEM instances
- **Penetration Testing**: Active exploitation and vulnerability validation
- **Compliance Checking**: Automated security compliance verification
- **Reconnaissance**: Information gathering and enumeration
- **Vulnerability Research**: CVE detection and analysis

## ⚠️ Important Notice

**FOR EDUCATIONAL AND AUTHORIZED USE ONLY**

This tool is intended for security auditing and testing purposes by authorized personnel only. Always obtain explicit written permission before scanning any system.

## 📦 Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 🔧 Basic Usage

```bash
# Full scan
python auditor.py -t http://target.com:4502

# Quick scan
python auditor.py -t http://target.com:4502 --mode quick

# With exploitation
python auditor.py -t http://target.com:4502 --exploit

# Brute force testing
python auditor.py -t http://target.com:4502 --brute-force
```

## 📈 Statistics

- **10+ CVEs** detected automatically
- **3 scan modes** for different scenarios
- **6 security check categories**
- **Multiple exploitation** capabilities
- **Comprehensive reporting** in JSON format

## 🤝 Contributing

Contributions are welcome! See the [Contributing Guide]({{ site.baseurl }}/contributing) for details.

## 📄 License

This project is licensed under the GPL-3.0 License - see the [LICENSE](https://github.com/Auditing-Korner/Apache-Sling-Auditor/blob/main/LICENSE) file for details.

## 👤 Author

**Ruben Silva**

- **LinkedIn**: [https://www.linkedin.com/in/ruben-silva85/](https://www.linkedin.com/in/ruben-silva85/)
- **GitHub**: [Auditing-Korner](https://github.com/Auditing-Korner)
- **Patreon**: [https://www.patreon.com/cw/rfs85](https://www.patreon.com/cw/rfs85) - Support cybersecurity research and get exclusive content

---

<div class="footer-links">
  <a href="{{ site.baseurl }}/installation">Get Started →</a>
  <a href="https://github.com/Auditing-Korner/Apache-Sling-Auditor">View on GitHub →</a>
  <a href="{{ site.baseurl }}/examples">See Examples →</a>
</div>

