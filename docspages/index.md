---
layout: default
title: Home
permalink: /
description: Comprehensive security auditing tool for Apache Sling and Adobe Experience Manager (AEM) instances. Detect vulnerabilities, misconfigurations, and security weaknesses with automated scanning and exploitation testing.
keywords: Apache Sling, AEM, Security Audit, Vulnerability Scanner, Penetration Testing, CVE Detection, Log4Shell, XSS, SSRF, Path Traversal, Security Testing
toc: false
related:
  - title: Quick Start Guide
    url: /quick-start
    description: Get started in minutes
  - title: Installation Guide
    url: /installation
    description: Setup instructions
  - title: Features Overview
    url: /features
    description: Complete feature list
---

# Apache Sling / AEM Security Auditor

<div class="hero">
  <h1>🔒 Comprehensive Security Auditing for Apache Sling & AEM</h1>
  <p class="lead">A powerful, feature-rich security auditing tool designed to identify misconfigurations, vulnerabilities, and security weaknesses in Apache Sling and Adobe Experience Manager (AEM) instances.</p>
  <p style="margin-top: 1.5rem; font-size: 1.1rem;">
    <strong>Author:</strong> 
    <a href="https://www.linkedin.com/in/ruben-silva85/" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline; font-weight: 600;">Ruben Silva</a> | 
    <a href="https://github.com/Auditing-Korner" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline; font-weight: 600;">GitHub</a> | 
    <a href="https://www.patreon.com/cw/rfs85" target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: underline; font-weight: 600;">Patreon</a>
  </p>
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
    <p>Quick, Full, and Stealth modes optimized for different scenarios. Choose the right mode for your security assessment needs.</p>
  </div>
  <div class="feature-card">
    <h3>⚡ High Performance</h3>
    <p>Asynchronous scanning with concurrent requests for fast results. Efficient I/O operations for maximum throughput.</p>
  </div>
  <div class="feature-card">
    <h3>🎯 CVE Detection</h3>
    <p>Automated detection of 10+ known CVEs including Log4Shell, XSS, SSRF, Path Traversal, and Information Disclosure.</p>
  </div>
  <div class="feature-card">
    <h3>💥 Active Exploitation</h3>
    <p>Generate PoCs and validate vulnerabilities with exploitation mode. Create proof-of-concept files for confirmed issues.</p>
  </div>
  <div class="feature-card">
    <h3>🔐 Brute Force Testing</h3>
    <p>Automated credential testing with configurable wordlists. Support for form-based and HTTP Basic authentication.</p>
  </div>
  <div class="feature-card">
    <h3>📊 Detailed Reporting</h3>
    <p>Rich console output and comprehensive JSON reports. Color-coded severity levels and detailed vulnerability information.</p>
  </div>
</div>

## 📚 Documentation

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin: 2rem 0;">
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>📦 [Installation Guide]({{ site.baseurl }}/installation)</strong><br>
    <small style="color: #6b7280;">Get started with installation and setup</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>🚀 [Quick Start]({{ site.baseurl }}/quick-start)</strong><br>
    <small style="color: #6b7280;">Run your first scan in minutes</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>✨ [Features]({{ site.baseurl }}/features)</strong><br>
    <small style="color: #6b7280;">Complete feature list and capabilities</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>📖 [Usage Guide]({{ site.baseurl }}/usage)</strong><br>
    <small style="color: #6b7280;">Detailed usage instructions</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>⚙️ [Configuration]({{ site.baseurl }}/configuration)</strong><br>
    <small style="color: #6b7280;">Configure the auditor</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>🎯 [CVE Detection]({{ site.baseurl }}/cve-detection)</strong><br>
    <small style="color: #6b7280;">Supported vulnerabilities</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>💥 [Exploitation]({{ site.baseurl }}/exploitation)</strong><br>
    <small style="color: #6b7280;">Exploitation capabilities</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>📚 [API Reference]({{ site.baseurl }}/api-reference)</strong><br>
    <small style="color: #6b7280;">Command-line options</small>
  </div>
  <div style="padding: 1rem; background: #f9fafb; border-radius: 8px; border-left: 4px solid #2563eb; transition: all 0.3s;">
    <strong>💡 [Examples]({{ site.baseurl }}/examples)</strong><br>
    <small style="color: #6b7280;">Usage examples and scenarios</small>
  </div>
</div>

## 🎯 Use Cases

- **Security Auditing**: Comprehensive security assessment of Sling/AEM instances
- **Penetration Testing**: Active exploitation and vulnerability validation
- **Compliance Checking**: Automated security compliance verification
- **Reconnaissance**: Information gathering and enumeration
- **Vulnerability Research**: CVE detection and analysis

<div class="alert alert-danger">
  <strong>⚠️ FOR EDUCATIONAL AND AUTHORIZED USE ONLY</strong><br>
  This tool is intended for security auditing and testing purposes by authorized personnel only. Always obtain explicit written permission before scanning any system.
</div>

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

<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin: 2rem 0;">
  <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #2563eb 0%, #1e40af 100%); color: white; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
    <div style="font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem;">10+</div>
    <div style="font-size: 0.9rem; opacity: 0.9;">CVEs Detected</div>
  </div>
  <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
    <div style="font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem;">3</div>
    <div style="font-size: 0.9rem; opacity: 0.9;">Scan Modes</div>
  </div>
  <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: white; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
    <div style="font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem;">6</div>
    <div style="font-size: 0.9rem; opacity: 0.9;">Security Categories</div>
  </div>
  <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); color: white; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
    <div style="font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem;">∞</div>
    <div style="font-size: 0.9rem; opacity: 0.9;">Exploitation Options</div>
  </div>
</div>

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

