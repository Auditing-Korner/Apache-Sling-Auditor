---
layout: default
title: Quick Start
permalink: /quick-start
---

# Quick Start Guide

Get up and running with Apache Sling Auditor in minutes.

## Your First Scan

The simplest way to scan a target:

```bash
python auditor.py -t http://target.com:4502
```

This will:
- Run a full scan with all checks enabled
- Display results in real-time with color-coded severity
- Save a detailed JSON report to `scan_results/`

## Basic Examples

### 1. Quick Security Check

Fast scan focusing on critical vulnerabilities:

```bash
python auditor.py -t http://target.com:4502 --mode quick
```

**What it does:**
- Tests critical vulnerabilities only
- Basic version detection
- Authentication checks
- Takes 1-3 minutes

### 2. Authenticated Scan

Scan with credentials:

```bash
python auditor.py -t https://target.com:4503 \
  -u admin \
  -p password \
  -v
```

**What it does:**
- Uses provided credentials for authenticated endpoints
- Tests protected paths
- Verbose output for detailed information

### 3. Stealth Scan

Low-profile scanning:

```bash
python auditor.py -t http://target.com:4502 --mode stealth
```

**What it does:**
- Minimal requests per second
- Passive detection only
- Safe, non-intrusive checks
- Takes longer but less detectable

### 4. With Wordlist Enumeration

Discover accessible paths:

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist wordlists/sling_paths.txt
```

**What it does:**
- Tests all paths in the wordlist
- Categorizes responses (200, 401, 403, 404)
- Reports exposed and protected paths

### 5. Exploitation Mode

Generate PoCs for detected vulnerabilities:

```bash
python auditor.py -t http://target.com:4502 --exploit
```

**What it does:**
- Actively exploits detected vulnerabilities
- Generates HTML PoC files for XSS
- Attempts file reading for Path Traversal
- Tests SSRF with internal resources

### 6. Brute Force Testing

Test login credentials:

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --username-wordlist wordlists/usernames.txt \
  --password-wordlist wordlists/passwords.txt
```

**What it does:**
- Tests username/password combinations
- Supports form-based and Basic auth
- Includes rate limiting
- Reports valid credentials

## Understanding Output

### Console Output

The auditor provides real-time feedback:

```
[INFO] Starting scan...
[INFO] Version detection...
[CRITICAL] Found CRITICAL severity issue: Log4Shell
  Path: /system/console
  Description: Potential Log4Shell vulnerability detected
[HIGH] Found HIGH severity issue: Exposed OSGI Console
  Path: /system/console
  Description: OSGI Console is publicly accessible
```

**Severity Colors:**
- 🔴 **CRITICAL** - Red
- 🟡 **HIGH** - Yellow
- 🔵 **MEDIUM** - Cyan
- 🟢 **LOW** - Green
- ⚪ **INFO** - White

### Report Location

After scanning, find your report at:

```
scan_results/YYYYMMDD_HHMMSS/detailed_report.json
```

Example: `scan_results/20241123_143224/detailed_report.json`

## Common Scenarios

### Scenario 1: Initial Reconnaissance

```bash
# Quick scan to identify obvious issues
python auditor.py -t http://target.com:4502 --mode quick -v
```

### Scenario 2: Comprehensive Audit

```bash
# Full scan with all features
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths_extended.txt \
  --exploit \
  --verbose
```

### Scenario 3: Covert Assessment

```bash
# Stealth scan through proxy
python auditor.py -t https://target.com:4503 \
  --mode stealth \
  --proxy http://127.0.0.1:8080 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

### Scenario 4: Credential Testing

```bash
# Brute force with custom wordlists
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --username-wordlist /path/to/usernames.txt \
  --password-wordlist /path/to/passwords.txt \
  -u admin -p admin  # Test default first
```

## Command-Line Options Quick Reference

| Option | Short | Description |
|--------|-------|-------------|
| `--target` | `-t` | Target URL (required) |
| `--mode` | | Scan mode: `quick`, `full`, `stealth` |
| `--username` | `-u` | Username for authentication |
| `--password` | `-p` | Password for authentication |
| `--wordlist` | | Path to wordlist file |
| `--exploit` | | Enable exploitation mode |
| `--brute-force` | | Enable brute force testing |
| `--verbose` | `-v` | Enable verbose output |
| `--proxy` | | Proxy URL |
| `--threads` | | Number of concurrent threads |
| `--timeout` | `-T` | Request timeout in seconds |
| `--insecure` | `-k` | Allow insecure SSL |

## Next Steps

Now that you've run your first scan:

1. **[Read the Usage Guide]({{ site.baseurl }}/usage)** - Learn advanced features
2. **[Explore Configuration]({{ site.baseurl }}/configuration)** - Customize scans
3. **[Check CVE Detection]({{ site.baseurl }}/cve-detection)** - Understand detected vulnerabilities
4. **[Review Examples]({{ site.baseurl }}/examples)** - See more use cases

## Tips for Success

✅ **Always get permission** before scanning any system  
✅ **Start with quick mode** to get an overview  
✅ **Use verbose mode** (`-v`) for detailed information  
✅ **Save reports** - They're automatically saved to `scan_results/`  
✅ **Review JSON reports** - They contain more details than console output  
✅ **Use wordlists** - They help discover hidden paths  
✅ **Test with exploitation** - Validate vulnerabilities with `--exploit`  

## Troubleshooting

### Scan takes too long?

- Use `--mode quick` for faster scans
- Reduce `--threads` if target is slow
- Increase `--timeout` if getting timeouts

### Too many false positives?

- Use `--mode stealth` for more accurate results
- Review configuration in `config/audit_config.yaml`
- Check verbose output for details

### Connection errors?

- Verify target URL is correct
- Check network connectivity
- Use `-k` flag for SSL issues
- Try increasing `--timeout`

---

**Ready for more?** Check out the [Complete Usage Guide]({{ site.baseurl }}/usage)!

