---
layout: default
title: Troubleshooting
permalink: /troubleshooting
description: Troubleshooting guide for Apache Sling Auditor. Common issues, error messages, and solutions for scan problems, configuration errors, and performance issues.
keywords: troubleshooting, error handling, common issues, scan problems, configuration errors
related:
  - title: Usage Guide
    url: /usage
    description: Usage instructions
  - title: Configuration
    url: /configuration
    description: Configuration guide
  - title: Quick Start
    url: /quick-start
    description: Get started
---

# Troubleshooting Guide

Common issues and solutions for Apache Sling Auditor.

## Common Issues

### Scan Takes Too Long

**Symptoms:**
- Scan hangs or takes excessive time
- Progress indicators stall

**Solutions:**
- Use `--mode quick` for faster scans
- Reduce `--threads` (try 3-5 instead of default 5)
- Increase `--timeout` if getting timeouts
- Check network connectivity to target
- Use smaller wordlists for path enumeration

**Example:**
```bash
python auditor.py -t http://target.com:4502 --mode quick --threads 3
```

---

### Connection Errors

**Symptoms:**
```
Request error: Connection refused
Request timeout: http://target.com:4502
```

**Solutions:**
- Verify target URL is correct (include `http://` or `https://`)
- Check network connectivity: `ping target.com`
- Verify port is open: `telnet target.com 4502` or `nc -zv target.com 4502`
- Check firewall rules
- Use `-k` flag for SSL certificate issues
- Increase `--timeout` value (default is 10 seconds)

**Example:**
```bash
python auditor.py -t https://target.com:4503 -k --timeout 30
```

---

### SSL Certificate Errors

**Symptoms:**
```
SSL: CERTIFICATE_VERIFY_FAILED
SSL error: certificate verify failed
```

**Solutions:**
- Use `-k` or `--insecure` flag to bypass SSL verification
- Verify certificate manually
- Check if using self-signed certificates

**Example:**
```bash
python auditor.py -t https://target.com:4503 -k
```

**Security Note**: Only use `-k` in testing environments. Never bypass SSL verification in production security assessments.

---

### Memory Usage High

**Symptoms:**
- High memory consumption during scans
- System becomes slow
- Out of memory errors

**Solutions:**
- Reduce `--threads` (lower concurrency = less memory)
- Use smaller wordlists
- Process wordlists in batches
- Close other applications
- Use `--mode quick` or `--mode stealth` (fewer concurrent requests)

**Example:**
```bash
python auditor.py -t http://target.com:4502 --threads 2 --wordlist small_wordlist.txt
```

---

### Default Credentials Not Being Tested

**Symptoms:**
- Credentials from `config/audit_config.yaml` not tested
- No credential testing results in report

**Cause:**
Default credentials are only tested if authentication-required paths (401/403 responses) are detected first.

**Solutions:**
1. **Use full scan mode** to check all endpoints:
   ```bash
   python auditor.py -t http://target.com:4502 --mode full
   ```

2. **Manually test credentials**:
   ```bash
   python auditor.py -t http://target.com:4502 -u admin -p admin
   ```

3. **Enable brute force** (tests credentials regardless):
   ```bash
   python auditor.py -t http://target.com:4502 --brute-force
   ```

---

### Configuration Errors

**Symptoms:**
```
KeyError: 'security_checks'
KeyError: 'configuration'
```

**Cause:**
Missing or incomplete configuration sections in `config/audit_config.yaml`.

**Solutions:**
- Keep the default `config/audit_config.yaml` as a template
- Only modify specific sections, don't remove entire sections
- Verify YAML syntax (indentation, formatting)
- Check that all referenced sections exist

**Example Fix:**
```yaml
# Ensure this section exists
security_checks:
  configuration:
    check_dispatcher: true
    check_replication: true
```

---

### Too Many False Positives

**Symptoms:**
- Many vulnerabilities reported that aren't real
- Inaccurate detection results

**Solutions:**
- Use `--mode stealth` for more accurate results
- Review configuration in `config/audit_config.yaml`
- Adjust detection patterns
- Use `-v` (verbose) to see detection logic
- Manually verify findings
- Use `--exploit` to validate vulnerabilities

**Example:**
```bash
python auditor.py -t http://target.com:4502 --mode stealth -v
```

---

### Rate Limiting Detected

**Symptoms:**
- Many 429 (Too Many Requests) responses
- Account lockouts during brute force
- Slow responses

**Solutions:**
- Use `--mode stealth` (5 req/s instead of 20)
- Reduce `--threads` (try 2-3)
- Increase delays in `config/audit_config.yaml`
- Use proxy with rate limiting
- Add delays between requests

**Example:**
```bash
python auditor.py -t http://target.com:4502 --mode stealth --threads 2
```

---

### No Exploit Outputs Generated

**Symptoms:**
- `--exploit` flag used but no PoC files created
- Missing exploit directories

**Solutions:**
- Verify vulnerabilities were detected (check JSON report)
- Ensure `--exploit` flag was used
- Check output directory permissions
- Review scan results for detected CVEs
- Some CVEs may not have exploitation capabilities

**Example:**
```bash
# First detect vulnerabilities
python auditor.py -t http://target.com:4502

# Then exploit if vulnerabilities found
python auditor.py -t http://target.com:4502 --exploit -v
```

---

### Wordlist Not Loading

**Symptoms:**
```
Wordlist file not found: wordlists/paths.txt
Error loading wordlist: [Errno 2] No such file or directory
```

**Solutions:**
- Verify wordlist file path is correct
- Use absolute path if relative path doesn't work
- Check file permissions
- Ensure wordlist file exists
- Verify file format (one path per line, starting with `/`)

**Example:**
```bash
# Use absolute path
python auditor.py -t http://target.com:4502 --wordlist /full/path/to/wordlist.txt

# Or relative path from project root
python auditor.py -t http://target.com:4502 --wordlist wordlists/sling_paths.txt
```

---

### Invalid URL Error

**Symptoms:**
```
Error: Target URL must include scheme (http:// or https://)
```

**Solutions:**
- Always include protocol (`http://` or `https://`)
- Check URL format: `http://hostname:port` or `https://hostname:port`
- Verify no extra spaces or characters

**Example:**
```bash
# Correct
python auditor.py -t http://target.com:4502

# Incorrect
python auditor.py -t target.com:4502
python auditor.py -t http://target.com:4502/
```

---

### Import Errors

**Symptoms:**
```
ModuleNotFoundError: No module named 'aiohttp'
ImportError: No module named 'rich'
```

**Solutions:**
- Install dependencies: `pip install -r requirements.txt`
- Use virtual environment:
  ```bash
  python -m venv venv
  source venv/bin/activate  # On Windows: .\venv\Scripts\activate
  pip install -r requirements.txt
  ```
- Verify Python version (requires Python 3.7+)

---

### Report Files Not Generated

**Symptoms:**
- No report files in `scan_results/` directory
- Missing JSON report

**Solutions:**
- Check output directory permissions
- Verify scan completed successfully (check console output)
- Specify custom output directory: `-o /path/to/output`
- Check disk space
- Review error messages in verbose mode

**Example:**
```bash
python auditor.py -t http://target.com:4502 -o /custom/output/path -v
```

---

## Performance Optimization

### For Fast Targets

```bash
python auditor.py -t http://target.com:4502 \
  --threads 10 \
  --timeout 5 \
  --mode full
```

### For Slow Targets

```bash
python auditor.py -t http://target.com:4502 \
  --threads 3 \
  --timeout 30 \
  --mode stealth
```

### For Large Wordlists

```bash
python auditor.py -t http://target.com:4502 \
  --wordlist large_wordlist.txt \
  --threads 5 \
  --mode full
```

---

## Getting Help

If you encounter issues not covered here:

1. **Check verbose output**: Use `-v` flag for detailed information
2. **Review JSON report**: Check `scan_results/` for detailed error information
3. **Verify configuration**: Ensure `config/audit_config.yaml` is valid
4. **Test connectivity**: Verify you can reach the target manually
5. **Check logs**: Review console output for error messages

---

## Error Message Reference

| Error Message | Cause | Solution |
|--------------|-------|----------|
| `Target URL must include scheme` | Missing http:// or https:// | Add protocol to URL |
| `Connection refused` | Target unreachable | Check network, firewall, port |
| `Request timeout` | Target too slow | Increase `--timeout` |
| `SSL: CERTIFICATE_VERIFY_FAILED` | SSL certificate issue | Use `-k` flag |
| `KeyError: 'section'` | Missing config section | Check `config/audit_config.yaml` |
| `Wordlist file not found` | Invalid wordlist path | Verify file path |
| `ModuleNotFoundError` | Missing dependencies | Run `pip install -r requirements.txt` |

---

**Still having issues?** Check the [Usage Guide]({{ site.baseurl }}/usage) or review the [Configuration Guide]({{ site.baseurl }}/configuration)!

