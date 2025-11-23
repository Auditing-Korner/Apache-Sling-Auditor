---
layout: default
title: API Reference
permalink: /api-reference
---

# API Reference

Complete reference for Apache Sling Auditor command-line interface.

## Command Structure

```bash
python auditor.py -t <target_url> [options]
```

## Required Arguments

### `-t, --target`

Target URL to scan.

**Format**: `http://hostname:port` or `https://hostname:port`

**Examples**:
```bash
-t http://example.com:4502
-t https://secure.aem:4503
```

**Required**: Yes

---

## Optional Arguments

### Authentication

#### `-u, --username`

Username for authentication.

**Example**:
```bash
-u admin
```

**Default**: None

---

#### `-p, --password`

Password for authentication.

**Example**:
```bash
-p password
```

**Default**: None

---

### Scan Configuration

#### `--mode`

Scan mode selection.

**Options**:
- `quick` - Fast security assessment
- `full` - Comprehensive audit (default)
- `stealth` - Low-profile scanning

**Example**:
```bash
--mode quick
```

**Default**: `full`

---

#### `--wordlist`

Path to wordlist file for path enumeration.

**Example**:
```bash
--wordlist wordlists/sling_paths.txt
```

**Default**: None

---

#### `--exploit`

Enable exploitation mode to generate PoCs and validate vulnerabilities.

**Example**:
```bash
--exploit
```

**Default**: Disabled

---

#### `--brute-force`

Enable brute force login testing.

**Example**:
```bash
--brute-force
```

**Default**: Disabled

---

#### `--username-wordlist`

Path to username wordlist for brute force attacks.

**Example**:
```bash
--username-wordlist wordlists/usernames.txt
```

**Default**: Uses default wordlist from config

---

#### `--password-wordlist`

Path to password wordlist for brute force attacks.

**Example**:
```bash
--password-wordlist wordlists/passwords.txt
```

**Default**: Uses default wordlist from config

---

### Network Configuration

#### `--proxy`

Proxy URL for routing traffic.

**Format**: `http://hostname:port` or `https://hostname:port`

**Example**:
```bash
--proxy http://127.0.0.1:8080
```

**Default**: None

---

#### `--user-agent`

Custom User-Agent string.

**Example**:
```bash
--user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

**Default**: Standard browser User-Agent

---

#### `--cookies`

Cookies to include with requests.

**Format**: `"key1=val1; key2=val2"`

**Example**:
```bash
--cookies "session=abc123; token=xyz789"
```

**Default**: None

---

#### `-T, --timeout`

Request timeout in seconds.

**Example**:
```bash
--timeout 30
```

**Default**: `10`

---

#### `-k, --insecure`

Allow insecure SSL connections (ignore certificate errors).

**Example**:
```bash
-k
```

**Default**: SSL verification enabled

---

### Performance

#### `--threads`

Number of concurrent threads/requests.

**Example**:
```bash
--threads 10
```

**Default**: `5`

**Note**: Higher values = faster but more resource-intensive

---

### Output

#### `-o, --output`

Output directory for scan results.

**Example**:
```bash
-o /path/to/output
```

**Default**: `scan_results`

---

#### `-v, --verbose`

Enable verbose output for detailed information.

**Example**:
```bash
-v
```

**Default**: Disabled

---

### Help

#### `-h, --help`

Show help message and exit.

**Example**:
```bash
-h
```

---

## Complete Option List

| Option | Short | Type | Default | Description |
|-------|------|------|---------|-------------|
| `--target` | `-t` | string | - | Target URL (required) |
| `--username` | `-u` | string | None | Username for authentication |
| `--password` | `-p` | string | None | Password for authentication |
| `--mode` | | choice | `full` | Scan mode: quick, full, stealth |
| `--wordlist` | | string | None | Path to wordlist file |
| `--exploit` | | flag | False | Enable exploitation mode |
| `--brute-force` | | flag | False | Enable brute force testing |
| `--username-wordlist` | | string | None | Username wordlist for brute force |
| `--password-wordlist` | | string | None | Password wordlist for brute force |
| `--proxy` | | string | None | Proxy URL |
| `--user-agent` | | string | Default | Custom User-Agent string |
| `--cookies` | | string | None | Cookies to include |
| `--timeout` | `-T` | int | 10 | Request timeout in seconds |
| `--insecure` | `-k` | flag | False | Allow insecure SSL |
| `--threads` | | int | 5 | Number of concurrent threads |
| `--output` | `-o` | string | `scan_results` | Output directory |
| `--verbose` | `-v` | flag | False | Enable verbose output |
| `--help` | `-h` | flag | - | Show help message |

## Usage Examples

### Basic Scan

```bash
python auditor.py -t http://target.com:4502
```

### Quick Scan

```bash
python auditor.py -t http://target.com:4502 --mode quick
```

### Authenticated Scan

```bash
python auditor.py -t http://target.com:4502 -u admin -p password
```

### With Exploitation

```bash
python auditor.py -t http://target.com:4502 --exploit
```

### Brute Force

```bash
python auditor.py -t http://target.com:4502 \
  --brute-force \
  --username-wordlist wordlists/usernames.txt \
  --password-wordlist wordlists/passwords.txt
```

### Through Proxy

```bash
python auditor.py -t http://target.com:4502 \
  --proxy http://127.0.0.1:8080
```

### Custom Configuration

```bash
python auditor.py -t http://target.com:4502 \
  --user-agent "Custom Agent" \
  --cookies "session=abc123" \
  --timeout 30 \
  --threads 10 \
  -v
```

### Complete Example

```bash
python auditor.py -t http://target.com:4502 \
  --mode full \
  --wordlist wordlists/sling_paths_extended.txt \
  --exploit \
  --brute-force \
  --username-wordlist wordlists/aem_usernames.txt \
  --password-wordlist wordlists/common_passwords.txt \
  --proxy http://127.0.0.1:8080 \
  --user-agent "Mozilla/5.0" \
  --cookies "session=abc123" \
  --timeout 15 \
  --threads 10 \
  -o /path/to/output \
  -v
```

## Exit Codes

- **0**: Success
- **1**: Error (invalid arguments, connection errors, etc.)

## Environment Variables

The auditor respects the following environment variables:

- **HTTP_PROXY**: HTTP proxy URL
- **HTTPS_PROXY**: HTTPS proxy URL
- **NO_PROXY**: Comma-separated list of hosts to bypass proxy

## Return Values

The auditor returns a JSON report to the output directory containing:

- Scan information
- All findings
- Vulnerability results
- Exploitation results (if enabled)
- Brute force results (if enabled)

## Error Handling

Common errors and solutions:

### Invalid URL

```
Error: Target URL must include scheme (http:// or https://)
```

**Solution**: Ensure URL includes protocol (http:// or https://)

### Connection Errors

```
Request error: Connection refused
```

**Solution**: Check target URL, network connectivity, firewall rules

### SSL Errors

```
SSL: CERTIFICATE_VERIFY_FAILED
```

**Solution**: Use `-k` flag to allow insecure SSL connections

### Timeout Errors

```
Request timeout: http://target.com:4502
```

**Solution**: Increase timeout with `--timeout` option

---

**Need examples?** Check out the [Usage Guide]({{ site.baseurl }}/usage) or [Examples]({{ site.baseurl }}/examples)!

