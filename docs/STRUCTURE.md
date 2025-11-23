# Repository Structure

This document describes the organization of the Apache Sling Auditor repository.

## Directory Structure

```
Apache-Sling-Auditor/
│
├── auditor.py                    # Main auditor application
├── requirements.txt              # Python dependencies
├── README.md                     # Main documentation
├── LICENSE                       # License file
├── CONTRIBUTING.md              # Contribution guidelines
│
├── config/                       # Configuration files
│   └── audit_config.yaml        # Main configuration (CVEs, paths, etc.)
│
├── wordlists/                    # Wordlists for testing
│   ├── usernames.txt            # Username wordlist for brute force
│   ├── aem_usernames.txt        # AEM-specific usernames
│   ├── passwords.txt            # Password wordlist for brute force
│   ├── common_passwords.txt     # Common weak passwords
│   ├── sling_paths.txt         # Base path enumeration wordlist
│   ├── sling_paths_extended.txt # Extended path wordlist
│   ├── sling_paths_generated.txt # Generated paths (gitignored)
│   ├── security_headers.txt     # Security headers for testing
│   ├── generate_paths.py        # Path generator script
│   └── header_test.py           # Header testing script
│
├── scan_results/                 # Scan outputs (GITIGNORED)
│   └── YYYYMMDD_HHMMSS/         # Timestamped scan directories
│       ├── detailed_report.json # JSON report
│       └── exploits/            # Exploit outputs (if --exploit used)
│
├── docs/                         # Documentation (optional)
│   └── STRUCTURE.md             # This file
│
└── tests/                        # Test files (optional, future)
```

## File Descriptions

### Core Files

- **auditor.py**: Main application entry point. Contains all scanning logic, CVE detection, exploitation capabilities, and reporting.

### Configuration

- **config/audit_config.yaml**: Central configuration file containing:
  - Scan mode settings
  - CVE definitions and test configurations
  - Path lists for enumeration
  - Default credentials
  - Brute force settings
  - Security check configurations

### Wordlists

- **usernames.txt**: General username wordlist for brute force attacks
- **aem_usernames.txt**: AEM-specific username wordlist
- **passwords.txt**: AEM/Sling-specific password wordlist
- **common_passwords.txt**: Common weak passwords from real-world breaches
- **sling_paths.txt**: Base path enumeration wordlist
- **sling_paths_extended.txt**: Extended comprehensive path wordlist
- **security_headers.txt**: Security headers for testing

### Output Files (Gitignored)

All output files are automatically excluded from Git:

- **scan_results/**: Contains all scan outputs
- **reports/**: Any generated reports
- **exploits/**: Exploit outputs (PoC files, extracted data)
- ***.json**: JSON reports (except config files)
- ***.html**: HTML reports
- ***.log**: Log files

## Best Practices

1. **Never commit scan results** - All outputs are gitignored for security
2. **Use config files** - Don't hardcode values, use `audit_config.yaml`
3. **Add wordlists** - Expand wordlists based on real-world findings
4. **Document changes** - Update README.md when adding features
5. **Test thoroughly** - Test on authorized systems only

## Security Notes

- Scan results may contain sensitive information about target systems
- Exploit outputs may contain extracted credentials or file contents
- Always review `.gitignore` before committing
- Use environment variables for sensitive configuration

