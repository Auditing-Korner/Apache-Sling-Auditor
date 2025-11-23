# Repository Organization

This document describes the organization and structure of the Apache Sling Auditor repository.

## Directory Structure

```
Apache-Sling-Auditor/
│
├── auditor.py                    # Main auditor application (1930+ lines)
├── requirements.txt              # Python dependencies
├── README.md                     # Main documentation
├── LICENSE                       # Apache License 2.0
├── CONTRIBUTING.md              # Contribution guidelines
├── .gitignore                   # Git ignore rules (comprehensive)
├── .gitattributes               # Git file handling rules
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
│   ├── usernames.txt            # General username wordlist (~100 entries)
│   ├── aem_usernames.txt        # AEM-specific usernames (~200 entries)
│   ├── passwords.txt            # AEM/Sling passwords (~150 entries)
│   ├── common_passwords.txt     # Common weak passwords (~200 entries)
│   ├── sling_paths.txt          # Base path wordlist
│   ├── sling_paths_extended.txt # Extended paths (~400 entries)
│   ├── sling_paths_generated.txt # Generated (gitignored)
│   ├── security_headers.txt     # Security headers for testing
│   ├── generate_paths.py         # Path generator script
│   └── header_test.py           # Header testing script
│
├── scan_results/                 # Scan outputs (GITIGNORED)
│   └── YYYYMMDD_HHMMSS/         # Timestamped directories
│       ├── detailed_report.json # JSON report
│       └── exploits/            # Exploit outputs (if --exploit used)
│           ├── CVE-*/           # Per-CVE exploit directories
│           ├── xss_poc_*.html   # XSS PoC files
│           ├── payload_*.js     # JavaScript payloads
│           ├── extracted_*.txt  # Extracted files
│           └── disclosure_*.txt # Information disclosure data
│
└── docs/                         # Documentation
    ├── STRUCTURE.md             # Repository structure
    └── REPOSITORY_ORGANIZATION.md # This file
```

## File Categories

### Source Code
- **auditor.py**: Main application (1930+ lines)
  - CVE detection and exploitation
  - Authentication testing
  - Brute force capabilities
  - Reporting functionality

### Configuration
- **config/audit_config.yaml**: Central configuration
  - All CVE definitions
  - Test paths and payloads
  - Brute force settings
  - Security check configurations

### Wordlists
- **wordlists/**: All enumeration and brute force wordlists
  - Username lists (general + AEM-specific)
  - Password lists (AEM-specific + common)
  - Path enumeration lists
  - Security headers

### Output Files (Gitignored)
All output files are **automatically excluded** from Git:
- `scan_results/` - All scan outputs
- `reports/` - Any report files
- `**/exploits/` - Exploit outputs
- `**/*_report.json` - JSON reports
- `**/extracted_*.txt` - Extracted file contents
- `**/xss_poc_*.html` - XSS PoC files
- `*.log` - Log files

## Git Ignore Rules

The `.gitignore` file ensures:
1. **Scan results are never committed** - All outputs excluded
2. **Exploit data is protected** - Extracted files excluded
3. **Credentials are safe** - Auth files excluded
4. **Generated files ignored** - Auto-generated wordlists excluded
5. **IDE files excluded** - Editor-specific files ignored

## Best Practices

### Before Committing
1. ✅ Run `git status` to verify no scan results are staged
2. ✅ Check that `scan_results/` is not in the commit
3. ✅ Verify no credentials or sensitive data
4. ✅ Review `.gitignore` if adding new file types

### File Organization
1. **Configuration**: All config in `config/` directory
2. **Wordlists**: All wordlists in `wordlists/` directory
3. **Documentation**: All docs in `docs/` directory
4. **Outputs**: All outputs in `scan_results/` (gitignored)

### Adding New Features
1. Add configuration to `config/audit_config.yaml`
2. Add wordlists to `wordlists/` if needed
3. Update documentation in `docs/` or `README.md`
4. Ensure new output files are in `.gitignore`

## Security Considerations

### Never Commit
- ❌ Scan results (`scan_results/`)
- ❌ Reports (`*.json`, `*.html` reports)
- ❌ Exploit outputs (`exploits/`)
- ❌ Extracted data (`extracted_*.txt`)
- ❌ Credentials (`credentials.yaml`, `auth.json`)
- ❌ Log files (`*.log`)

### Always Commit
- ✅ Source code (`auditor.py`)
- ✅ Configuration templates (`config/audit_config.yaml`)
- ✅ Wordlists (`wordlists/*.txt`)
- ✅ Documentation (`README.md`, `docs/`)
- ✅ Requirements (`requirements.txt`)

## Verification

To verify scan results are properly ignored:
```bash
# Check if scan_results is ignored
git check-ignore scan_results/

# View what would be committed (should not include scan_results)
git status

# Verify .gitignore is working
git status --ignored
```

