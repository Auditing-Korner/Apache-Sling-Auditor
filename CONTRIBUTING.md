# Contributing to Apache Sling Auditor

Thank you for your interest in contributing to Apache Sling Auditor!

## Repository Structure

```
Apache-Sling-Auditor/
├── auditor.py              # Main auditor script
├── config/                 # Configuration files
│   └── audit_config.yaml   # Main configuration
├── wordlists/              # Wordlists for enumeration and brute force
│   ├── usernames.txt       # Username wordlist
│   ├── passwords.txt       # Password wordlist
│   ├── sling_paths.txt    # Base path wordlist
│   └── ...
├── scan_results/           # Scan outputs (gitignored)
├── docs/                   # Documentation (if added)
├── tests/                  # Test files (if added)
├── requirements.txt        # Python dependencies
├── README.md              # Main documentation
└── LICENSE                # License file
```

## Important: Never Commit Scan Results

**CRITICAL**: Never commit scan results, reports, or extracted data to the repository. These files contain sensitive information and are automatically excluded via `.gitignore`.

### Excluded Files/Directories:
- `scan_results/` - All scan output directories
- `reports/` - Any report files
- `output/` - Alternative output directory
- `**/exploits/` - Exploit outputs
- `**/extracted_*.txt` - Extracted file contents
- `**/xss_poc_*.html` - XSS PoC files
- `**/payload_*.js` - JavaScript payloads
- `**/disclosure_*.txt` - Information disclosure data
- `*.json` (except config files) - JSON reports
- `*.html` - HTML reports
- `*.log` - Log files

### Verification Before Committing

Always verify before committing:
```bash
# Check what will be committed (should NOT include scan_results)
git status

# Verify scan_results is ignored
git check-ignore scan_results/

# View all ignored files
git status --ignored
```

If you see `scan_results/` in `git status`, DO NOT COMMIT. The `.gitignore` should prevent this automatically.

## Development Guidelines

1. **Code Style**: Follow PEP 8 Python style guidelines
2. **Testing**: Test your changes before submitting
3. **Documentation**: Update README.md if adding new features
4. **Configuration**: Add new configuration options to `config/audit_config.yaml`
5. **Wordlists**: Add new wordlists to `wordlists/` directory

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Ensure all tests pass
5. Update documentation if needed
6. Submit a pull request with a clear description

## Security Considerations

- Never commit credentials or API keys
- Never commit scan results or extracted data
- Review `.gitignore` before committing
- Use environment variables for sensitive configuration

