# Git Repository Setup Guide

This document explains the Git configuration for the Apache Sling Auditor repository.

## Files Overview

### `.gitignore`
Comprehensive ignore rules for:
- Scan results and reports (CRITICAL - never commit)
- Python cache and build artifacts
- IDE and editor files
- OS-specific files
- Security credentials and keys
- Jekyll build outputs
- Generated files

### `.gitattributes`
File handling rules for:
- Line ending normalization (LF for all text files)
- Binary file detection
- Linguist-generated file marking
- Diff settings for different file types

### `.git/info/exclude`
Local-only ignore patterns (not committed to repository)

## Critical Security Rules

### NEVER COMMIT

The following are automatically excluded:

1. **Scan Results** (`scan_results/`, `reports/`, `output/`)
2. **Exploit Outputs** (`**/exploits/`, `**/xss_poc_*.html`)
3. **Extracted Data** (`**/extracted_*.txt`, `**/disclosure_*.txt`)
4. **Credentials** (`*.pem`, `*.key`, `credentials.yaml`, `*.env`)
5. **Reports** (`*.json`, `*.html`, `*.pdf` - except config files)

## Verification

### Check What's Ignored

```bash
# Verify specific files/directories are ignored
git check-ignore scan_results/
git check-ignore __pycache__/
git check-ignore docspages/_site/

# List all ignored files
git status --ignored
```

### Before Committing

Always verify before committing:

```bash
# Check what will be committed
git status

# Should NOT see:
# - scan_results/
# - __pycache__/
# - *.log files
# - exploit outputs
```

## File Categories

### Tracked Files
- Source code (`*.py`)
- Configuration templates (`config/*.yaml`)
- Documentation (`docs/`, `docspages/`)
- Wordlists (`wordlists/*.txt` - except generated)
- Requirements (`requirements.txt`)

### Ignored Files
- Scan outputs (`scan_results/`)
- Build artifacts (`__pycache__/`, `build/`)
- IDE files (`.vscode/`, `.idea/`)
- OS files (`.DS_Store`, `Thumbs.db`)
- Credentials (`*.pem`, `*.key`, `*.env`)

## Line Endings

All text files use LF (Unix) line endings:
- Python files: `*.py text eol=lf`
- Config files: `*.yaml text eol=lf`
- Documentation: `*.md text eol=lf`

This ensures consistency across platforms.

## Generated Files

Files marked as `linguist-generated=true`:
- Generated wordlists
- Scan results (if accidentally present)
- Exploit outputs
- Jekyll build outputs
- Python cache files

These are excluded from language statistics.

## Best Practices

1. **Always check `git status`** before committing
2. **Never force-add ignored files** (`git add -f`)
3. **Review `.gitignore`** when adding new file types
4. **Use `.git/info/exclude`** for personal/local ignores
5. **Test locally** before pushing

## Troubleshooting

### File Still Showing in Git

If a file that should be ignored is still tracked:

```bash
# Remove from Git (but keep locally)
git rm --cached filename

# For directories
git rm -r --cached directory/
```

### Verify Ignore Rules

```bash
# Check which rule matches
git check-ignore -v path/to/file
```

### Update Git Attributes

After changing `.gitattributes`:

```bash
# Refresh attributes
git add --renormalize .
```

## Repository Structure

```
Apache-Sling-Auditor/
├── .gitignore          # Shared ignore rules
├── .gitattributes      # File handling rules
├── .git/
│   └── info/
│       └── exclude    # Local-only ignores
└── ...
```

## Security Checklist

Before every commit, verify:

- [ ] No `scan_results/` in `git status`
- [ ] No `*.log` files
- [ ] No `*.json` reports (except config)
- [ ] No credentials (`*.pem`, `*.key`, `*.env`)
- [ ] No exploit outputs
- [ ] No `__pycache__/` directories

## Support

For questions or issues:
- Review this document
- Check `.gitignore` comments
- Review `.gitattributes` rules
- Open an issue on GitHub

---

**Remember**: When in doubt, check `git status` before committing!

