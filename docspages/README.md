# Apache Sling Auditor Documentation

This directory contains the GitHub Pages documentation for Apache Sling Auditor.

## Repository

**GitHub Repository**: [https://github.com/Auditing-Korner/Apache-Sling-Auditor](https://github.com/Auditing-Korner/Apache-Sling-Auditor)

**Live Documentation**: [https://auditing-korner.github.io/Apache-Sling-Auditor](https://auditing-korner.github.io/Apache-Sling-Auditor)

## Automatic Deployment

The documentation is automatically deployed using GitHub Actions whenever:

- Changes are pushed to the `main` branch in the `docspages/` directory
- The workflow is manually triggered from the Actions tab

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment information.

## Local Development

To run the documentation locally:

```bash
# Navigate to docspages directory
cd docspages

# Install Jekyll and dependencies
bundle install

# Serve locally
bundle exec jekyll serve

# Access at http://localhost:4000/Apache-Sling-Auditor
```

## Structure

- `_config.yml` - Jekyll configuration
- `_layouts/default.html` - HTML layout template
- `index.md` - Home page
- `installation.md` - Installation guide
- `quick-start.md` - Quick start guide
- `features.md` - Features documentation
- `usage.md` - Usage guide
- `configuration.md` - Configuration guide
- `cve-detection.md` - CVE detection documentation
- `exploitation.md` - Exploitation guide
- `api-reference.md` - API reference
- `examples.md` - Usage examples
- `contributing.md` - Contributing guide
- `assets/css/style.css` - Custom styles
- `Gemfile` - Ruby dependencies

## Updating Documentation

1. Edit the markdown files in this directory
2. Test locally with `bundle exec jekyll serve`
3. Commit and push changes to the `main` branch
4. GitHub Actions will automatically build and deploy

## GitHub Pages Setup

The documentation is configured to deploy automatically via GitHub Actions:

1. Workflow file: `.github/workflows/pages.yml`
2. Source directory: `docspages/`
3. Build output: `docspages/_site/`
4. Deployment: Automatic on push to `main`

No manual configuration needed - just push your changes!

## Troubleshooting

### Build Failures

- Check the Actions tab for error messages
- Verify Jekyll configuration in `_config.yml`
- Ensure all required files are present

### Pages Not Updating

- Wait a few minutes for GitHub to rebuild
- Check the Actions tab for deployment status
- Verify changes were pushed to the `main` branch

### Local Build Issues

- Ensure Ruby and Bundler are installed
- Run `bundle install` to install dependencies
- Check Ruby version (3.1+ recommended)

## Author

**Ruben Silva**

- **LinkedIn**: [https://www.linkedin.com/in/ruben-silva85/](https://www.linkedin.com/in/ruben-silva85/)
- **GitHub**: [Auditing-Korner](https://github.com/Auditing-Korner)
- **Patreon**: [https://www.patreon.com/cw/rfs85](https://www.patreon.com/cw/rfs85) - Support cybersecurity research and get exclusive content

## Support

For issues or questions about the documentation:

- Open an issue on [GitHub](https://github.com/Auditing-Korner/Apache-Sling-Auditor/issues)
- Check the [deployment guide](DEPLOYMENT.md) for deployment help
