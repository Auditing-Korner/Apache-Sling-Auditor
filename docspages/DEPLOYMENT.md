# GitHub Pages Deployment Guide

This guide explains how the GitHub Pages documentation is automatically deployed.

## Automatic Deployment

The documentation is automatically deployed using GitHub Actions whenever:

- Changes are pushed to the `main` branch in the `docspages/` directory
- The workflow is manually triggered from the Actions tab

## Deployment Workflow

The deployment process uses the `.github/workflows/pages.yml` workflow:

1. **Checkout**: Clones the repository
2. **Setup Ruby**: Installs Ruby and Bundler
3. **Build**: Builds the Jekyll site from `docspages/`
4. **Deploy**: Deploys to GitHub Pages

## Accessing the Documentation

Once deployed, the documentation will be available at:

**https://auditing-korner.github.io/Apache-Sling-Auditor**

## Manual Deployment

If you need to manually trigger a deployment:

1. Go to the **Actions** tab in GitHub
2. Select **Deploy GitHub Pages** workflow
3. Click **Run workflow**
4. Select the branch (usually `main`)
5. Click **Run workflow**

## Local Testing

Before pushing changes, test locally:

```bash
cd docspages
bundle install
bundle exec jekyll serve
```

Visit `http://localhost:4000/Apache-Sling-Auditor` to preview.

## Troubleshooting

### Build Failures

- Check the Actions tab for error messages
- Verify Jekyll configuration in `_config.yml`
- Ensure all required files are present

### Pages Not Updating

- Wait a few minutes for GitHub to rebuild
- Check the Actions tab for deployment status
- Verify changes were pushed to the `main` branch

### 404 Errors

- Ensure `baseurl` in `_config.yml` matches repository name
- Check that pages have correct `permalink` front matter
- Verify file paths are correct

## Configuration

The deployment is configured in:

- `.github/workflows/pages.yml` - GitHub Actions workflow
- `docspages/_config.yml` - Jekyll configuration
- `docspages/Gemfile` - Ruby dependencies

## Repository Settings

To enable GitHub Pages:

1. Go to **Settings** → **Pages**
2. Source should be set to **GitHub Actions**
3. The workflow will handle the rest automatically

---

For more information, see the [GitHub Pages documentation](https://docs.github.com/en/pages).

