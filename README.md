# GitHub Enterprise API Key Validator

A comprehensive Python framework to validate GitHub Enterprise API key permissions and enumerate all accessible company information.

## Features

- **Comprehensive Permission Validation**: Test 60 GitHub API permissions including:
  - Repository operations (read, write, delete, admin)
  - Organization management (read, admin, teams, webhooks, secrets)
  - Security features (secrets, GPG keys, SSH keys, code scanning, Dependabot)
  - User features (email, follow, notifications)
  - Collaboration (issues, discussions, projects)
  - Enterprise features (enterprise admin)
  - Branch protection and workflows
- **Company Enumeration**: Collect all accessible organization data (repos, teams, members, webhooks, secrets, workflows, etc.)
- **GitHub Actions Visibility**: Automatically surface workflows, secrets, and runner coverage for every repository plus org-level secrets.
- **Enterprise Runner Telemetry**: Enumerate enterprise-wide self-hosted runners, their status, and label health via the `--enterprise-slug` flag.
- **Dual Interface**: Use as both a Python library and CLI tool
- **Flexible Output**: JSON, human-readable console, or both

## Installation

```bash
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

## Usage

### CLI Usage

```bash
# Validate permissions and enumerate company info
python main.py --api-key <your-api-key> --company <company-name>

# Validate permissions only
python main.py --api-key <your-api-key> --company <company-name> --validate

# Enumerate company info only
python main.py --api-key <your-api-key> --company <company-name> --enumerate

# Output in JSON format
python main.py --api-key <your-api-key> --company <company-name> --output json

# Output in console format
python main.py --api-key <your-api-key> --company <company-name> --output console

# Include enterprise-wide runner telemetry
python main.py --api-key <your-api-key> --company <company-name> --enterprise-slug <enterprise-slug>

# Output in both formats
python main.py --api-key <your-api-key> --company <company-name> --output both

# Save results to JSON file (auto-generates filename)
python main.py --api-key <your-api-key> --company <company-name> --save-json

# Save results to specific JSON file
python main.py --api-key <your-api-key> --company <company-name> --save-json results.json

# Save results to CSV file
python main.py --api-key <your-api-key> --company <company-name> --save-csv

# Save both JSON and CSV to specific directory
python main.py --api-key <your-api-key> --company <company-name> --save-json --save-csv --output-dir ./reports
```

### Library Usage

```python
from github_validator import GitHubValidator

# Initialize validator
validator = GitHubValidator(api_key="your-api-key", company_name="company-name")

# Validate permissions
permissions = validator.validate_permissions()

# Enumerate company information
company_info = validator.enumerate_company()

# Get both
results = validator.validate_and_enumerate()
```

## Project Structure

```
Git_APIKeys/
├── github_validator/
│   ├── __init__.py
│   ├── api_client.py
│   ├── permissions.py
│   ├── enumerator.py
│   ├── formatters.py
│   └── cli.py
├── tests/
│   ├── test_permissions.py
│   ├── test_enumerator.py
│   └── test_api_client.py
├── requirements.txt
├── setup.py
├── README.md
└── main.py
```

## Validated Permissions

The framework validates **60 permissions** across two categories:

### Critical Permissions (27)
- `repo` - Repository access
- `repo_write` - Repository write access
- `repo_delete` - Repository delete access
- `admin:org` - Organization admin access
- `read:org` - Organization read access
- `write:org` - Organization write access
- `admin:repo_hook` - Repository webhook management
- `write:repo_hook` - Repository webhook creation and updates
- `read:repo_hook` - Repository webhook visibility
- `admin:org_hook` - Organization webhook management
- `read:org_hook` - Organization webhook visibility
- `workflow` - GitHub Actions workflow access
- `repo_secrets` - Repository secrets access
- `org_secrets` - Organization secrets access
- `write:packages` - Package write access
- `delete:packages` - Package delete access
- `admin:gpg_key` - GPG key administration
- `write:gpg_key` - GPG key management
- `admin:public_key` - SSH key administration
- `write:public_key` - SSH key management
- `admin:enterprise` - Enterprise admin access
- `manage_billing:enterprise` - Enterprise billing management
- `enterprise_admin` - Enterprise admin access (legacy)
- `manage_runners:enterprise` - Enterprise runner administration
- `read:runners:enterprise` - Enterprise runner visibility
- `read:audit_log` - Organization audit log read access
- `write:audit_log` - Organization audit log write access

### Standard Permissions (33)
- `read:user` - User information access
- `user` - Full user profile control
- `gist` - Gist access
- `read:packages` - Package read access
- `notifications` - Notifications access
- `user:email` - User email access
- `user:follow` - User follow/unfollow access
- `read:discussion` - Discussions read access
- `write:discussion` - Discussions write access
- `read:gpg_key` - GPG keys read access
- `read:public_key` - SSH keys read access
- `read:enterprise` - Enterprise read access
- `repo:status` - Commit status access
- `repo_deployment` - Deployment access
- `public_repo` - Public repository access
- `repo:invite` - Repository invitation access
- `write:org` - Organization write access
- `issues` - Issues and pull requests access
- `team_management` - Team management access
- `branch_protection` - Branch protection rules access
- `code_scanning` - Code scanning alerts access
- `dependabot_alerts` - Dependabot alerts access
- `security_advisories` - Security advisories access
- `secret_scanning_alerts` - Secret scanning alerts access
- `security_events` - Aggregate security event access
- `projects` - Projects access
- `runners_repo` - Repository-level GitHub Actions runners access
- `runners_org` - Organization-level GitHub Actions runners access
- `repo_access_count` - Repository access count and permission breakdown
- `secrets_comprehensive` - Comprehensive secrets enumeration (repo and org level)
- `codespace` - Manage GitHub Codespaces
- `codespaces_metadata` - Read Codespaces metadata
- `codespaces_user` - Manage Codespaces user secrets
- `codespaces_lifecycle_admin` - Administer Codespaces lifecycle

### GitHub Actions Insights

Every run now produces an Actions summary by default:

- Counts of repositories with workflows, number of workflows discovered, and which repositories expose Actions secrets.
- Repository-level and organization-level runner coverage, including online/offline breakdowns and tracked labels (e.g., `appsec`, `appsec-dind`).
- Organization Actions secrets and detailed runner tables in console, JSON, and CSV outputs.

Add `--enterprise-slug <slug>` (or `GITHUB_ENTERPRISE_SLUG`) to extend this view to enterprise-wide runners.
### Enterprise Runner Monitoring

Provide the enterprise slug (e.g., `my-company-enterprise`) through `--enterprise-slug` or the `GITHUB_ENTERPRISE_SLUG` environment variable to:

- Populate `manage_runners:enterprise` / `read:runners:enterprise` checks with real data.
- Collect a full inventory of enterprise runners (status, labels, per-label online counts).
- Include runner telemetry in JSON/console output and CSV exports.

## Testing

```bash
pytest tests/
```

## License

MIT

