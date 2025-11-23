"""
CLI Interface Module

Command-line interface for the GitHub Enterprise API Key Validator.
"""

import click
import sys
import os
from typing import Optional
from .api_client import GitHubAPIClient
from .permissions import PermissionChecker
from .enumerator import CompanyEnumerator
from .formatters import OutputFormatter
from .runners import EnterpriseRunnerInspector
from .runner_operations import RunnerOperations
from .resources import ResourceLister
from .test_suite import TestSuite
from .report_generator import HTMLReportGenerator
from .actions_detector import ActionsDetector
from .security_analyzer import SecurityAnalyzer
from .repository_analyzer import RepositoryAnalyzer
from .codespaces_detector import CodespacesDetector
from .issues_prs_analyzer import IssuesPRsAnalyzer
from .content_analyzer import ContentAnalyzer
from .packages_analyzer import PackagesAnalyzer
from .token_metadata import TokenMetadataAnalyzer
from .repository_insights import RepositoryInsightsAnalyzer
from .audit_log_analyzer import EnterpriseAuditLogAnalyzer
from .gists_analyzer import GistsAnalyzer
from .user_activity import UserActivityAnalyzer
from .discussions_analyzer import DiscussionsAnalyzer
from .commit_analyzer import CommitAnalyzer
from .branch_analyzer import BranchAnalyzer
from .team_analyzer import TeamAnalyzer
from .notification_analyzer import NotificationAnalyzer
from .webhook_analyzer import WebhookAnalyzer
from .oauth_app_analyzer import OAuthAppAnalyzer
from .github_app_analyzer import GitHubAppAnalyzer
from .dependency_analyzer import DependencyAnalyzer
from .pr_reviews_analyzer import PRReviewsAnalyzer
from .repository_settings_analyzer import RepositorySettingsAnalyzer
from .organization_settings_analyzer import OrganizationSettingsAnalyzer
from .environment_secrets_analyzer import EnvironmentSecretsAnalyzer
from .milestones_analyzer import MilestonesAnalyzer
from .labels_analyzer import LabelsAnalyzer
from .projects_analyzer import ProjectsAnalyzer
from .reactions_analyzer import ReactionsAnalyzer
from .commit_comments_analyzer import CommitCommentsAnalyzer
from .pr_files_analyzer import PRFilesAnalyzer
from .issue_events_analyzer import IssueEventsAnalyzer
from .contributors_analyzer import ContributorsAnalyzer
from .stargazers_watchers_analyzer import StargazersWatchersAnalyzer
from .fork_network_analyzer import ForkNetworkAnalyzer
from .release_assets_analyzer import ReleaseAssetsAnalyzer
from .repository_invitations_analyzer import RepositoryInvitationsAnalyzer
from .repository_transfer_analyzer import RepositoryTransferAnalyzer
from .workflow_run_logs_analyzer import WorkflowRunLogsAnalyzer
from .artifact_details_analyzer import ArtifactDetailsAnalyzer
from .secret_scanning_alerts_analyzer import SecretScanningAlertsAnalyzer
from .code_scanning_alerts_analyzer import CodeScanningAlertsAnalyzer
from .repository_topics_analyzer import RepositoryTopicsAnalyzer
from .repository_languages_analyzer import RepositoryLanguagesAnalyzer
from .enterprise_settings_analyzer import EnterpriseSettingsAnalyzer
from .repository_statistics_analyzer import RepositoryStatisticsAnalyzer
from .rate_limit_monitor import RateLimitMonitor
from .permission_drift_detector import PermissionDriftDetector
from .compliance_checker import ComplianceChecker, ComplianceFramework
from .remediation_engine import RemediationEngine


@click.command()
@click.option(
    "--api-key",
    required=True,
    help="GitHub Enterprise API key/token",
    envvar="GITHUB_API_KEY"
)
@click.option(
    "--company",
    required=True,
    help="Company/Organization name to validate and enumerate"
)
@click.option(
    "--base-url",
    default=None,
    help="GitHub Enterprise base URL (defaults to github.com API)"
)
@click.option(
    "--validate",
    is_flag=True,
    default=False,
    help="Only validate permissions (skip enumeration)"
)
@click.option(
    "--enumerate",
    is_flag=True,
    default=False,
    help="Only enumerate company info (skip permission validation)"
)
@click.option(
    "--output",
    type=click.Choice(["json", "console", "both"], case_sensitive=False),
    default="console",
    help="Output format: json, console, or both"
)
@click.option(
    "--all-orgs",
    is_flag=True,
    default=False,
    help="Enumerate all accessible organizations (ignores --company for enumeration)"
)
@click.option(
    "--save-json",
    type=str,
    default=None,
    help="Save JSON results to specified file (auto-generates filename if not provided)"
)
@click.option(
    "--save-csv",
    type=str,
    default=None,
    help="Save results to CSV file (auto-generates filename if not provided)"
)
@click.option(
    "--output-dir",
    type=str,
    default=".",
    help="Directory to save output files (default: current directory)"
)
@click.option(
    "--enterprise-slug",
    type=str,
    default=None,
    envvar="GITHUB_ENTERPRISE_SLUG",
    help="Enterprise slug to query enterprise-wide runner metadata"
)
@click.option(
    "--list-ssh-keys",
    is_flag=True,
    default=False,
    help="List SSH keys available from GitHub API"
)
@click.option(
    "--list-projects",
    is_flag=True,
    default=False,
    help="List all projects accessible by the token"
)
@click.option(
    "--list-repos",
    is_flag=True,
    default=False,
    help="List all repositories accessible by the token"
)
@click.option(
    "--list-webhooks",
    is_flag=True,
    default=False,
    help="List webhooks from repositories and organizations"
)
@click.option(
    "--extract-secrets",
    type=str,
    default=None,
    help="Extract all organization secrets (requires org_secrets permission)"
)
@click.option(
    "--validate-repo-creation",
    is_flag=True,
    default=False,
    help="Validate if token can create new repositories"
)
@click.option(
    "--execute",
    type=str,
    default=None,
    help="Execute command on online runners via SSH"
)
@click.option(
    "--ssh-user",
    type=str,
    default=None,
    help="SSH username for runner execution"
)
@click.option(
    "--ssh-key",
    type=str,
    default=None,
    help="Path to SSH private key"
)
@click.option(
    "--ssh-port",
    type=int,
    default=22,
    help="SSH port (default: 22)"
)
@click.option(
    "--test-all",
    is_flag=True,
    default=False,
    help="Run comprehensive test suite"
)
@click.option(
    "--generate-report",
    type=str,
    default=None,
    help="Generate HTML security report with actual findings (specify output filename)"
)
@click.option(
    "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose logging and detailed output"
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Disable API response caching"
)
@click.option(
    "--compare-keys",
    type=str,
    default=None,
    help="Compare multiple API keys (provide JSON file with keys array)"
)
@click.option(
    "--export-format",
    type=click.Choice(["html", "pdf", "excel", "json", "all"], case_sensitive=False),
    multiple=True,
    default=["html"],
    help="Export formats for report (can specify multiple)"
)
@click.option(
    "--monitor-rate-limit",
    is_flag=True,
    default=False,
    help="Monitor and display rate limit usage throughout execution"
)
@click.option(
    "--detect-drift",
    is_flag=True,
    default=False,
    help="Detect permission changes compared to previous snapshots"
)
@click.option(
    "--check-compliance",
    type=click.Choice(["SOC2", "ISO27001", "NIST_CSF", "CIS_BENCHMARKS", "PCI_DSS", "GDPR", "all"], case_sensitive=False),
    multiple=True,
    default=None,
    help="Check compliance against specified frameworks"
)
def main(api_key: str, company: str, base_url: Optional[str], 
         validate: bool, enumerate: bool, output: str, all_orgs: bool,
         save_json: Optional[str], save_csv: Optional[str], output_dir: str,
         enterprise_slug: Optional[str], list_ssh_keys: bool, list_projects: bool,
         list_repos: bool, list_webhooks: bool, extract_secrets: Optional[str],
         validate_repo_creation: bool, execute: Optional[str], ssh_user: Optional[str],
         ssh_key: Optional[str], ssh_port: int, test_all: bool, generate_report: Optional[str] = None,
         verbose: bool = False, no_cache: bool = False, compare_keys: Optional[str] = None,
         export_format: tuple = ("html",), monitor_rate_limit: bool = False,
         detect_drift: bool = False, check_compliance: tuple = None):
    """
    GitHub Enterprise API Key Validator
    
    Validates API key permissions and enumerates company/organization information.
    """
    # Initialize components
    try:
        from .progress import get_logger
        from .cache import get_cache
        
        logger = get_logger(verbose=verbose)
        
        # Configure cache
        if no_cache:
            get_cache().clear()
            logger.info("API caching disabled")
        
        api_client = GitHubAPIClient(api_key, base_url)
        
        # Initialize rate limit monitor if requested
        rate_limit_monitor = None
        if monitor_rate_limit or generate_report:
            rate_limit_monitor = RateLimitMonitor(api_client)
            if monitor_rate_limit:
                rate_limit_status = rate_limit_monitor.check_rate_limit()
                core = rate_limit_status.get("core", {})
                click.echo(f"\n📊 Rate Limit Status:", err=True)
                click.echo(f"  Remaining: {core.get('remaining', 0)}/{core.get('limit', 0)} ({core.get('usage_percent', 0):.1f}% used)", err=True)
                click.echo(f"  Status: {core.get('status', 'unknown').upper()}", err=True)
                if core.get('time_until_reset'):
                    click.echo(f"  Resets in: {int(core.get('time_until_reset', 0) / 60)} minutes", err=True)
        
        # Test authentication first
        user_info = api_client.test_authentication()
        if not user_info:
            click.echo("Error: Invalid API key or authentication failed", err=True)
            sys.exit(1)
        
        click.echo(f"Authenticated as: {user_info.get('login', 'Unknown')}", err=True)
        
        # Handle new feature flags first
        runner_ops = RunnerOperations(api_client)
        resources = ResourceLister(api_client)
        
        # List SSH keys
        if list_ssh_keys:
            click.echo("Listing SSH keys...", err=True)
            ssh_keys = runner_ops.list_ssh_keys()
            if output == "json":
                import json
                click.echo(json.dumps({"ssh_keys": ssh_keys}, indent=2))
            else:
                click.echo(f"\nFound {len(ssh_keys)} SSH key(s):")
                for key in ssh_keys:
                    click.echo(f"  - {key.get('title', 'Untitled')} (ID: {key.get('id')})")
            return
        
        # List projects
        if list_projects:
            click.echo("Listing projects...", err=True)
            projects = resources.list_projects()
            if output == "json":
                import json
                click.echo(json.dumps(projects, indent=2))
            else:
                click.echo(f"\nTotal Projects: {projects.get('total', 0)}")
                click.echo(f"  User Projects: {len(projects.get('user_projects', []))}")
                click.echo(f"  Organization Projects: {len(projects.get('org_projects', []))}")
                click.echo(f"  Repository Projects: {len(projects.get('repo_projects', []))}")
            return
        
        # List repositories
        if list_repos:
            click.echo("Listing repositories...", err=True)
            repos = resources.list_repositories()
            if output == "json":
                import json
                click.echo(json.dumps(repos, indent=2))
            else:
                click.echo(f"\nTotal Repositories: {repos.get('total', 0)}")
                click.echo(f"  User Repositories: {len(repos.get('user_repos', []))}")
                click.echo(f"  Organization Repositories: {len(repos.get('org_repos', []))}")
                click.echo(f"  Starred Repositories: {len(repos.get('starred_repos', []))}")
            return
        
        # List webhooks
        if list_webhooks:
            click.echo("Listing webhooks...", err=True)
            webhooks = resources.list_webhooks()
            if output == "json":
                import json
                click.echo(json.dumps(webhooks, indent=2))
            else:
                click.echo(f"\nTotal Webhooks: {webhooks.get('total', 0)}")
                click.echo(f"  User Repository Webhooks: {len(webhooks.get('user_repo_webhooks', []))}")
                click.echo(f"  Organization Webhooks: {len(webhooks.get('org_webhooks', []))}")
                click.echo(f"  Organization Repository Webhooks: {len(webhooks.get('org_repo_webhooks', []))}")
            return
        
        # Extract secrets
        if extract_secrets:
            click.echo(f"Extracting secrets from organization: {extract_secrets}...", err=True)
            secrets = resources.extract_org_secrets(extract_secrets)
            if output == "json":
                import json
                click.echo(json.dumps({"secrets": secrets}, indent=2))
            else:
                click.echo(f"\nFound {len(secrets)} secret(s) in {extract_secrets}")
                for secret in secrets:
                    click.echo(f"  - {secret.get('name', 'Unknown')}")
            return
        
        # Validate repo creation
        if validate_repo_creation:
            click.echo("Validating repository creation permissions...", err=True)
            validation = resources.validate_repo_creation()
            if output == "json":
                import json
                click.echo(json.dumps(validation, indent=2))
            else:
                click.echo(f"\nCan create user repositories: {validation.get('can_create_user_repos', False)}")
                click.echo(f"Can create org repositories: {validation.get('can_create_org_repos', False)}")
                click.echo(f"Overall can create: {validation.get('overall_can_create', False)}")
            return
        
        # Execute on runners
        if execute:
            if not enterprise_slug:
                click.echo("Error: --enterprise-slug is required for --execute", err=True)
                sys.exit(1)
            click.echo(f"Executing command on runners: {execute}", err=True)
            inspector = EnterpriseRunnerInspector(api_client, enterprise_slug)
            runner_data = inspector.fetch_runners()
            runners = runner_data.get("runners", [])
            results = runner_ops.execute_on_runners(
                runners=runners,
                command=execute,
                ssh_user=ssh_user,
                ssh_key=ssh_key,
                ssh_port=ssh_port
            )
            if output == "json":
                import json
                click.echo(json.dumps(results, indent=2))
            else:
                click.echo(f"\nExecution Summary:")
                click.echo(f"  Total: {results.get('total', 0)}")
                click.echo(f"  Successful: {results.get('successful', 0)}")
                click.echo(f"  Failed: {results.get('failed', 0)}")
            return
        
        # Test all
        if test_all:
            click.echo("Running comprehensive test suite...", err=True)
            test_suite = TestSuite(api_client, enterprise_slug)
            results = test_suite.run_all_tests()
            if output == "json":
                import json
                click.echo(json.dumps(results, indent=2))
            else:
                click.echo(f"\nTest Suite Summary:")
                summary = results.get("summary", {})
                click.echo(f"  Total Tests: {summary.get('total_tests', 0)}")
                click.echo(f"  Passed: {summary.get('passed', 0)}")
                click.echo(f"  Failed: {summary.get('failed', 0)}")
                click.echo(f"  Success Rate: {summary.get('success_rate', 0):.1f}%")
            return
        
        # Generate HTML report with actual findings
        if generate_report:
            click.echo("Collecting data for security report...", err=True)
            
            # Collect all data
            permissions_data = None
            enumeration_data = None
            enterprise_runner_data = None
            resources_data = {}
            test_results_data = None
            
            # Get permissions
            click.echo("  - Validating permissions...", err=True)
            permission_checker = PermissionChecker(api_client, enterprise_slug=enterprise_slug)
            permissions_data = permission_checker.validate_all_permissions(
                org_name=company,
                enterprise_slug=enterprise_slug,
            )
            
            # Get enumeration
            click.echo("  - Enumerating organization...", err=True)
            enumerator = CompanyEnumerator(api_client)
            if all_orgs:
                enumeration_data = enumerator.enumerate_all_accessible_orgs()
            else:
                enumeration_data = enumerator.enumerate_organization(company)
            
            # Get runner data
            if enterprise_slug:
                click.echo("  - Collecting runner telemetry...", err=True)
                inspector = EnterpriseRunnerInspector(api_client, enterprise_slug)
                enterprise_runner_data = inspector.fetch_runners()
            
            # Get resources
            click.echo("  - Listing resources...", err=True)
            resources_data["repositories"] = resources.list_repositories()
            resources_data["projects"] = resources.list_projects()
            resources_data["webhooks"] = resources.list_webhooks()
            
            # Get secrets if accessible
            try:
                click.echo("  - Extracting secrets...", err=True)
                secrets = resources.extract_org_secrets(company)
                resources_data["secrets"] = secrets
            except Exception as e:
                click.echo(f"  - Could not extract secrets: {str(e)}", err=True)
                resources_data["secrets"] = []
            
            # PR Reviews Analysis
            click.echo("  - Analyzing PR reviews...", err=True)
            pr_reviews_analyzer = PRReviewsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_pr_reviews = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_pr_reviews[org_name] = pr_reviews_analyzer.analyze_org_pr_reviews(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["pr_reviews"] = org_pr_reviews
                else:
                    try:
                        org_pr_reviews = pr_reviews_analyzer.analyze_org_pr_reviews(company, max_repos=15)
                        resources_data["pr_reviews"] = {company: org_pr_reviews}
                    except Exception:
                        resources_data["pr_reviews"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze PR reviews: {str(e)}", err=True)
                resources_data["pr_reviews"] = {}
            
            # Repository Settings Analysis
            click.echo("  - Analyzing repository settings...", err=True)
            repo_settings_analyzer = RepositorySettingsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_repo_settings = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_repo_settings[org_name] = repo_settings_analyzer.analyze_org_repo_settings(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["repository_settings"] = org_repo_settings
                else:
                    try:
                        org_repo_settings = repo_settings_analyzer.analyze_org_repo_settings(company, max_repos=15)
                        resources_data["repository_settings"] = {company: org_repo_settings}
                    except Exception:
                        resources_data["repository_settings"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze repository settings: {str(e)}", err=True)
                resources_data["repository_settings"] = {}
            
            # Organization Settings Analysis
            click.echo("  - Analyzing organization settings...", err=True)
            org_settings_analyzer = OrganizationSettingsAnalyzer(api_client)
            try:
                if all_orgs:
                    org_settings = org_settings_analyzer.analyze_all_orgs_settings(max_orgs=10)
                    resources_data["organization_settings"] = org_settings
                else:
                    org_settings = org_settings_analyzer.analyze_org_settings(company)
                    resources_data["organization_settings"] = {company: org_settings}
            except Exception as e:
                click.echo(f"  - Could not analyze organization settings: {str(e)}", err=True)
                resources_data["organization_settings"] = {}
            
            # Environment Secrets Analysis
            click.echo("  - Analyzing environment secrets...", err=True)
            env_secrets_analyzer = EnvironmentSecretsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_env_secrets = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_env_secrets[org_name] = env_secrets_analyzer.analyze_org_environments(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["environment_secrets"] = org_env_secrets
                else:
                    try:
                        org_env_secrets = env_secrets_analyzer.analyze_org_environments(company, max_repos=15)
                        resources_data["environment_secrets"] = {company: org_env_secrets}
                    except Exception:
                        resources_data["environment_secrets"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze environment secrets: {str(e)}", err=True)
                resources_data["environment_secrets"] = {}
            
            # Milestones Analysis
            click.echo("  - Analyzing milestones...", err=True)
            milestones_analyzer = MilestonesAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_milestones = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_milestones[org_name] = milestones_analyzer.analyze_org_milestones(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["milestones"] = org_milestones
                else:
                    try:
                        org_milestones = milestones_analyzer.analyze_org_milestones(company, max_repos=15)
                        resources_data["milestones"] = {company: org_milestones}
                    except Exception:
                        resources_data["milestones"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze milestones: {str(e)}", err=True)
                resources_data["milestones"] = {}
            
            # Labels Analysis
            click.echo("  - Analyzing labels...", err=True)
            labels_analyzer = LabelsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_labels = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_labels[org_name] = labels_analyzer.analyze_org_repo_labels(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["labels"] = org_labels
                else:
                    try:
                        org_labels = labels_analyzer.analyze_org_repo_labels(company, max_repos=15)
                        resources_data["labels"] = {company: org_labels}
                    except Exception:
                        resources_data["labels"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze labels: {str(e)}", err=True)
                resources_data["labels"] = {}
            
            # Projects Analysis
            click.echo("  - Analyzing GitHub Projects...", err=True)
            projects_analyzer = ProjectsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_projects = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_projects[org_name] = projects_analyzer.analyze_org_repo_projects(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["projects_analysis"] = org_projects
                else:
                    try:
                        org_projects = projects_analyzer.analyze_org_repo_projects(company, max_repos=15)
                        resources_data["projects_analysis"] = {company: org_projects}
                    except Exception:
                        resources_data["projects_analysis"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze projects: {str(e)}", err=True)
                resources_data["projects_analysis"] = {}
            
            # Reactions Analysis
            click.echo("  - Analyzing reactions...", err=True)
            reactions_analyzer = ReactionsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_reactions = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_reactions[org_name] = reactions_analyzer.analyze_org_reactions(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["reactions"] = org_reactions
                else:
                    try:
                        org_reactions = reactions_analyzer.analyze_org_reactions(company, max_repos=15)
                        resources_data["reactions"] = {company: org_reactions}
                    except Exception:
                        resources_data["reactions"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze reactions: {str(e)}", err=True)
                resources_data["reactions"] = {}
            
            # Commit Comments Analysis
            click.echo("  - Analyzing commit comments...", err=True)
            commit_comments_analyzer = CommitCommentsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_commit_comments = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_commit_comments[org_name] = commit_comments_analyzer.analyze_org_commit_comments(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["commit_comments"] = org_commit_comments
                else:
                    try:
                        org_commit_comments = commit_comments_analyzer.analyze_org_commit_comments(company, max_repos=15)
                        resources_data["commit_comments"] = {company: org_commit_comments}
                    except Exception:
                        resources_data["commit_comments"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze commit comments: {str(e)}", err=True)
                resources_data["commit_comments"] = {}
            
            # PR Files Analysis
            click.echo("  - Analyzing PR files changed...", err=True)
            pr_files_analyzer = PRFilesAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_pr_files = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_pr_files[org_name] = pr_files_analyzer.analyze_org_pr_files(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["pr_files"] = org_pr_files
                else:
                    try:
                        org_pr_files = pr_files_analyzer.analyze_org_pr_files(company, max_repos=15)
                        resources_data["pr_files"] = {company: org_pr_files}
                    except Exception:
                        resources_data["pr_files"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze PR files: {str(e)}", err=True)
                resources_data["pr_files"] = {}
            
            # Issue Events Analysis
            click.echo("  - Analyzing issue events...", err=True)
            issue_events_analyzer = IssueEventsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_issue_events = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_issue_events[org_name] = issue_events_analyzer.analyze_org_issue_events(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["issue_events"] = org_issue_events
                else:
                    try:
                        org_issue_events = issue_events_analyzer.analyze_org_issue_events(company, max_repos=15)
                        resources_data["issue_events"] = {company: org_issue_events}
                    except Exception:
                        resources_data["issue_events"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze issue events: {str(e)}", err=True)
                resources_data["issue_events"] = {}
            
            # Contributors Analysis
            click.echo("  - Analyzing contributors...", err=True)
            contributors_analyzer = ContributorsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_contributors = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_contributors[org_name] = contributors_analyzer.analyze_org_contributors(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["contributors"] = org_contributors
                else:
                    try:
                        org_contributors = contributors_analyzer.analyze_org_contributors(company, max_repos=15)
                        resources_data["contributors"] = {company: org_contributors}
                    except Exception:
                        resources_data["contributors"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze contributors: {str(e)}", err=True)
                resources_data["contributors"] = {}
            
            # Stargazers/Watchers Analysis
            click.echo("  - Analyzing stargazers and watchers...", err=True)
            stargazers_watchers_analyzer = StargazersWatchersAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_stargazers_watchers = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_stargazers_watchers[org_name] = stargazers_watchers_analyzer.analyze_org_stargazers_watchers(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["stargazers_watchers"] = org_stargazers_watchers
                else:
                    try:
                        org_stargazers_watchers = stargazers_watchers_analyzer.analyze_org_stargazers_watchers(company, max_repos=15)
                        resources_data["stargazers_watchers"] = {company: org_stargazers_watchers}
                    except Exception:
                        resources_data["stargazers_watchers"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze stargazers/watchers: {str(e)}", err=True)
                resources_data["stargazers_watchers"] = {}
            
            # Fork Network Analysis
            click.echo("  - Analyzing fork network...", err=True)
            fork_network_analyzer = ForkNetworkAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_forks = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_forks[org_name] = fork_network_analyzer.analyze_org_forks(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["fork_network"] = org_forks
                else:
                    try:
                        org_forks = fork_network_analyzer.analyze_org_forks(company, max_repos=15)
                        resources_data["fork_network"] = {company: org_forks}
                    except Exception:
                        resources_data["fork_network"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze fork network: {str(e)}", err=True)
                resources_data["fork_network"] = {}
            
            # Release Assets Analysis
            click.echo("  - Analyzing release assets...", err=True)
            release_assets_analyzer = ReleaseAssetsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_release_assets = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_release_assets[org_name] = release_assets_analyzer.analyze_org_release_assets(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["release_assets"] = org_release_assets
                else:
                    try:
                        org_release_assets = release_assets_analyzer.analyze_org_release_assets(company, max_repos=15)
                        resources_data["release_assets"] = {company: org_release_assets}
                    except Exception:
                        resources_data["release_assets"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze release assets: {str(e)}", err=True)
                resources_data["release_assets"] = {}
            
            # Repository Invitations Analysis
            click.echo("  - Analyzing repository invitations...", err=True)
            invitations_analyzer = RepositoryInvitationsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_invitations = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_invitations[org_name] = invitations_analyzer.analyze_org_repo_invitations(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["repository_invitations"] = org_invitations
                else:
                    try:
                        org_invitations = invitations_analyzer.analyze_org_repo_invitations(company, max_repos=15)
                        resources_data["repository_invitations"] = {company: org_invitations}
                    except Exception:
                        resources_data["repository_invitations"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze invitations: {str(e)}", err=True)
                resources_data["repository_invitations"] = {}
            
            # Repository Transfer Analysis
            click.echo("  - Analyzing repository transfers...", err=True)
            transfer_analyzer = RepositoryTransferAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_transfers = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_transfers[org_name] = transfer_analyzer.analyze_org_repo_transfers(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["repository_transfers"] = org_transfers
                else:
                    try:
                        org_transfers = transfer_analyzer.analyze_org_repo_transfers(company, max_repos=15)
                        resources_data["repository_transfers"] = {company: org_transfers}
                    except Exception:
                        resources_data["repository_transfers"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze transfers: {str(e)}", err=True)
                resources_data["repository_transfers"] = {}
            
            # Workflow Run Logs Analysis
            click.echo("  - Analyzing workflow run logs...", err=True)
            workflow_logs_analyzer = WorkflowRunLogsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_workflow_logs = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_workflow_logs[org_name] = workflow_logs_analyzer.analyze_org_workflow_logs(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["workflow_run_logs"] = org_workflow_logs
                else:
                    try:
                        org_workflow_logs = workflow_logs_analyzer.analyze_org_workflow_logs(company, max_repos=15)
                        resources_data["workflow_run_logs"] = {company: org_workflow_logs}
                    except Exception:
                        resources_data["workflow_run_logs"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze workflow logs: {str(e)}", err=True)
                resources_data["workflow_run_logs"] = {}
            
            # Artifact Details Analysis
            click.echo("  - Analyzing artifact details...", err=True)
            artifact_details_analyzer = ArtifactDetailsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_artifacts = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_artifacts[org_name] = artifact_details_analyzer.analyze_org_artifacts(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["artifact_details"] = org_artifacts
                else:
                    try:
                        org_artifacts = artifact_details_analyzer.analyze_org_artifacts(company, max_repos=15)
                        resources_data["artifact_details"] = {company: org_artifacts}
                    except Exception:
                        resources_data["artifact_details"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze artifact details: {str(e)}", err=True)
                resources_data["artifact_details"] = {}
            
            # Secret Scanning Alerts Analysis
            click.echo("  - Analyzing secret scanning alerts...", err=True)
            secret_alerts_analyzer = SecretScanningAlertsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_secret_alerts = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_secret_alerts[org_name] = secret_alerts_analyzer.analyze_org_secret_alerts(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["secret_scanning_alerts"] = org_secret_alerts
                else:
                    try:
                        org_secret_alerts = secret_alerts_analyzer.analyze_org_secret_alerts(company, max_repos=15)
                        resources_data["secret_scanning_alerts"] = {company: org_secret_alerts}
                    except Exception:
                        resources_data["secret_scanning_alerts"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze secret scanning alerts: {str(e)}", err=True)
                resources_data["secret_scanning_alerts"] = {}
            
            # Code Scanning Alerts Analysis
            click.echo("  - Analyzing code scanning alerts...", err=True)
            code_alerts_analyzer = CodeScanningAlertsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_code_alerts = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_code_alerts[org_name] = code_alerts_analyzer.analyze_org_code_alerts(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["code_scanning_alerts"] = org_code_alerts
                else:
                    try:
                        org_code_alerts = code_alerts_analyzer.analyze_org_code_alerts(company, max_repos=15)
                        resources_data["code_scanning_alerts"] = {company: org_code_alerts}
                    except Exception:
                        resources_data["code_scanning_alerts"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze code scanning alerts: {str(e)}", err=True)
                resources_data["code_scanning_alerts"] = {}
            
            # Repository Topics Analysis
            click.echo("  - Analyzing repository topics...", err=True)
            topics_analyzer = RepositoryTopicsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_topics = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_topics[org_name] = topics_analyzer.analyze_org_topics(org_name, max_repos=20)
                            except Exception:
                                pass
                    resources_data["repository_topics"] = org_topics
                else:
                    try:
                        org_topics = topics_analyzer.analyze_org_topics(company, max_repos=30)
                        resources_data["repository_topics"] = {company: org_topics}
                    except Exception:
                        resources_data["repository_topics"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze repository topics: {str(e)}", err=True)
                resources_data["repository_topics"] = {}
            
            # Repository Languages Analysis
            click.echo("  - Analyzing repository languages...", err=True)
            languages_analyzer = RepositoryLanguagesAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_languages = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_languages[org_name] = languages_analyzer.analyze_org_languages(org_name, max_repos=20)
                            except Exception:
                                pass
                    resources_data["repository_languages"] = org_languages
                else:
                    try:
                        org_languages = languages_analyzer.analyze_org_languages(company, max_repos=30)
                        resources_data["repository_languages"] = {company: org_languages}
                    except Exception:
                        resources_data["repository_languages"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze repository languages: {str(e)}", err=True)
                resources_data["repository_languages"] = {}
            
            # Enterprise Settings Analysis
            if enterprise_slug:
                click.echo("  - Analyzing enterprise settings...", err=True)
                enterprise_settings_analyzer = EnterpriseSettingsAnalyzer(api_client)
                try:
                    enterprise_settings = enterprise_settings_analyzer.analyze_enterprise_settings(enterprise_slug)
                    resources_data["enterprise_settings"] = enterprise_settings
                except Exception as e:
                    click.echo(f"  - Could not analyze enterprise settings: {str(e)}", err=True)
                    resources_data["enterprise_settings"] = {}
            
            # Repository Statistics Analysis
            click.echo("  - Analyzing repository statistics...", err=True)
            statistics_analyzer = RepositoryStatisticsAnalyzer(api_client)
            try:
                if all_orgs and enumeration_data and "organizations" in enumeration_data:
                    org_statistics = {}
                    for org in enumeration_data.get("organizations", [])[:3]:  # Limit to first 3 orgs
                        org_name = org.get("organization_name", "")
                        if org_name:
                            try:
                                org_statistics[org_name] = statistics_analyzer.analyze_org_statistics(org_name, max_repos=10)
                            except Exception:
                                pass
                    resources_data["repository_statistics"] = org_statistics
                else:
                    try:
                        org_statistics = statistics_analyzer.analyze_org_statistics(company, max_repos=15)
                        resources_data["repository_statistics"] = {company: org_statistics}
                    except Exception:
                        resources_data["repository_statistics"] = {}
            except Exception as e:
                click.echo(f"  - Could not analyze repository statistics: {str(e)}", err=True)
                resources_data["repository_statistics"] = {}
            
            # Run test suite
            if enterprise_slug:
                click.echo("  - Running test suite...", err=True)
                test_suite = TestSuite(api_client, enterprise_slug)
                test_results_data = test_suite.run_all_tests()
            
            # Initialize new feature data
            drift_data = None
            compliance_data = None
            rate_limit_data = None
            
            # Permission drift detection
            if detect_drift:
                click.echo("  - Detecting permission drift...", err=True)
                drift_detector = PermissionDriftDetector(storage_dir=os.path.join(output_dir, ".permission_history"))
                api_key_id = user_info.get('login', 'unknown')
                drift_data = drift_detector.detect_drift(api_key_id, permissions_data)
                if drift_data.get("has_changes"):
                    click.echo(f"  ⚠️  Permission changes detected: {drift_data.get('change_count', 0)} changes", err=True)
                else:
                    click.echo("  ✓ No permission changes detected", err=True)
            
            # Compliance checking
            if check_compliance:
                click.echo("  - Checking compliance...", err=True)
                compliance_checker = ComplianceChecker()
                frameworks = []
                if "all" in check_compliance:
                    frameworks = list(ComplianceFramework)
                else:
                    # Convert tuple to list and filter valid framework names
                    check_compliance_list = list(check_compliance) if isinstance(check_compliance, tuple) else [check_compliance]
                    frameworks = []
                    for f in check_compliance_list:
                        if isinstance(f, str) and f in ComplianceFramework.__members__:
                            frameworks.append(ComplianceFramework[f])
                
                if frameworks:
                    compliance_data = compliance_checker.check_compliance(
                        permissions_data, resources_data, frameworks
                    )
                    overall = compliance_data.get("overall_compliant", False)
                    click.echo(f"  {'✓' if overall else '⚠️'} Overall compliance: {'COMPLIANT' if overall else 'NON-COMPLIANT'}", err=True)
            
            # Rate limit monitoring (final check)
            if rate_limit_monitor:
                rate_limit_data = rate_limit_monitor.check_rate_limit()
                rate_limit_stats = rate_limit_monitor.get_statistics()
            
            # Generate remediation suggestions
            click.echo("  - Generating remediation suggestions...", err=True)
            remediation_engine = RemediationEngine()
            
            # Calculate risk assessment for remediation engine
            risk_assessment = None
            if permissions_data or resources_data:
                from .risk_scorer import RiskScorer
                risk_scorer = RiskScorer()
                permissions_assessment = risk_scorer.assess_permissions(permissions_data) if permissions_data else {}
                resources_assessment = risk_scorer.assess_resources(resources_data) if resources_data else {}
                if permissions_assessment and resources_assessment:
                    risk_assessment = {
                        "overall_risk": risk_scorer.calculate_overall_risk(permissions_assessment, resources_assessment),
                        "permissions_assessment": permissions_assessment,
                        "resources_assessment": resources_assessment
                    }
            
            remediation_data = remediation_engine.generate_remediations(
                permissions_data=permissions_data,
                resources_data=resources_data,
                compliance_data=compliance_data,
                drift_data=drift_data,
                runner_data=enterprise_runner_data,
                risk_assessment=risk_assessment
            )
            
            total_remediations = remediation_data.get("summary", {}).get("total", 0)
            click.echo(f"  ✓ Generated {total_remediations} remediation suggestions", err=True)
            
            # Generate report
            click.echo("  - Generating HTML report...", err=True)
            report_gen = HTMLReportGenerator()
            report_file = generate_report if generate_report.endswith('.html') else f"{generate_report}.html"
            if output_dir != ".":
                os.makedirs(output_dir, exist_ok=True)
                report_file = os.path.join(output_dir, report_file)
            
            # Generate report with optional export formats
            export_formats = list(export_format) if export_format else ["html"]
            
            if len(export_formats) > 1 or (len(export_formats) == 1 and export_formats[0] != "html"):
                # Use multi-format export
                exported_files = report_gen.generate_report_with_export(
                    permissions_data=permissions_data,
                    enumeration_data=enumeration_data,
                    runner_data=enterprise_runner_data,
                    resources_data=resources_data,
                    test_results=test_results_data,
                    output_file=report_file,
                    export_formats=export_formats
                )
                click.echo(f"\nReport exported to:", err=True)
                for fmt, file_path in exported_files.items():
                    click.echo(f"  {fmt.upper()}: {file_path}", err=True)
            else:
                # Standard HTML report
                report_gen.generate_report(
                    permissions_data=permissions_data,
                    enumeration_data=enumeration_data,
                    runner_data=enterprise_runner_data,
                    resources_data=resources_data,
                    test_results=test_results_data,
                    output_file=report_file,
                    drift_data=drift_data,
                    compliance_data=compliance_data,
                    rate_limit_data=rate_limit_data,
                    remediation_data=remediation_data
                )
                click.echo(f"\n✓ HTML security report generated: {report_file}", err=True)
                click.echo(f"  Report contains actual findings from your API key analysis.", err=True)
            return
        
        # Determine what to do for original functionality
        do_validate = not enumerate or validate
        do_enumerate = not validate or enumerate
        
        if not do_validate and not do_enumerate:
            click.echo("Error: Must specify either --validate or --enumerate", err=True)
            sys.exit(1)
        
        formatter = OutputFormatter()
        
        formatter = OutputFormatter()
        permissions_data = None
        enumeration_data = None
        enterprise_runner_data = None
        
        # Validate permissions
        if do_validate:
            click.echo("Validating permissions...", err=True)
            permission_checker = PermissionChecker(api_client, enterprise_slug=enterprise_slug)
            permissions_data = permission_checker.validate_all_permissions(
                org_name=company,
                enterprise_slug=enterprise_slug,
            )
        
        # Enumerate company info
        if do_enumerate:
            click.echo("Enumerating company information...", err=True)
            enumerator = CompanyEnumerator(api_client)
            
            if all_orgs:
                enumeration_data = enumerator.enumerate_all_accessible_orgs()
            else:
                enumeration_data = enumerator.enumerate_organization(company)

        if enterprise_slug:
            click.echo(f"Collecting enterprise runner telemetry for '{enterprise_slug}'...", err=True)
            inspector = EnterpriseRunnerInspector(api_client, enterprise_slug)
            enterprise_runner_data = inspector.fetch_runners()
        
        # Prepare combined data for file saving
        combined_data = {}
        if permissions_data:
            combined_data["permissions"] = permissions_data
        if enumeration_data:
            combined_data["enumeration"] = enumeration_data
        if enterprise_runner_data:
            combined_data["enterprise_runners"] = enterprise_runner_data
        
        # Save to files if requested
        saved_files = []
        if save_json is not None or save_csv is not None:
            # Ensure output directory exists
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
        
        if save_json is not None:
            json_filename = save_json if save_json else None
            if json_filename and not json_filename.endswith('.json'):
                json_filename += '.json'
            if output_dir != "." and json_filename:
                json_filename = os.path.join(output_dir, json_filename)
            elif output_dir != "." and not json_filename:
                # Auto-generate filename in output directory
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                json_filename = os.path.join(output_dir, f"github_validation_{timestamp}.json")
            
            saved_file = formatter.save_to_file(combined_data, json_filename, "json")
            saved_files.append(saved_file)
            click.echo(f"JSON results saved to: {saved_file}", err=True)
        
        if save_csv is not None:
            csv_filename = save_csv if save_csv else None
            if csv_filename and not csv_filename.endswith('.csv'):
                csv_filename += '.csv'
            if output_dir != "." and csv_filename:
                csv_filename = os.path.join(output_dir, csv_filename)
            elif output_dir != "." and not csv_filename:
                # Auto-generate filename in output directory
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                csv_filename = os.path.join(output_dir, f"github_validation_{timestamp}.csv")
            
            saved_file = formatter.export_to_csv(
                permissions_data,
                enumeration_data,
                csv_filename,
                enterprise_runner_data,
            )
            saved_files.append(saved_file)
            click.echo(f"CSV results saved to: {saved_file}", err=True)
        
        # Output results
        if output in ["json", "both"]:
            json_output = formatter.format_combined_json(
                permissions_data,
                enumeration_data,
                enterprise_runner_data,
            )
            if output == "json":
                click.echo(json_output)
            else:
                # Print JSON if both formats requested
                click.echo(json_output)
        
        if output in ["console", "both"]:
            formatter.format_combined_console(permissions_data, enumeration_data, enterprise_runner_data)
        
    except KeyboardInterrupt:
        click.echo("\nOperation cancelled by user", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

