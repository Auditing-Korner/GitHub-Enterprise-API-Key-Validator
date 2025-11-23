"""
GitHub Enterprise API Key Validator

A comprehensive framework to validate GitHub Enterprise API key permissions
and enumerate all accessible company information.
"""

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
from .risk_scorer import RiskScorer, RiskLevel
from .rate_limit_monitor import RateLimitMonitor
from .permission_drift_detector import PermissionDriftDetector
from .compliance_checker import ComplianceChecker, ComplianceFramework
from .remediation_engine import RemediationEngine, RemediationPriority, RemediationCategory

__version__ = "1.0.0"
__all__ = [
    "GitHubValidator",
    "GitHubAPIClient",
    "PermissionChecker",
    "CompanyEnumerator",
    "OutputFormatter",
    "EnterpriseRunnerInspector",
    "RunnerOperations",
    "ResourceLister",
    "TestSuite",
    "HTMLReportGenerator",
    "ActionsDetector",
    "SecurityAnalyzer",
    "RepositoryAnalyzer",
    "CodespacesDetector",
    "IssuesPRsAnalyzer",
    "ContentAnalyzer",
    "PackagesAnalyzer",
    "TokenMetadataAnalyzer",
    "RepositoryInsightsAnalyzer",
    "EnterpriseAuditLogAnalyzer",
    "GistsAnalyzer",
    "UserActivityAnalyzer",
    "DiscussionsAnalyzer",
    "CommitAnalyzer",
    "BranchAnalyzer",
    "TeamAnalyzer",
    "NotificationAnalyzer",
    "WebhookAnalyzer",
    "OAuthAppAnalyzer",
    "GitHubAppAnalyzer",
    "DependencyAnalyzer",
    "PRReviewsAnalyzer",
    "RepositorySettingsAnalyzer",
    "OrganizationSettingsAnalyzer",
    "EnvironmentSecretsAnalyzer",
    "MilestonesAnalyzer",
    "LabelsAnalyzer",
    "ProjectsAnalyzer",
    "ReactionsAnalyzer",
    "CommitCommentsAnalyzer",
    "PRFilesAnalyzer",
    "IssueEventsAnalyzer",
    "ContributorsAnalyzer",
    "StargazersWatchersAnalyzer",
    "ForkNetworkAnalyzer",
    "ReleaseAssetsAnalyzer",
    "RepositoryInvitationsAnalyzer",
    "RepositoryTransferAnalyzer",
    "WorkflowRunLogsAnalyzer",
    "ArtifactDetailsAnalyzer",
    "SecretScanningAlertsAnalyzer",
    "CodeScanningAlertsAnalyzer",
    "RepositoryTopicsAnalyzer",
    "RepositoryLanguagesAnalyzer",
    "EnterpriseSettingsAnalyzer",
    "RepositoryStatisticsAnalyzer",
    "RiskScorer",
    "RiskLevel",
    "RateLimitMonitor",
    "PermissionDriftDetector",
    "ComplianceChecker",
    "ComplianceFramework",
    "RemediationEngine",
    "RemediationPriority",
    "RemediationCategory",
]


class GitHubValidator:
    """
    Main class for validating GitHub Enterprise API keys and enumerating company information.
    
    This class provides a high-level interface for both permission validation
    and company enumeration.
    
    Example:
        >>> from github_validator import GitHubValidator
        >>> validator = GitHubValidator(api_key="your-key", company_name="company")
        >>> permissions = validator.validate_permissions()
        >>> company_info = validator.enumerate_company()
    """
    
    def __init__(self, api_key: str, company_name: str = None, base_url: str = None, enterprise_slug: str = None):
        """
        Initialize GitHub Validator.
        
        Args:
            api_key: GitHub Enterprise API key/token
            company_name: Optional company/organization name
            base_url: Optional GitHub Enterprise base URL (defaults to github.com)
        """
        self.api_client = GitHubAPIClient(api_key, base_url)
        self.company_name = company_name
        self.enterprise_slug = enterprise_slug
        self.permission_checker = PermissionChecker(self.api_client, enterprise_slug=enterprise_slug)
        self.enumerator = CompanyEnumerator(self.api_client)
        self.formatter = OutputFormatter()
    
    def validate_permissions(self, org_name: str = None, enterprise_slug: str = None) -> dict:
        """
        Validate all permissions for the API key.
        
        Args:
            org_name: Optional organization name to test org-specific permissions.
                     If not provided, uses the company_name from initialization.
        
        Returns:
            Dictionary containing permission validation results
        """
        target_org = org_name or self.company_name
        return self.permission_checker.validate_all_permissions(
            org_name=target_org,
            enterprise_slug=enterprise_slug or self.enterprise_slug,
        )
    
    def enumerate_company(self, org_name: str = None) -> dict:
        """
        Enumerate all accessible information for a company/organization.
        
        Args:
            org_name: Optional organization name to enumerate.
                     If not provided, uses the company_name from initialization.
        
        Returns:
            Dictionary containing all accessible company information
        """
        target_org = org_name or self.company_name
        if not target_org:
            raise ValueError("Organization name must be provided either in constructor or as parameter")
        
        return self.enumerator.enumerate_organization(target_org)
    
    def enumerate_all_orgs(self) -> dict:
        """
        Enumerate all organizations accessible by the API key.
        
        Returns:
            Dictionary containing all accessible organizations and their data
        """
        return self.enumerator.enumerate_all_accessible_orgs()
    
    def validate_and_enumerate(self, org_name: str = None) -> dict:
        """
        Validate permissions and enumerate company information in one call.
        
        Args:
            org_name: Optional organization name.
                     If not provided, uses the company_name from initialization.
        
        Returns:
            Dictionary containing both permission validation and enumeration results
        """
        target_org = org_name or self.company_name
        
        permissions = self.validate_permissions(org_name=target_org)
        enumeration = self.enumerate_company(org_name=target_org) if target_org else None
        
        return {
            "permissions": permissions,
            "enumeration": enumeration
        }
    
    def get_permissions_json(self, org_name: str = None) -> str:
        """
        Get permission validation results as JSON string.
        
        Args:
            org_name: Optional organization name
        
        Returns:
            JSON string of permission validation results
        """
        permissions = self.validate_permissions(org_name=org_name)
        return self.formatter.format_permissions_json(permissions)
    
    def get_enumeration_json(self, org_name: str = None) -> str:
        """
        Get enumeration results as JSON string.
        
        Args:
            org_name: Optional organization name
        
        Returns:
            JSON string of enumeration results
        """
        enumeration = self.enumerate_company(org_name=org_name) if (org_name or self.company_name) else None
        if not enumeration:
            raise ValueError("Organization name must be provided")
        return self.formatter.format_enumeration_json(enumeration)
    
    def print_permissions_console(self, org_name: str = None) -> None:
        """
        Print permission validation results to console.
        
        Args:
            org_name: Optional organization name
        """
        permissions = self.validate_permissions(org_name=org_name)

    def inspect_enterprise_runners(self, enterprise_slug: str = None) -> dict:
        """
        Collect enterprise-level runner information.

        Args:
            enterprise_slug: Optional enterprise slug override.

        Returns:
            Runner telemetry dictionary.
        """
        slug = enterprise_slug or self.enterprise_slug
        if not slug:
            raise ValueError("Enterprise slug must be provided to inspect runners")
        inspector = EnterpriseRunnerInspector(self.api_client, slug)
        return inspector.fetch_runners()
    
    def print_enumeration_console(self, org_name: str = None) -> None:
        """
        Print enumeration results to console.
        
        Args:
            org_name: Optional organization name
        """
        enumeration = self.enumerate_company(org_name=org_name) if (org_name or self.company_name) else None
        if not enumeration:
            raise ValueError("Organization name must be provided")
        self.formatter.format_enumeration_console(enumeration)
    
    def test_authentication(self) -> dict:
        """
        Test if the API key is valid.
        
        Returns:
            User information if authentication succeeds, None otherwise
        """
        return self.api_client.test_authentication()

