"""
Repository Settings Deep Dive Module

Provides comprehensive analysis of repository settings including:
- Visibility and access settings
- Merge settings and strategies
- Security policy enforcement
- Vulnerability alerts settings
- Dependency graph settings
- Branch protection settings
- Feature flags and capabilities
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class RepositorySettingsAnalyzer:
    """Analyzes repository settings in detail."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_settings(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze repository settings in detail.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with detailed repository settings
        """
        settings_data = {
            "repository": repo_full_name,
            "basic_settings": {},
            "merge_settings": {},
            "security_settings": {},
            "feature_settings": {},
            "vulnerability_alerts": {},
            "dependency_graph": {},
            "branch_protection_summary": {},
            "errors": []
        }
        
        try:
            # Get repository basic info
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            if repo_info:
                settings_data["basic_settings"] = {
                    "private": repo_info.get("private", False),
                    "visibility": repo_info.get("visibility", ""),
                    "archived": repo_info.get("archived", False),
                    "disabled": repo_info.get("disabled", False),
                    "default_branch": repo_info.get("default_branch", ""),
                    "allow_squash_merge": repo_info.get("allow_squash_merge", True),
                    "allow_merge_commit": repo_info.get("allow_merge_commit", True),
                    "allow_rebase_merge": repo_info.get("allow_rebase_merge", True),
                    "allow_auto_merge": repo_info.get("allow_auto_merge", False),
                    "delete_branch_on_merge": repo_info.get("delete_branch_on_merge", False),
                    "allow_update_branch": repo_info.get("allow_update_branch", False),
                    "has_issues": repo_info.get("has_issues", True),
                    "has_projects": repo_info.get("has_projects", True),
                    "has_wiki": repo_info.get("has_wiki", True),
                    "has_pages": repo_info.get("has_pages", False),
                    "has_downloads": repo_info.get("has_downloads", True),
                    "allow_forking": repo_info.get("allow_forking", True),
                    "is_template": repo_info.get("is_template", False),
                    "web_commit_signoff_required": repo_info.get("web_commit_signoff_required", False)
                }
                
                settings_data["merge_settings"] = {
                    "allow_squash_merge": repo_info.get("allow_squash_merge", True),
                    "allow_merge_commit": repo_info.get("allow_merge_commit", True),
                    "allow_rebase_merge": repo_info.get("allow_rebase_merge", True),
                    "allow_auto_merge": repo_info.get("allow_auto_merge", False),
                    "delete_branch_on_merge": repo_info.get("delete_branch_on_merge", False),
                    "allow_update_branch": repo_info.get("allow_update_branch", False)
                }
                
                settings_data["feature_settings"] = {
                    "has_issues": repo_info.get("has_issues", True),
                    "has_projects": repo_info.get("has_projects", True),
                    "has_wiki": repo_info.get("has_wiki", True),
                    "has_pages": repo_info.get("has_pages", False),
                    "has_downloads": repo_info.get("has_downloads", True),
                    "allow_forking": repo_info.get("allow_forking", True),
                    "is_template": repo_info.get("is_template", False)
                }
        except Exception as e:
            settings_data["errors"].append(f"Failed to get repository info: {str(e)}")
        
        # Get vulnerability alerts settings
        try:
            vuln_alerts = self.api_client.get(f"/repos/{repo_full_name}/vulnerability-alerts")
            settings_data["vulnerability_alerts"] = {
                "enabled": vuln_alerts is not None
            }
        except Exception:
            settings_data["vulnerability_alerts"] = {"enabled": False}
        
        # Get dependency graph settings
        try:
            dep_graph = self.api_client.get(f"/repos/{repo_full_name}/dependency-graph/status")
            if dep_graph:
                settings_data["dependency_graph"] = {
                    "enabled": dep_graph.get("enabled", False)
                }
        except Exception:
            settings_data["dependency_graph"] = {"enabled": False}
        
        # Get security and analysis settings
        try:
            security_settings = self.api_client.get(f"/repos/{repo_full_name}")
            if security_settings:
                settings_data["security_settings"] = {
                    "private": security_settings.get("private", False),
                    "archived": security_settings.get("archived", False),
                    "disabled": security_settings.get("disabled", False),
                    "web_commit_signoff_required": security_settings.get("web_commit_signoff_required", False)
                }
        except Exception:
            pass
        
        # Get branch protection summary (check default branch)
        try:
            default_branch = settings_data["basic_settings"].get("default_branch", "main")
            protection = self.api_client.get(f"/repos/{repo_full_name}/branches/{default_branch}/protection")
            if protection:
                settings_data["branch_protection_summary"] = {
                    "protected": True,
                    "required_status_checks": protection.get("required_status_checks", {}).get("strict", False) if protection.get("required_status_checks") else False,
                    "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False) if protection.get("enforce_admins") else False,
                    "required_pull_request_reviews": protection.get("required_pull_request_reviews", {}).get("required_approving_review_count", 0) if protection.get("required_pull_request_reviews") else 0,
                    "allow_force_pushes": protection.get("allow_force_pushes", {}).get("enabled", False) if protection.get("allow_force_pushes") else False,
                    "allow_deletions": protection.get("allow_deletions", {}).get("enabled", False) if protection.get("allow_deletions") else False
                }
            else:
                settings_data["branch_protection_summary"] = {"protected": False}
        except Exception:
            settings_data["branch_protection_summary"] = {"protected": False}
        
        return settings_data
    
    def analyze_org_repo_settings(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze repository settings across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide repository settings analysis
        """
        org_settings = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "private_repos": 0,
                "public_repos": 0,
                "archived_repos": 0,
                "repos_with_vulnerability_alerts": 0,
                "repos_with_dependency_graph": 0,
                "repos_with_branch_protection": 0,
                "repos_allow_forking": 0,
                "repos_allow_auto_merge": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_settings = self.analyze_repo_settings(repo_full_name)
                        org_settings["repositories"][repo_full_name] = repo_settings
                        
                        # Update summary
                        org_settings["summary"]["total_repos_analyzed"] += 1
                        if repo_settings["basic_settings"].get("private", False):
                            org_settings["summary"]["private_repos"] += 1
                        else:
                            org_settings["summary"]["public_repos"] += 1
                        
                        if repo_settings["basic_settings"].get("archived", False):
                            org_settings["summary"]["archived_repos"] += 1
                        
                        if repo_settings["vulnerability_alerts"].get("enabled", False):
                            org_settings["summary"]["repos_with_vulnerability_alerts"] += 1
                        
                        if repo_settings["dependency_graph"].get("enabled", False):
                            org_settings["summary"]["repos_with_dependency_graph"] += 1
                        
                        if repo_settings["branch_protection_summary"].get("protected", False):
                            org_settings["summary"]["repos_with_branch_protection"] += 1
                        
                        if repo_settings["feature_settings"].get("allow_forking", True):
                            org_settings["summary"]["repos_allow_forking"] += 1
                        
                        if repo_settings["merge_settings"].get("allow_auto_merge", False):
                            org_settings["summary"]["repos_allow_auto_merge"] += 1
                    except Exception as e:
                        org_settings["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_settings["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_settings

