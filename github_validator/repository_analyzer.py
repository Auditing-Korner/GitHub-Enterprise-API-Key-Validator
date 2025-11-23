"""
Repository Analysis Module

Provides comprehensive repository analysis including:
- Collaborators and permissions
- Repository settings
- Deployments and environments
- Releases and tags
- Fork relationships
- Deployment keys
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class RepositoryAnalyzer:
    """Analyzes repository-level resources and settings."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repository(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Comprehensive analysis of a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with repository analysis
        """
        repo_analysis = {
            "repository": repo_full_name,
            "collaborators": [],
            "deployments": [],
            "environments": [],
            "releases": [],
            "tags": [],
            "forks": [],
            "deploy_keys": [],
            "settings": {},
            "errors": []
        }
        
        # Get collaborators
        try:
            collaborators = self.api_client.get_paginated(f"/repos/{repo_full_name}/collaborators")
            repo_analysis["collaborators"] = [
                {
                    "login": c.get("login", ""),
                    "id": c.get("id", ""),
                    "permissions": c.get("permissions", {}),
                    "role_name": c.get("role_name", "")
                }
                for c in collaborators
            ]
        except Exception as e:
            repo_analysis["errors"].append(f"Collaborators: {str(e)}")
        
        # Get deployments
        try:
            deployments = self.api_client.get_paginated(f"/repos/{repo_full_name}/deployments")
            repo_analysis["deployments"] = [
                {
                    "id": d.get("id", ""),
                    "ref": d.get("ref", ""),
                    "sha": d.get("sha", ""),
                    "task": d.get("task", ""),
                    "environment": d.get("environment", ""),
                    "creator": {
                        "login": d.get("creator", {}).get("login", ""),
                        "type": d.get("creator", {}).get("type", "")
                    } if d.get("creator") else {},
                    "created_at": d.get("created_at", ""),
                    "updated_at": d.get("updated_at", "")
                }
                for d in deployments[:50]  # Limit for performance
            ]
        except Exception as e:
            repo_analysis["errors"].append(f"Deployments: {str(e)}")
        
        # Get environments
        try:
            environments = self.api_client.get_paginated(f"/repos/{repo_full_name}/environments")
            repo_analysis["environments"] = [
                {
                    "id": e.get("id", ""),
                    "name": e.get("name", ""),
                    "url": e.get("url", ""),
                    "html_url": e.get("html_url", ""),
                    "protection_rules": e.get("protection_rules", []),
                    "deployment_branch_policy": e.get("deployment_branch_policy", {}),
                    "secrets": len(e.get("secrets", [])) if isinstance(e.get("secrets"), list) else 0,
                    "variables": len(e.get("variables", [])) if isinstance(e.get("variables"), list) else 0
                }
                for e in environments
            ]
        except Exception as e:
            repo_analysis["errors"].append(f"Environments: {str(e)}")
        
        # Get releases
        try:
            releases = self.api_client.get_paginated(f"/repos/{repo_full_name}/releases")
            repo_analysis["releases"] = [
                {
                    "id": r.get("id", ""),
                    "tag_name": r.get("tag_name", ""),
                    "name": r.get("name", ""),
                    "draft": r.get("draft", False),
                    "prerelease": r.get("prerelease", False),
                    "author": {
                        "login": r.get("author", {}).get("login", ""),
                        "type": r.get("author", {}).get("type", "")
                    } if r.get("author") else {},
                    "created_at": r.get("created_at", ""),
                    "published_at": r.get("published_at", ""),
                    "assets_count": len(r.get("assets", []))
                }
                for r in releases[:30]  # Limit for performance
            ]
        except Exception as e:
            repo_analysis["errors"].append(f"Releases: {str(e)}")
        
        # Get tags
        try:
            tags = self.api_client.get_paginated(f"/repos/{repo_full_name}/tags")
            repo_analysis["tags"] = [
                {
                    "name": t.get("name", ""),
                    "commit": {
                        "sha": t.get("commit", {}).get("sha", ""),
                        "url": t.get("commit", {}).get("url", "")
                    } if t.get("commit") else {},
                    "zipball_url": t.get("zipball_url", ""),
                    "tarball_url": t.get("tarball_url", "")
                }
                for t in tags[:50]  # Limit for performance
            ]
        except Exception as e:
            repo_analysis["errors"].append(f"Tags: {str(e)}")
        
        # Get forks
        try:
            forks = self.api_client.get_paginated(f"/repos/{repo_full_name}/forks")
            repo_analysis["forks"] = [
                {
                    "id": f.get("id", ""),
                    "full_name": f.get("full_name", ""),
                    "owner": {
                        "login": f.get("owner", {}).get("login", ""),
                        "type": f.get("owner", {}).get("type", "")
                    } if f.get("owner") else {},
                    "private": f.get("private", False),
                    "fork": f.get("fork", False),
                    "created_at": f.get("created_at", "")
                }
                for f in forks[:30]  # Limit for performance
            ]
        except Exception as e:
            repo_analysis["errors"].append(f"Forks: {str(e)}")
        
        # Get deploy keys
        try:
            deploy_keys = self.api_client.get_paginated(f"/repos/{repo_full_name}/keys")
            repo_analysis["deploy_keys"] = [
                {
                    "id": k.get("id", ""),
                    "key": k.get("key", ""),
                    "title": k.get("title", ""),
                    "read_only": k.get("read_only", True),
                    "verified": k.get("verified", False),
                    "created_at": k.get("created_at", "")
                }
                for k in deploy_keys
            ]
        except Exception as e:
            repo_analysis["errors"].append(f"Deploy keys: {str(e)}")
        
        # Get repository settings
        try:
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            if repo_info:
                repo_analysis["settings"] = {
                    "private": repo_info.get("private", False),
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
                    "is_template": repo_info.get("is_template", False)
                }
        except Exception as e:
            repo_analysis["errors"].append(f"Settings: {str(e)}")
        
        return repo_analysis
    
    def analyze_org_repositories(self, org_name: str, max_repos: int = 50) -> Dict[str, Any]:
        """
        Analyze repositories in an organization.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization repository analysis
        """
        org_repos_analysis = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos": 0,
                "total_collaborators": 0,
                "total_deployments": 0,
                "total_environments": 0,
                "total_releases": 0,
                "total_deploy_keys": 0,
                "private_repos": 0,
                "archived_repos": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_analysis = self.analyze_repository(repo_full_name)
                        org_repos_analysis["repositories"][repo_full_name] = repo_analysis
                        
                        # Update summary
                        org_repos_analysis["summary"]["total_repos"] += 1
                        org_repos_analysis["summary"]["total_collaborators"] += len(repo_analysis.get("collaborators", []))
                        org_repos_analysis["summary"]["total_deployments"] += len(repo_analysis.get("deployments", []))
                        org_repos_analysis["summary"]["total_environments"] += len(repo_analysis.get("environments", []))
                        org_repos_analysis["summary"]["total_releases"] += len(repo_analysis.get("releases", []))
                        org_repos_analysis["summary"]["total_deploy_keys"] += len(repo_analysis.get("deploy_keys", []))
                        
                        if repo_analysis.get("settings", {}).get("private", False):
                            org_repos_analysis["summary"]["private_repos"] += 1
                        if repo_analysis.get("settings", {}).get("archived", False):
                            org_repos_analysis["summary"]["archived_repos"] += 1
                    except Exception as e:
                        org_repos_analysis["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_repos_analysis["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_repos_analysis

