"""
Branch Analysis Module

Analyzes repository branches including:
- All branches and branch details
- Branch protection rules
- Branch comparison and differences
- Default branch analysis
- Branch commit history
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class BranchAnalyzer:
    """Analyzes repository branches and branch protection."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_branches(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze repository branches.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with branch analysis
        """
        branch_data = {
            "repository": repo_full_name,
            "branches": [],
            "default_branch": None,
            "protected_branches": [],
            "summary": {
                "total_branches": 0,
                "protected_count": 0,
                "default_branch": None
            },
            "errors": []
        }
        
        try:
            # Get repository info for default branch
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            if repo_info:
                branch_data["default_branch"] = repo_info.get("default_branch", "main")
                branch_data["summary"]["default_branch"] = branch_data["default_branch"]
            
            # Get all branches
            branches = self.api_client.get_paginated(f"/repos/{repo_full_name}/branches")
            
            for branch in branches:
                branch_name = branch.get("name", "")
                protected = branch.get("protected", False)
                
                branch_info = {
                    "name": branch_name,
                    "protected": protected,
                    "sha": branch.get("commit", {}).get("sha", "") if branch.get("commit") else "",
                    "commit_url": branch.get("commit", {}).get("url", "") if branch.get("commit") else ""
                }
                
                # Get branch protection if protected
                if protected:
                    try:
                        protection = self.api_client.get(f"/repos/{repo_full_name}/branches/{branch_name}/protection")
                        if protection:
                            branch_info["protection"] = {
                                "required_status_checks": protection.get("required_status_checks", {}),
                                "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False) if protection.get("enforce_admins") else False,
                                "required_pull_request_reviews": protection.get("required_pull_request_reviews", {}),
                                "restrictions": protection.get("restrictions", {}),
                                "allow_force_pushes": protection.get("allow_force_pushes", {}).get("enabled", False) if protection.get("allow_force_pushes") else False,
                                "allow_deletions": protection.get("allow_deletions", {}).get("enabled", False) if protection.get("allow_deletions") else False
                            }
                            branch_data["protected_branches"].append(branch_info)
                    except Exception:
                        pass
                
                branch_data["branches"].append(branch_info)
                branch_data["summary"]["total_branches"] += 1
                if protected:
                    branch_data["summary"]["protected_count"] += 1
        except Exception as e:
            branch_data["errors"].append(f"Failed to get branches: {str(e)}")
        
        return branch_data
    
    def compare_branches(self, repo_full_name: str, base: str, head: str) -> Dict[str, Any]:
        """
        Compare two branches.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            base: Base branch name
            head: Head branch name
            
        Returns:
            Dictionary with branch comparison
        """
        comparison = {
            "repository": repo_full_name,
            "base": base,
            "head": head,
            "ahead_by": 0,
            "behind_by": 0,
            "total_commits": 0,
            "files": [],
            "errors": []
        }
        
        try:
            compare_result = self.api_client.get(
                f"/repos/{repo_full_name}/compare/{base}...{head}"
            )
            if compare_result:
                comparison["ahead_by"] = compare_result.get("ahead_by", 0)
                comparison["behind_by"] = compare_result.get("behind_by", 0)
                comparison["total_commits"] = compare_result.get("total_commits", 0)
                comparison["files"] = [
                    {
                        "filename": f.get("filename", ""),
                        "additions": f.get("additions", 0),
                        "deletions": f.get("deletions", 0),
                        "changes": f.get("changes", 0),
                        "status": f.get("status", "")
                    }
                    for f in compare_result.get("files", [])[:50]  # Limit to 50 files
                ]
        except Exception as e:
            comparison["errors"].append(f"Failed to compare branches: {str(e)}")
        
        return comparison
    
    def analyze_org_branches(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze branches across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide branch analysis
        """
        org_branches = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_branches": 0,
                "total_protected_branches": 0,
                "repos_with_protection": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_branches = self.analyze_repo_branches(repo_full_name)
                        org_branches["repositories"][repo_full_name] = repo_branches
                        
                        # Update summary
                        org_branches["summary"]["total_repos_analyzed"] += 1
                        org_branches["summary"]["total_branches"] += repo_branches["summary"]["total_branches"]
                        org_branches["summary"]["total_protected_branches"] += repo_branches["summary"]["protected_count"]
                        
                        if repo_branches["summary"]["protected_count"] > 0:
                            org_branches["summary"]["repos_with_protection"] += 1
                    except Exception as e:
                        org_branches["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_branches["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_branches

