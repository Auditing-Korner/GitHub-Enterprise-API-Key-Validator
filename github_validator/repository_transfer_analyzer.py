"""
Repository Transfer History Analysis Module

Analyzes repository transfer history including:
- Repository ownership transfers
- Transfer history
- Transfer events
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class RepositoryTransferAnalyzer:
    """Analyzes repository transfer history."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_transfer_history(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze transfer history for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with transfer history analysis
        """
        transfer_data = {
            "repository": repo_full_name,
            "current_owner": {},
            "transfer_history": [],
            "summary": {
                "has_transferred": False,
                "transfer_count": 0
            },
            "errors": []
        }
        
        try:
            # Get repository info
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            if repo_info:
                transfer_data["current_owner"] = {
                    "login": repo_info.get("owner", {}).get("login", ""),
                    "type": repo_info.get("owner", {}).get("type", ""),
                    "id": repo_info.get("owner", {}).get("id", "")
                } if repo_info.get("owner") else {}
                
                # Check if repository was transferred (created_at vs owner creation)
                # Note: GitHub API doesn't directly provide transfer history,
                # but we can infer from repository metadata
                created_at = repo_info.get("created_at", "")
                updated_at = repo_info.get("updated_at", "")
                
                # If updated_at is significantly later than created_at, might indicate transfer
                # This is a heuristic approach since GitHub doesn't expose transfer history directly
                transfer_data["summary"]["has_transferred"] = created_at != updated_at
        except Exception as e:
            transfer_data["errors"].append(f"Failed to get repository info: {str(e)}")
        
        return transfer_data
    
    def analyze_org_repo_transfers(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze transfer history across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide transfer analysis
        """
        org_transfers = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "repos_possibly_transferred": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_transfer = self.analyze_repo_transfer_history(repo_full_name)
                        org_transfers["repositories"][repo_full_name] = repo_transfer
                        
                        # Update summary
                        org_transfers["summary"]["total_repos_analyzed"] += 1
                        if repo_transfer["summary"]["has_transferred"]:
                            org_transfers["summary"]["repos_possibly_transferred"] += 1
                    except Exception as e:
                        org_transfers["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_transfers["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_transfers

