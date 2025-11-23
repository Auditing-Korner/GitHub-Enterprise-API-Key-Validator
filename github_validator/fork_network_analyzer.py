"""
Fork Network Analysis Module

Analyzes fork network including:
- Fork relationships
- Fork network structure
- Fork activity
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class ForkNetworkAnalyzer:
    """Analyzes fork network."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_forks(self, repo_full_name: str, max_forks: int = 100) -> Dict[str, Any]:
        """
        Analyze forks for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_forks: Maximum number of forks to analyze
            
        Returns:
            Dictionary with forks analysis
        """
        forks_data = {
            "repository": repo_full_name,
            "forks": [],
            "summary": {
                "total_forks": 0,
                "forks_by_org": 0,
                "forks_by_user": 0,
                "unique_forkers": set()
            },
            "errors": []
        }
        
        try:
            # Get forks
            forks = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/forks",
                params={"per_page": 100, "sort": "newest"}
            )
            
            for fork in forks[:max_forks]:
                fork_info = {
                    "full_name": fork.get("full_name", ""),
                    "owner": {
                        "login": fork.get("owner", {}).get("login", ""),
                        "type": fork.get("owner", {}).get("type", ""),
                        "id": fork.get("owner", {}).get("id", "")
                    } if fork.get("owner") else {},
                    "fork": fork.get("fork", False),
                    "created_at": fork.get("created_at", ""),
                    "updated_at": fork.get("updated_at", ""),
                    "pushed_at": fork.get("pushed_at", ""),
                    "stargazers_count": fork.get("stargazers_count", 0),
                    "watchers_count": fork.get("watchers_count", 0)
                }
                
                forks_data["forks"].append(fork_info)
                forks_data["summary"]["total_forks"] += 1
                
                owner_type = fork_info["owner"].get("type", "")
                if owner_type == "Organization":
                    forks_data["summary"]["forks_by_org"] += 1
                elif owner_type == "User":
                    forks_data["summary"]["forks_by_user"] += 1
                
                if fork_info["owner"].get("login"):
                    forks_data["summary"]["unique_forkers"].add(fork_info["owner"]["login"])
        except Exception as e:
            forks_data["errors"].append(f"Failed to get forks: {str(e)}")
        
        # Convert set to count
        forks_data["summary"]["unique_forkers"] = len(forks_data["summary"]["unique_forkers"])
        
        return forks_data
    
    def analyze_org_forks(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze forks across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide forks analysis
        """
        org_forks = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_forks": 0,
                "repos_with_forks": 0,
                "unique_forkers": set()
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_forks = self.analyze_repo_forks(repo_full_name, max_forks=50)
                        org_forks["repositories"][repo_full_name] = repo_forks
                        
                        # Update summary
                        org_forks["summary"]["total_repos_analyzed"] += 1
                        org_forks["summary"]["total_forks"] += repo_forks["summary"]["total_forks"]
                        
                        if repo_forks["summary"]["total_forks"] > 0:
                            org_forks["summary"]["repos_with_forks"] += 1
                        
                        # Track unique forkers
                        for fork in repo_forks["forks"]:
                            if fork.get("owner", {}).get("login"):
                                org_forks["summary"]["unique_forkers"].add(fork["owner"]["login"])
                    except Exception as e:
                        org_forks["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_forks["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert set to count
        org_forks["summary"]["unique_forkers"] = len(org_forks["summary"]["unique_forkers"])
        
        return org_forks

