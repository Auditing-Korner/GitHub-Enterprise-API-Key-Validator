"""
Repository Contributors Analysis Module

Analyzes repository contributors including:
- Detailed contributor statistics
- Contributor activity patterns
- Contributor permissions
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class ContributorsAnalyzer:
    """Analyzes repository contributors."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_contributors(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze contributors for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with contributors analysis
        """
        contributors_data = {
            "repository": repo_full_name,
            "contributors": [],
            "summary": {
                "total_contributors": 0,
                "total_contributions": 0,
                "top_contributors": []
            },
            "errors": []
        }
        
        try:
            # Get contributors
            contributors = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/contributors",
                params={"per_page": 100}
            )
            
            for contributor in contributors:
                contributor_info = {
                    "login": contributor.get("login", ""),
                    "id": contributor.get("id", ""),
                    "contributions": contributor.get("contributions", 0),
                    "type": contributor.get("type", ""),
                    "avatar_url": contributor.get("avatar_url", "")
                }
                
                contributors_data["contributors"].append(contributor_info)
                contributors_data["summary"]["total_contributors"] += 1
                contributors_data["summary"]["total_contributions"] += contributor_info["contributions"]
            
            # Sort by contributions
            contributors_data["contributors"].sort(key=lambda x: x["contributions"], reverse=True)
            contributors_data["summary"]["top_contributors"] = [
                {
                    "login": c["login"],
                    "contributions": c["contributions"]
                }
                for c in contributors_data["contributors"][:20]  # Top 20
            ]
        except Exception as e:
            contributors_data["errors"].append(f"Failed to get contributors: {str(e)}")
        
        return contributors_data
    
    def analyze_org_contributors(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze contributors across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide contributors analysis
        """
        org_contributors = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_contributors": 0,
                "unique_contributors": set(),
                "total_contributions": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_contributors = self.analyze_repo_contributors(repo_full_name)
                        org_contributors["repositories"][repo_full_name] = repo_contributors
                        
                        # Update summary
                        org_contributors["summary"]["total_repos_analyzed"] += 1
                        org_contributors["summary"]["total_contributors"] += repo_contributors["summary"]["total_contributors"]
                        org_contributors["summary"]["total_contributions"] += repo_contributors["summary"]["total_contributions"]
                        
                        # Track unique contributors
                        for contributor in repo_contributors["contributors"]:
                            org_contributors["summary"]["unique_contributors"].add(contributor["login"])
                    except Exception as e:
                        org_contributors["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_contributors["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert set to list
        org_contributors["summary"]["unique_contributors"] = len(org_contributors["summary"]["unique_contributors"])
        
        return org_contributors

