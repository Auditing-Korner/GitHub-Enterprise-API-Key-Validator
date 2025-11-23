"""
Stargazers/Watchers Analysis Module

Analyzes repository stargazers and watchers including:
- Who starred repositories
- Who watches repositories
- Star/watch patterns
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class StargazersWatchersAnalyzer:
    """Analyzes repository stargazers and watchers."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_stargazers_watchers(self, repo_full_name: str, max_items: int = 100) -> Dict[str, Any]:
        """
        Analyze stargazers and watchers for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_items: Maximum number of stargazers/watchers to analyze
            
        Returns:
            Dictionary with stargazers/watchers analysis
        """
        data = {
            "repository": repo_full_name,
            "stargazers": [],
            "watchers": [],
            "summary": {
                "total_stargazers": 0,
                "total_watchers": 0,
                "unique_stargazers": set(),
                "unique_watchers": set()
            },
            "errors": []
        }
        
        # Get stargazers
        try:
            stargazers = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/stargazers",
                params={"per_page": 100}
            )
            
            for star in stargazers[:max_items]:
                star_info = {
                    "login": star.get("login", ""),
                    "id": star.get("id", ""),
                    "type": star.get("type", ""),
                    "starred_at": star.get("starred_at", "")
                }
                data["stargazers"].append(star_info)
                data["summary"]["total_stargazers"] += 1
                if star_info["login"]:
                    data["summary"]["unique_stargazers"].add(star_info["login"])
        except Exception as e:
            data["errors"].append(f"Failed to get stargazers: {str(e)}")
        
        # Get watchers
        try:
            watchers = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/subscribers",
                params={"per_page": 100}
            )
            
            for watcher in watchers[:max_items]:
                watcher_info = {
                    "login": watcher.get("login", ""),
                    "id": watcher.get("id", ""),
                    "type": watcher.get("type", "")
                }
                data["watchers"].append(watcher_info)
                data["summary"]["total_watchers"] += 1
                if watcher_info["login"]:
                    data["summary"]["unique_watchers"].add(watcher_info["login"])
        except Exception as e:
            data["errors"].append(f"Failed to get watchers: {str(e)}")
        
        # Convert sets to lists
        data["summary"]["unique_stargazers"] = len(data["summary"]["unique_stargazers"])
        data["summary"]["unique_watchers"] = len(data["summary"]["unique_watchers"])
        
        return data
    
    def analyze_org_stargazers_watchers(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze stargazers/watchers across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide stargazers/watchers analysis
        """
        org_data = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_stargazers": 0,
                "total_watchers": 0,
                "unique_stargazers": set(),
                "unique_watchers": set()
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_data = self.analyze_repo_stargazers_watchers(repo_full_name, max_items=50)
                        org_data["repositories"][repo_full_name] = repo_data
                        
                        # Update summary
                        org_data["summary"]["total_repos_analyzed"] += 1
                        org_data["summary"]["total_stargazers"] += repo_data["summary"]["total_stargazers"]
                        org_data["summary"]["total_watchers"] += repo_data["summary"]["total_watchers"]
                        
                        # Track unique users
                        for star in repo_data["stargazers"]:
                            if star.get("login"):
                                org_data["summary"]["unique_stargazers"].add(star["login"])
                        for watcher in repo_data["watchers"]:
                            if watcher.get("login"):
                                org_data["summary"]["unique_watchers"].add(watcher["login"])
                    except Exception as e:
                        org_data["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_data["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert sets to counts
        org_data["summary"]["unique_stargazers"] = len(org_data["summary"]["unique_stargazers"])
        org_data["summary"]["unique_watchers"] = len(org_data["summary"]["unique_watchers"])
        
        return org_data

