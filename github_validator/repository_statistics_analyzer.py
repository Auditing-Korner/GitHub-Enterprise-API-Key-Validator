"""
Repository Statistics Analysis Module

Analyzes detailed repository statistics including:
- Repository activity patterns
- Engagement metrics
- Detailed statistics
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class RepositoryStatisticsAnalyzer:
    """Analyzes detailed repository statistics."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_statistics(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze detailed statistics for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with repository statistics
        """
        stats_data = {
            "repository": repo_full_name,
            "basic_stats": {},
            "code_frequency": {},
            "commit_activity": {},
            "contributor_stats": [],
            "participation": {},
            "punch_card": {},
            "summary": {
                "stats_available": False
            },
            "errors": []
        }
        
        try:
            # Get repository info for basic stats
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            if repo_info:
                stats_data["basic_stats"] = {
                    "size": repo_info.get("size", 0),
                    "stargazers_count": repo_info.get("stargazers_count", 0),
                    "watchers_count": repo_info.get("watchers_count", 0),
                    "forks_count": repo_info.get("forks_count", 0),
                    "open_issues_count": repo_info.get("open_issues_count", 0),
                    "subscribers_count": repo_info.get("subscribers_count", 0),
                    "network_count": repo_info.get("network_count", 0),
                    "language": repo_info.get("language", "")
                }
                stats_data["summary"]["stats_available"] = True
        except Exception as e:
            stats_data["errors"].append(f"Failed to get repository info: {str(e)}")
        
        # Get code frequency (additions/deletions per week)
        try:
            code_freq = self.api_client.get(f"/repos/{repo_full_name}/stats/code_frequency")
            if code_freq:
                stats_data["code_frequency"] = {
                    "weeks_analyzed": len(code_freq),
                    "total_additions": sum(week[1] for week in code_freq if len(week) > 1),
                    "total_deletions": sum(abs(week[2]) for week in code_freq if len(week) > 2)
                }
        except Exception:
            pass
        
        # Get commit activity (commits per week)
        try:
            commit_activity = self.api_client.get(f"/repos/{repo_full_name}/stats/commit_activity")
            if commit_activity:
                stats_data["commit_activity"] = {
                    "weeks_analyzed": len(commit_activity),
                    "total_commits": sum(week.get("total", 0) for week in commit_activity),
                    "weeks_with_commits": sum(1 for week in commit_activity if week.get("total", 0) > 0)
                }
        except Exception:
            pass
        
        # Get contributor statistics
        try:
            contributors = self.api_client.get(f"/repos/{repo_full_name}/stats/contributors")
            if contributors:
                stats_data["contributor_stats"] = [
                    {
                        "author": {
                            "login": c.get("author", {}).get("login", ""),
                            "id": c.get("author", {}).get("id", "")
                        } if c.get("author") else {},
                        "total_commits": c.get("total", 0),
                        "weeks": len(c.get("weeks", []))
                    }
                    for c in contributors[:20]  # Top 20 contributors
                ]
        except Exception:
            pass
        
        # Get participation (all vs owner commits)
        try:
            participation = self.api_client.get(f"/repos/{repo_full_name}/stats/participation")
            if participation:
                stats_data["participation"] = {
                    "all_commits": participation.get("all", []),
                    "owner_commits": participation.get("owner", []),
                    "total_all": sum(participation.get("all", [])),
                    "total_owner": sum(participation.get("owner", []))
                }
        except Exception:
            pass
        
        return stats_data
    
    def analyze_org_statistics(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze statistics across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide statistics analysis
        """
        org_stats = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "repos_with_stats": 0,
                "total_stargazers": 0,
                "total_forks": 0,
                "total_watchers": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_stats = self.analyze_repo_statistics(repo_full_name)
                        org_stats["repositories"][repo_full_name] = repo_stats
                        
                        # Update summary
                        org_stats["summary"]["total_repos_analyzed"] += 1
                        if repo_stats["summary"]["stats_available"]:
                            org_stats["summary"]["repos_with_stats"] += 1
                        
                        basic_stats = repo_stats.get("basic_stats", {})
                        org_stats["summary"]["total_stargazers"] += basic_stats.get("stargazers_count", 0)
                        org_stats["summary"]["total_forks"] += basic_stats.get("forks_count", 0)
                        org_stats["summary"]["total_watchers"] += basic_stats.get("watchers_count", 0)
                    except Exception as e:
                        org_stats["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_stats["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_stats

