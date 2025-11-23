"""
Repository Insights and Analytics Module

Analyzes repository insights including:
- Traffic statistics (clones, views)
- Popular paths and content
- Referrer statistics
- Commit activity patterns
- Contributor statistics
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from .api_client import GitHubAPIClient


class RepositoryInsightsAnalyzer:
    """Analyzes repository insights and analytics."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_traffic(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze repository traffic statistics.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with traffic analysis
        """
        traffic_data = {
            "repository": repo_full_name,
            "clones": {},
            "views": {},
            "popular_paths": [],
            "popular_referrers": [],
            "errors": []
        }
        
        # Get clone statistics
        try:
            clones = self.api_client.get(f"/repos/{repo_full_name}/traffic/clones")
            if clones:
                traffic_data["clones"] = {
                    "count": clones.get("count", 0),
                    "uniques": clones.get("uniques", 0),
                    "clones": [
                        {
                            "timestamp": c.get("timestamp", ""),
                            "count": c.get("count", 0),
                            "uniques": c.get("uniques", 0)
                        }
                        for c in clones.get("clones", [])
                    ]
                }
        except Exception as e:
            traffic_data["errors"].append(f"Clones: {str(e)}")
        
        # Get view statistics
        try:
            views = self.api_client.get(f"/repos/{repo_full_name}/traffic/views")
            if views:
                traffic_data["views"] = {
                    "count": views.get("count", 0),
                    "uniques": views.get("uniques", 0),
                    "views": [
                        {
                            "timestamp": v.get("timestamp", ""),
                            "count": v.get("count", 0),
                            "uniques": v.get("uniques", 0)
                        }
                        for v in views.get("views", [])
                    ]
                }
        except Exception as e:
            traffic_data["errors"].append(f"Views: {str(e)}")
        
        # Get popular paths
        try:
            paths = self.api_client.get(f"/repos/{repo_full_name}/traffic/popular/paths")
            if paths:
                traffic_data["popular_paths"] = [
                    {
                        "path": p.get("path", ""),
                        "title": p.get("title", ""),
                        "count": p.get("count", 0),
                        "uniques": p.get("uniques", 0)
                    }
                    for p in paths[:50]  # Limit for performance
                ]
        except Exception as e:
            traffic_data["errors"].append(f"Popular paths: {str(e)}")
        
        # Get popular referrers
        try:
            referrers = self.api_client.get(f"/repos/{repo_full_name}/traffic/popular/referrers")
            if referrers:
                traffic_data["popular_referrers"] = [
                    {
                        "referrer": r.get("referrer", ""),
                        "count": r.get("count", 0),
                        "uniques": r.get("uniques", 0)
                    }
                    for r in referrers[:50]  # Limit for performance
                ]
        except Exception as e:
            traffic_data["errors"].append(f"Popular referrers: {str(e)}")
        
        return traffic_data
    
    def analyze_repo_commit_activity(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze repository commit activity patterns.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with commit activity analysis
        """
        activity_data = {
            "repository": repo_full_name,
            "stats": {},
            "punch_card": [],
            "code_frequency": [],
            "contributors": [],
            "errors": []
        }
        
        # Get commit activity (last year, weekly aggregates)
        try:
            activity = self.api_client.get(f"/repos/{repo_full_name}/stats/commit_activity")
            if activity:
                activity_data["stats"] = {
                    "total_commits": sum(week.get("total", 0) for week in activity),
                    "weeks": [
                        {
                            "week": week.get("week", 0),
                            "days": week.get("days", []),
                            "total": week.get("total", 0)
                        }
                        for week in activity[-12:]  # Last 12 weeks
                    ]
                }
        except Exception as e:
            activity_data["errors"].append(f"Commit activity: {str(e)}")
        
        # Get punch card (hourly commit patterns)
        try:
            punch_card = self.api_client.get(f"/repos/{repo_full_name}/stats/punch_card")
            if punch_card:
                activity_data["punch_card"] = punch_card[:168]  # 24 hours * 7 days
        except Exception as e:
            activity_data["errors"].append(f"Punch card: {str(e)}")
        
        # Get code frequency (additions/deletions over time)
        try:
            code_freq = self.api_client.get(f"/repos/{repo_full_name}/stats/code_frequency")
            if code_freq:
                activity_data["code_frequency"] = [
                    {
                        "week": entry[0],
                        "additions": entry[1],
                        "deletions": entry[2]
                    }
                    for entry in code_freq[-52:]  # Last 52 weeks
                ]
        except Exception as e:
            activity_data["errors"].append(f"Code frequency: {str(e)}")
        
        # Get contributor statistics
        try:
            contributors = self.api_client.get(f"/repos/{repo_full_name}/stats/contributors")
            if contributors:
                activity_data["contributors"] = [
                    {
                        "author": {
                            "login": c.get("author", {}).get("login", ""),
                            "id": c.get("author", {}).get("id", "")
                        } if c.get("author") else {},
                        "total": sum(w.get("c", 0) for w in c.get("weeks", [])),
                        "weeks": len(c.get("weeks", []))
                    }
                    for c in contributors[:50]  # Top 50 contributors
                ]
        except Exception as e:
            activity_data["errors"].append(f"Contributors: {str(e)}")
        
        return activity_data
    
    def analyze_org_repository_insights(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze repository insights across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide insights
        """
        org_insights = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_clones": 0,
                "total_unique_clones": 0,
                "total_views": 0,
                "total_unique_views": 0,
                "total_commits": 0,
                "repos_with_traffic": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        # Get traffic data
                        traffic = self.analyze_repo_traffic(repo_full_name)
                        
                        # Get commit activity
                        activity = self.analyze_repo_commit_activity(repo_full_name)
                        
                        org_insights["repositories"][repo_full_name] = {
                            "traffic": traffic,
                            "activity": activity
                        }
                        
                        # Update summary
                        org_insights["summary"]["total_repos_analyzed"] += 1
                        org_insights["summary"]["total_clones"] += traffic.get("clones", {}).get("count", 0)
                        org_insights["summary"]["total_unique_clones"] += traffic.get("clones", {}).get("uniques", 0)
                        org_insights["summary"]["total_views"] += traffic.get("views", {}).get("count", 0)
                        org_insights["summary"]["total_unique_views"] += traffic.get("views", {}).get("uniques", 0)
                        org_insights["summary"]["total_commits"] += activity.get("stats", {}).get("total_commits", 0)
                        
                        if traffic.get("clones", {}).get("count", 0) > 0 or traffic.get("views", {}).get("count", 0) > 0:
                            org_insights["summary"]["repos_with_traffic"] += 1
                    except Exception as e:
                        org_insights["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_insights["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_insights

