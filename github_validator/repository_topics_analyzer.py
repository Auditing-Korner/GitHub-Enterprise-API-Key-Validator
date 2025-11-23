"""
Repository Topics Deep Dive Analysis Module

Analyzes repository topics including:
- Topic usage across organization
- Topic-based repository grouping
- Topic distribution
"""

from typing import Dict, List, Optional, Any
from collections import Counter
from .api_client import GitHubAPIClient


class RepositoryTopicsAnalyzer:
    """Analyzes repository topics in detail."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_topics(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze topics for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with topics analysis
        """
        topics_data = {
            "repository": repo_full_name,
            "topics": [],
            "summary": {
                "total_topics": 0
            },
            "errors": []
        }
        
        try:
            # Get repository info
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            if repo_info:
                topics = repo_info.get("topics", [])
                topics_data["topics"] = topics
                topics_data["summary"]["total_topics"] = len(topics)
        except Exception as e:
            topics_data["errors"].append(f"Failed to get repository topics: {str(e)}")
        
        return topics_data
    
    def analyze_org_topics(self, org_name: str, max_repos: int = 100) -> Dict[str, Any]:
        """
        Analyze topics across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide topics analysis
        """
        org_topics = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "unique_topics": set(),
                "topic_usage": Counter(),
                "repos_with_topics": 0,
                "topics_by_repo_count": {}
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_topics = self.analyze_repo_topics(repo_full_name)
                        org_topics["repositories"][repo_full_name] = repo_topics
                        
                        # Update summary
                        org_topics["summary"]["total_repos_analyzed"] += 1
                        topics = repo_topics.get("topics", [])
                        
                        if topics:
                            org_topics["summary"]["repos_with_topics"] += 1
                            for topic in topics:
                                org_topics["summary"]["unique_topics"].add(topic)
                                org_topics["summary"]["topic_usage"][topic] += 1
                    except Exception as e:
                        org_topics["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        
            # Build topics_by_repo_count (how many repos use each topic)
            for topic, count in org_topics["summary"]["topic_usage"].items():
                org_topics["summary"]["topics_by_repo_count"][topic] = count
        except Exception as e:
            org_topics["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert sets and Counters to lists/dicts
        org_topics["summary"]["unique_topics"] = list(org_topics["summary"]["unique_topics"])
        org_topics["summary"]["topic_usage"] = dict(org_topics["summary"]["topic_usage"])
        
        return org_topics

