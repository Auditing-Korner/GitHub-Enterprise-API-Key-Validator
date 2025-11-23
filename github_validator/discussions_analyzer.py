"""
Discussions Analysis Module

Analyzes repository discussions including:
- Discussion categories and topics
- Discussion comments and replies
- Community engagement patterns
- Discussion participants
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class DiscussionsAnalyzer:
    """Analyzes repository discussions."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_discussions(self, repo_full_name: str, max_discussions: int = 50) -> Dict[str, Any]:
        """
        Analyze repository discussions.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_discussions: Maximum number of discussions to analyze
            
        Returns:
            Dictionary with discussions analysis
        """
        discussions_data = {
            "repository": repo_full_name,
            "categories": [],
            "discussions": [],
            "summary": {
                "total_discussions": 0,
                "total_comments": 0,
                "categories_count": 0,
                "participants": set(),
                "discussion_types": {}
            },
            "errors": []
        }
        
        # Get discussion categories
        try:
            categories = self.api_client.get_paginated(f"/repos/{repo_full_name}/discussions/categories")
            discussions_data["categories"] = [
                {
                    "id": c.get("id", ""),
                    "name": c.get("name", ""),
                    "slug": c.get("slug", ""),
                    "description": c.get("description", ""),
                    "emoji": c.get("emoji", ""),
                    "created_at": c.get("created_at", "")
                }
                for c in categories
            ]
            discussions_data["summary"]["categories_count"] = len(discussions_data["categories"])
        except Exception as e:
            discussions_data["errors"].append(f"Categories: {str(e)}")
        
        # Get discussions
        try:
            discussions = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/discussions",
                params={"per_page": 100}
            )
            
            for discussion in discussions[:max_discussions]:
                discussion_data = {
                    "number": discussion.get("number", 0),
                    "title": discussion.get("title", ""),
                    "body": discussion.get("body", "")[:1000],  # First 1000 chars
                    "category": {
                        "id": discussion.get("category", {}).get("id", ""),
                        "name": discussion.get("category", {}).get("name", "")
                    } if discussion.get("category") else {},
                    "author": {
                        "login": discussion.get("user", {}).get("login", ""),
                        "id": discussion.get("user", {}).get("id", "")
                    } if discussion.get("user") else {},
                    "state": discussion.get("state", ""),
                    "comments": discussion.get("comments", 0),
                    "upvote_count": discussion.get("upvote_count", 0),
                    "created_at": discussion.get("created_at", ""),
                    "updated_at": discussion.get("updated_at", ""),
                    "html_url": discussion.get("html_url", "")
                }
                
                # Get discussion comments
                try:
                    comments = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/discussions/{discussion.get('number')}/comments",
                        params={"per_page": 100}
                    )
                    discussion_data["comments_list"] = [
                        {
                            "id": c.get("id", ""),
                            "body": c.get("body", "")[:500],  # First 500 chars
                            "author": {
                                "login": c.get("user", {}).get("login", ""),
                                "id": c.get("user", {}).get("id", "")
                            } if c.get("user") else {},
                            "created_at": c.get("created_at", ""),
                            "updated_at": c.get("updated_at", "")
                        }
                        for c in comments[:20]  # Limit to 20 comments per discussion
                    ]
                    
                    # Collect participants
                    if discussion_data.get("author", {}).get("login"):
                        discussions_data["summary"]["participants"].add(discussion_data["author"]["login"])
                    for comment in discussion_data.get("comments_list", []):
                        if comment.get("author", {}).get("login"):
                            discussions_data["summary"]["participants"].add(comment["author"]["login"])
                except Exception:
                    discussion_data["comments_list"] = []
                
                discussions_data["discussions"].append(discussion_data)
                
                # Update summary
                discussions_data["summary"]["total_discussions"] += 1
                discussions_data["summary"]["total_comments"] += discussion.get("comments", 0)
                
                # Count by category
                category_name = discussion_data.get("category", {}).get("name", "uncategorized")
                discussions_data["summary"]["discussion_types"][category_name] = discussions_data["summary"]["discussion_types"].get(category_name, 0) + 1
        except Exception as e:
            discussions_data["errors"].append(f"Discussions: {str(e)}")
        
        # Convert set to list for JSON serialization
        discussions_data["summary"]["participants"] = list(discussions_data["summary"]["participants"])
        
        return discussions_data
    
    def analyze_org_discussions(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze discussions across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide discussions analysis
        """
        org_discussions = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_discussions": 0,
                "total_comments": 0,
                "total_categories": 0,
                "total_participants": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_discussions = self.analyze_repo_discussions(repo_full_name, max_discussions=20)
                        org_discussions["repositories"][repo_full_name] = repo_discussions
                        
                        # Update summary
                        org_discussions["summary"]["total_repos_analyzed"] += 1
                        org_discussions["summary"]["total_discussions"] += repo_discussions["summary"]["total_discussions"]
                        org_discussions["summary"]["total_comments"] += repo_discussions["summary"]["total_comments"]
                        org_discussions["summary"]["total_categories"] += repo_discussions["summary"]["categories_count"]
                        org_discussions["summary"]["total_participants"] += len(repo_discussions["summary"]["participants"])
                    except Exception as e:
                        org_discussions["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_discussions["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_discussions

