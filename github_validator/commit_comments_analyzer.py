"""
Commit Comments Analysis Module

Analyzes commit comments including:
- Comments on commits
- Commit review comments
- Line-by-line comments
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class CommitCommentsAnalyzer:
    """Analyzes commit comments."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_commit_comments(self, repo_full_name: str, max_commits: int = 50) -> Dict[str, Any]:
        """
        Analyze commit comments for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_commits: Maximum number of commits to analyze
            
        Returns:
            Dictionary with commit comments analysis
        """
        comments_data = {
            "repository": repo_full_name,
            "commits": [],
            "summary": {
                "total_commits_analyzed": 0,
                "total_comments": 0,
                "commits_with_comments": 0,
                "commenters": set()
            },
            "errors": []
        }
        
        try:
            # Get commits
            commits = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/commits",
                params={"per_page": 100}
            )
            
            for commit in commits[:max_commits]:
                commit_sha = commit.get("sha", "")
                
                # Get comments for this commit
                try:
                    comments = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/commits/{commit_sha}/comments"
                    )
                    
                    if comments:
                        commit_info = {
                            "sha": commit_sha[:8],  # Short SHA
                            "message": commit.get("commit", {}).get("message", "")[:100] if commit.get("commit") else "",
                            "comments": [],
                            "total_comments": len(comments)
                        }
                        
                        for comment in comments:
                            comment_info = {
                                "id": comment.get("id", ""),
                                "user": {
                                    "login": comment.get("user", {}).get("login", ""),
                                    "id": comment.get("user", {}).get("id", "")
                                } if comment.get("user") else {},
                                "body": comment.get("body", "")[:300] if comment.get("body") else "",
                                "path": comment.get("path", ""),
                                "line": comment.get("line"),
                                "position": comment.get("position"),
                                "created_at": comment.get("created_at", "")
                            }
                            commit_info["comments"].append(comment_info)
                            
                            if comment_info["user"].get("login"):
                                comments_data["summary"]["commenters"].add(comment_info["user"]["login"])
                        
                        comments_data["commits"].append(commit_info)
                        comments_data["summary"]["total_comments"] += len(comments)
                        comments_data["summary"]["commits_with_comments"] += 1
                except Exception as e:
                    comments_data["errors"].append(f"Failed to get comments for commit {commit_sha[:8]}: {str(e)}")
                
                comments_data["summary"]["total_commits_analyzed"] += 1
        except Exception as e:
            comments_data["errors"].append(f"Failed to get commits: {str(e)}")
        
        # Convert set to list
        comments_data["summary"]["commenters"] = list(comments_data["summary"]["commenters"])
        
        return comments_data
    
    def analyze_org_commit_comments(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze commit comments across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide commit comments analysis
        """
        org_comments = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_comments": 0,
                "commits_with_comments": 0,
                "unique_commenters": set()
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_comments = self.analyze_repo_commit_comments(repo_full_name, max_commits=30)
                        org_comments["repositories"][repo_full_name] = repo_comments
                        
                        # Update summary
                        org_comments["summary"]["total_repos_analyzed"] += 1
                        org_comments["summary"]["total_comments"] += repo_comments["summary"]["total_comments"]
                        org_comments["summary"]["commits_with_comments"] += repo_comments["summary"]["commits_with_comments"]
                        org_comments["summary"]["unique_commenters"].update(repo_comments["summary"]["commenters"])
                    except Exception as e:
                        org_comments["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_comments["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert set to list
        org_comments["summary"]["unique_commenters"] = len(org_comments["summary"]["unique_commenters"])
        
        return org_comments

