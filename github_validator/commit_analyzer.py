"""
Commit Analysis Module

Analyzes repository commits including:
- Commit history and statistics
- Contributors and their contributions
- Code changes and file modifications
- Commit messages and patterns
- Commit frequency and activity
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from .api_client import GitHubAPIClient


class CommitAnalyzer:
    """Analyzes repository commits and commit history."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_commits(self, repo_full_name: str, max_commits: int = 100) -> Dict[str, Any]:
        """
        Analyze repository commits.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_commits: Maximum number of commits to analyze
            
        Returns:
            Dictionary with commit analysis
        """
        commit_data = {
            "repository": repo_full_name,
            "commits": [],
            "summary": {
                "total_commits": 0,
                "unique_authors": set(),
                "total_additions": 0,
                "total_deletions": 0,
                "total_files_changed": 0,
                "commit_frequency": {},
                "authors": {}
            },
            "errors": []
        }
        
        try:
            commits = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/commits",
                params={"per_page": 100}
            )
            
            for commit in commits[:max_commits]:
                commit_sha = commit.get("sha", "")
                
                # Get detailed commit information
                try:
                    commit_detail = self.api_client.get(f"/repos/{repo_full_name}/commits/{commit_sha}")
                    if commit_detail:
                        commit_info = {
                            "sha": commit_detail.get("sha", ""),
                            "message": commit_detail.get("commit", {}).get("message", "")[:200],  # First 200 chars
                            "author": {
                                "name": commit_detail.get("commit", {}).get("author", {}).get("name", ""),
                                "email": commit_detail.get("commit", {}).get("author", {}).get("email", ""),
                                "date": commit_detail.get("commit", {}).get("author", {}).get("date", "")
                            },
                            "committer": {
                                "name": commit_detail.get("commit", {}).get("committer", {}).get("name", ""),
                                "email": commit_detail.get("commit", {}).get("committer", {}).get("email", ""),
                                "date": commit_detail.get("commit", {}).get("committer", {}).get("date", "")
                            },
                            "stats": {
                                "additions": commit_detail.get("stats", {}).get("additions", 0),
                                "deletions": commit_detail.get("stats", {}).get("deletions", 0),
                                "total": commit_detail.get("stats", {}).get("total", 0)
                            },
                            "files": [
                                {
                                    "filename": f.get("filename", ""),
                                    "additions": f.get("additions", 0),
                                    "deletions": f.get("deletions", 0),
                                    "changes": f.get("changes", 0),
                                    "status": f.get("status", "")
                                }
                                for f in commit_detail.get("files", [])[:20]  # Limit to 20 files per commit
                            ],
                            "url": commit_detail.get("html_url", "")
                        }
                        
                        commit_data["commits"].append(commit_info)
                        
                        # Update summary
                        commit_data["summary"]["total_commits"] += 1
                        author_email = commit_info["author"]["email"]
                        commit_data["summary"]["unique_authors"].add(author_email)
                        
                        commit_data["summary"]["total_additions"] += commit_info["stats"]["additions"]
                        commit_data["summary"]["total_deletions"] += commit_info["stats"]["deletions"]
                        commit_data["summary"]["total_files_changed"] += len(commit_info["files"])
                        
                        # Track by author
                        if author_email not in commit_data["summary"]["authors"]:
                            commit_data["summary"]["authors"][author_email] = {
                                "name": commit_info["author"]["name"],
                                "commits": 0,
                                "additions": 0,
                                "deletions": 0
                            }
                        commit_data["summary"]["authors"][author_email]["commits"] += 1
                        commit_data["summary"]["authors"][author_email]["additions"] += commit_info["stats"]["additions"]
                        commit_data["summary"]["authors"][author_email]["deletions"] += commit_info["stats"]["deletions"]
                        
                        # Track commit frequency by date
                        commit_date = commit_info["author"]["date"][:10] if commit_info["author"]["date"] else ""
                        if commit_date:
                            commit_data["summary"]["commit_frequency"][commit_date] = commit_data["summary"]["commit_frequency"].get(commit_date, 0) + 1
                except Exception:
                    # If detailed commit fails, use basic info
                    commit_data["commits"].append({
                        "sha": commit.get("sha", ""),
                        "message": commit.get("commit", {}).get("message", "")[:200] if commit.get("commit") else "",
                        "author": commit.get("commit", {}).get("author", {}).get("name", "") if commit.get("commit") else ""
                    })
                    commit_data["summary"]["total_commits"] += 1
        except Exception as e:
            commit_data["errors"].append(f"Failed to get commits: {str(e)}")
        
        # Convert set to list for JSON serialization
        commit_data["summary"]["unique_authors"] = list(commit_data["summary"]["unique_authors"])
        
        return commit_data
    
    def analyze_org_commits(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze commits across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide commit analysis
        """
        org_commits = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_commits": 0,
                "total_unique_authors": set(),
                "total_additions": 0,
                "total_deletions": 0,
                "top_contributors": []
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_commits = self.analyze_repo_commits(repo_full_name, max_commits=50)
                        org_commits["repositories"][repo_full_name] = repo_commits
                        
                        # Update summary
                        org_commits["summary"]["total_repos_analyzed"] += 1
                        org_commits["summary"]["total_commits"] += repo_commits["summary"]["total_commits"]
                        org_commits["summary"]["total_unique_authors"].update(repo_commits["summary"]["unique_authors"])
                        org_commits["summary"]["total_additions"] += repo_commits["summary"]["total_additions"]
                        org_commits["summary"]["total_deletions"] += repo_commits["summary"]["total_deletions"]
                        
                        # Collect top contributors
                        for author_email, author_data in repo_commits["summary"]["authors"].items():
                            org_commits["summary"]["top_contributors"].append({
                                "email": author_email,
                                "name": author_data["name"],
                                "commits": author_data["commits"],
                                "additions": author_data["additions"],
                                "deletions": author_data["deletions"]
                            })
                    except Exception as e:
                        org_commits["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_commits["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Sort top contributors
        org_commits["summary"]["top_contributors"].sort(key=lambda x: x["commits"], reverse=True)
        org_commits["summary"]["top_contributors"] = org_commits["summary"]["top_contributors"][:20]  # Top 20
        
        # Convert set to list
        org_commits["summary"]["total_unique_authors"] = len(org_commits["summary"]["total_unique_authors"])
        
        return org_commits

