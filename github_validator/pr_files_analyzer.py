"""
PR Files Changed Analysis Module

Analyzes files changed in pull requests including:
- Files changed in PRs
- File-level diff statistics
- File change patterns
"""

from typing import Dict, List, Optional, Any
from collections import Counter
from .api_client import GitHubAPIClient


class PRFilesAnalyzer:
    """Analyzes files changed in pull requests."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_pr_files(self, repo_full_name: str, max_prs: int = 20) -> Dict[str, Any]:
        """
        Analyze files changed in PRs for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_prs: Maximum number of PRs to analyze
            
        Returns:
            Dictionary with PR files analysis
        """
        files_data = {
            "repository": repo_full_name,
            "pull_requests": [],
            "summary": {
                "total_prs_analyzed": 0,
                "total_files_changed": 0,
                "total_additions": 0,
                "total_deletions": 0,
                "file_extensions": Counter(),
                "most_changed_files": []
            },
            "errors": []
        }
        
        try:
            # Get pull requests
            prs = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/pulls",
                params={"state": "all", "per_page": 100}
            )
            
            for pr in prs[:max_prs]:
                pr_number = pr.get("number", "")
                
                # Get files changed in this PR
                try:
                    files = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/pulls/{pr_number}/files"
                    )
                    
                    pr_info = {
                        "number": pr_number,
                        "title": pr.get("title", "")[:100],
                        "state": pr.get("state", ""),
                        "merged": pr.get("merged", False),
                        "files": [],
                        "total_files": len(files),
                        "total_additions": 0,
                        "total_deletions": 0
                    }
                    
                    for file in files:
                        file_info = {
                            "filename": file.get("filename", ""),
                            "status": file.get("status", ""),  # added, removed, modified, renamed
                            "additions": file.get("additions", 0),
                            "deletions": file.get("deletions", 0),
                            "changes": file.get("changes", 0)
                        }
                        
                        pr_info["files"].append(file_info)
                        pr_info["total_additions"] += file_info["additions"]
                        pr_info["total_deletions"] += file_info["deletions"]
                        
                        # Track file extensions
                        if file_info["filename"]:
                            ext = file_info["filename"].split(".")[-1] if "." in file_info["filename"] else "no_extension"
                            files_data["summary"]["file_extensions"][ext] += 1
                        
                        # Track most changed files
                        files_data["summary"]["most_changed_files"].append({
                            "filename": file_info["filename"],
                            "changes": file_info["changes"]
                        })
                    
                    files_data["pull_requests"].append(pr_info)
                    files_data["summary"]["total_prs_analyzed"] += 1
                    files_data["summary"]["total_files_changed"] += pr_info["total_files"]
                    files_data["summary"]["total_additions"] += pr_info["total_additions"]
                    files_data["summary"]["total_deletions"] += pr_info["total_deletions"]
                except Exception as e:
                    files_data["errors"].append(f"Failed to get files for PR #{pr_number}: {str(e)}")
        except Exception as e:
            files_data["errors"].append(f"Failed to get pull requests: {str(e)}")
        
        # Sort most changed files
        files_data["summary"]["most_changed_files"].sort(key=lambda x: x["changes"], reverse=True)
        files_data["summary"]["most_changed_files"] = files_data["summary"]["most_changed_files"][:30]  # Top 30
        
        # Convert Counter to dict
        files_data["summary"]["file_extensions"] = dict(files_data["summary"]["file_extensions"])
        
        return files_data
    
    def analyze_org_pr_files(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze PR files across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide PR files analysis
        """
        org_files = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_prs": 0,
                "total_files_changed": 0,
                "total_additions": 0,
                "total_deletions": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_files = self.analyze_repo_pr_files(repo_full_name, max_prs=10)
                        org_files["repositories"][repo_full_name] = repo_files
                        
                        # Update summary
                        org_files["summary"]["total_repos_analyzed"] += 1
                        org_files["summary"]["total_prs"] += repo_files["summary"]["total_prs_analyzed"]
                        org_files["summary"]["total_files_changed"] += repo_files["summary"]["total_files_changed"]
                        org_files["summary"]["total_additions"] += repo_files["summary"]["total_additions"]
                        org_files["summary"]["total_deletions"] += repo_files["summary"]["total_deletions"]
                    except Exception as e:
                        org_files["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_files["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_files

