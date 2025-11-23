"""
Milestones Analysis Module

Analyzes repository milestones including:
- Milestone details and progress
- Milestone issues and PRs
- Milestone state and due dates
- Milestone statistics
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class MilestonesAnalyzer:
    """Analyzes repository milestones."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_milestones(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze milestones for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with milestones analysis
        """
        milestones_data = {
            "repository": repo_full_name,
            "milestones": [],
            "summary": {
                "total_milestones": 0,
                "open_milestones": 0,
                "closed_milestones": 0,
                "milestones_with_due_dates": 0,
                "total_issues": 0,
                "total_prs": 0
            },
            "errors": []
        }
        
        try:
            # Get all milestones
            milestones = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/milestones",
                params={"state": "all"}
            )
            
            for milestone in milestones:
                milestone_number = milestone.get("number", "")
                milestone_info = {
                    "number": milestone_number,
                    "title": milestone.get("title", ""),
                    "description": milestone.get("description", "")[:500] if milestone.get("description") else "",
                    "state": milestone.get("state", ""),
                    "open_issues": milestone.get("open_issues", 0),
                    "closed_issues": milestone.get("closed_issues", 0),
                    "due_on": milestone.get("due_on", ""),
                    "created_at": milestone.get("created_at", ""),
                    "updated_at": milestone.get("updated_at", ""),
                    "closed_at": milestone.get("closed_at", ""),
                    "creator": {
                        "login": milestone.get("creator", {}).get("login", ""),
                        "id": milestone.get("creator", {}).get("id", "")
                    } if milestone.get("creator") else {}
                }
                
                # Get issues and PRs for this milestone
                try:
                    issues = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/issues",
                        params={"milestone": milestone_number, "state": "all"}
                    )
                    milestone_info["issues"] = [
                        {
                            "number": issue.get("number", ""),
                            "title": issue.get("title", ""),
                            "state": issue.get("state", ""),
                            "pull_request": issue.get("pull_request") is not None
                        }
                        for issue in issues[:50]  # Limit to 50
                    ]
                    milestone_info["total_issues"] = len(milestone_info["issues"])
                    milestone_info["total_prs"] = sum(1 for issue in milestone_info["issues"] if issue.get("pull_request"))
                except Exception as e:
                    milestone_info["issues"] = []
                    milestone_info["total_issues"] = 0
                    milestone_info["total_prs"] = 0
                    milestones_data["errors"].append(f"Failed to get issues for milestone {milestone_number}: {str(e)}")
                
                milestones_data["milestones"].append(milestone_info)
                
                # Update summary
                milestones_data["summary"]["total_milestones"] += 1
                if milestone_info["state"] == "open":
                    milestones_data["summary"]["open_milestones"] += 1
                else:
                    milestones_data["summary"]["closed_milestones"] += 1
                
                if milestone_info.get("due_on"):
                    milestones_data["summary"]["milestones_with_due_dates"] += 1
                
                milestones_data["summary"]["total_issues"] += milestone_info["total_issues"]
                milestones_data["summary"]["total_prs"] += milestone_info["total_prs"]
        except Exception as e:
            milestones_data["errors"].append(f"Failed to get milestones: {str(e)}")
        
        return milestones_data
    
    def analyze_org_milestones(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze milestones across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide milestones analysis
        """
        org_milestones = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_milestones": 0,
                "open_milestones": 0,
                "closed_milestones": 0,
                "repos_with_milestones": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_milestones = self.analyze_repo_milestones(repo_full_name)
                        org_milestones["repositories"][repo_full_name] = repo_milestones
                        
                        # Update summary
                        org_milestones["summary"]["total_repos_analyzed"] += 1
                        org_milestones["summary"]["total_milestones"] += repo_milestones["summary"]["total_milestones"]
                        org_milestones["summary"]["open_milestones"] += repo_milestones["summary"]["open_milestones"]
                        org_milestones["summary"]["closed_milestones"] += repo_milestones["summary"]["closed_milestones"]
                        
                        if repo_milestones["summary"]["total_milestones"] > 0:
                            org_milestones["summary"]["repos_with_milestones"] += 1
                    except Exception as e:
                        org_milestones["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_milestones["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_milestones

