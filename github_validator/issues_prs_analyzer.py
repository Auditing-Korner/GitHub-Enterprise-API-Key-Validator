"""
Issues and Pull Requests Analysis Module

Analyzes issues and pull requests across repositories:
- Open/closed issues and PRs
- Comments and discussions
- Labels, milestones, assignees
- Reviews and review comments
- PR checks and statuses
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class IssuesPRsAnalyzer:
    """Analyzes issues and pull requests."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_issues_prs(self, repo_full_name: str, max_items: int = 50) -> Dict[str, Any]:
        """
        Analyze issues and pull requests for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_items: Maximum number of issues/PRs to analyze per type
            
        Returns:
            Dictionary with issues and PRs analysis
        """
        analysis = {
            "repository": repo_full_name,
            "issues": {
                "open": [],
                "closed": [],
                "total": 0
            },
            "pull_requests": {
                "open": [],
                "closed": [],
                "merged": [],
                "total": 0
            },
            "comments": [],
            "labels": [],
            "milestones": [],
            "assignees": [],
            "reviewers": [],
            "errors": []
        }
        
        # Get open issues
        try:
            open_issues = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/issues",
                params={"state": "open", "per_page": 100}
            )
            for issue in open_issues[:max_items]:
                if "pull_request" not in issue:  # Issues only, not PRs
                    issue_data = {
                        "number": issue.get("number", 0),
                        "title": issue.get("title", ""),
                        "state": issue.get("state", ""),
                        "user": {
                            "login": issue.get("user", {}).get("login", ""),
                            "type": issue.get("user", {}).get("type", "")
                        } if issue.get("user") else {},
                        "assignees": [a.get("login", "") for a in issue.get("assignees", [])],
                        "labels": [l.get("name", "") for l in issue.get("labels", [])],
                        "milestone": issue.get("milestone", {}).get("title", "") if issue.get("milestone") else None,
                        "comments": issue.get("comments", 0),
                        "created_at": issue.get("created_at", ""),
                        "updated_at": issue.get("updated_at", ""),
                        "body": issue.get("body", "")[:500] if issue.get("body") else ""  # First 500 chars
                    }
                    analysis["issues"]["open"].append(issue_data)
                    analysis["issues"]["total"] += 1
        except Exception as e:
            analysis["errors"].append(f"Open issues: {str(e)}")
        
        # Get closed issues
        try:
            closed_issues = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/issues",
                params={"state": "closed", "per_page": 100}
            )
            for issue in closed_issues[:max_items]:
                if "pull_request" not in issue:
                    issue_data = {
                        "number": issue.get("number", 0),
                        "title": issue.get("title", ""),
                        "state": issue.get("state", ""),
                        "user": {
                            "login": issue.get("user", {}).get("login", ""),
                            "type": issue.get("user", {}).get("type", "")
                        } if issue.get("user") else {},
                        "assignees": [a.get("login", "") for a in issue.get("assignees", [])],
                        "labels": [l.get("name", "") for l in issue.get("labels", [])],
                        "closed_at": issue.get("closed_at", ""),
                        "created_at": issue.get("created_at", ""),
                        "body": issue.get("body", "")[:500] if issue.get("body") else ""
                    }
                    analysis["issues"]["closed"].append(issue_data)
                    analysis["issues"]["total"] += 1
        except Exception as e:
            analysis["errors"].append(f"Closed issues: {str(e)}")
        
        # Get open pull requests
        try:
            open_prs = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/pulls",
                params={"state": "open", "per_page": 100}
            )
            for pr in open_prs[:max_items]:
                pr_data = {
                    "number": pr.get("number", 0),
                    "title": pr.get("title", ""),
                    "state": pr.get("state", ""),
                    "user": {
                        "login": pr.get("user", {}).get("login", ""),
                        "type": pr.get("user", {}).get("type", "")
                    } if pr.get("user") else {},
                    "head": {
                        "ref": pr.get("head", {}).get("ref", ""),
                        "sha": pr.get("head", {}).get("sha", "")
                    } if pr.get("head") else {},
                    "base": {
                        "ref": pr.get("base", {}).get("ref", ""),
                        "sha": pr.get("base", {}).get("sha", "")
                    } if pr.get("base") else {},
                    "draft": pr.get("draft", False),
                    "merged": pr.get("merged", False),
                    "mergeable": pr.get("mergeable"),
                    "mergeable_state": pr.get("mergeable_state", ""),
                    "additions": pr.get("additions", 0),
                    "deletions": pr.get("deletions", 0),
                    "changed_files": pr.get("changed_files", 0),
                    "commits": pr.get("commits", 0),
                    "comments": pr.get("comments", 0),
                    "review_comments": pr.get("review_comments", 0),
                    "requested_reviewers": [r.get("login", "") for r in pr.get("requested_reviewers", [])],
                    "labels": [l.get("name", "") for l in pr.get("labels", [])],
                    "created_at": pr.get("created_at", ""),
                    "updated_at": pr.get("updated_at", ""),
                    "body": pr.get("body", "")[:500] if pr.get("body") else ""
                }
                analysis["pull_requests"]["open"].append(pr_data)
                analysis["pull_requests"]["total"] += 1
        except Exception as e:
            analysis["errors"].append(f"Open PRs: {str(e)}")
        
        # Get closed/merged pull requests
        try:
            closed_prs = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/pulls",
                params={"state": "closed", "per_page": 100}
            )
            for pr in closed_prs[:max_items]:
                pr_data = {
                    "number": pr.get("number", 0),
                    "title": pr.get("title", ""),
                    "state": pr.get("state", ""),
                    "merged": pr.get("merged", False),
                    "merged_at": pr.get("merged_at", ""),
                    "closed_at": pr.get("closed_at", ""),
                    "user": {
                        "login": pr.get("user", {}).get("login", ""),
                        "type": pr.get("user", {}).get("type", "")
                    } if pr.get("user") else {},
                    "merged_by": {
                        "login": pr.get("merged_by", {}).get("login", "")
                    } if pr.get("merged_by") else {},
                    "additions": pr.get("additions", 0),
                    "deletions": pr.get("deletions", 0),
                    "changed_files": pr.get("changed_files", 0),
                    "created_at": pr.get("created_at", "")
                }
                if pr_data["merged"]:
                    analysis["pull_requests"]["merged"].append(pr_data)
                else:
                    analysis["pull_requests"]["closed"].append(pr_data)
                analysis["pull_requests"]["total"] += 1
        except Exception as e:
            analysis["errors"].append(f"Closed PRs: {str(e)}")
        
        # Get repository labels
        try:
            labels = self.api_client.get_paginated(f"/repos/{repo_full_name}/labels")
            analysis["labels"] = [
                {
                    "name": l.get("name", ""),
                    "color": l.get("color", ""),
                    "description": l.get("description", ""),
                    "default": l.get("default", False)
                }
                for l in labels
            ]
        except Exception:
            pass
        
        # Get repository milestones
        try:
            milestones = self.api_client.get_paginated(f"/repos/{repo_full_name}/milestones")
            analysis["milestones"] = [
                {
                    "number": m.get("number", 0),
                    "title": m.get("title", ""),
                    "description": m.get("description", ""),
                    "state": m.get("state", ""),
                    "open_issues": m.get("open_issues", 0),
                    "closed_issues": m.get("closed_issues", 0),
                    "due_on": m.get("due_on", "")
                }
                for m in milestones
            ]
        except Exception:
            pass
        
        # Collect unique assignees and reviewers
        all_assignees = set()
        all_reviewers = set()
        
        for issue in analysis["issues"]["open"] + analysis["issues"]["closed"]:
            all_assignees.update(issue.get("assignees", []))
        
        for pr in analysis["pull_requests"]["open"] + analysis["pull_requests"]["closed"] + analysis["pull_requests"]["merged"]:
            all_reviewers.update(pr.get("requested_reviewers", []))
        
        analysis["assignees"] = list(all_assignees)
        analysis["reviewers"] = list(all_reviewers)
        
        return analysis
    
    def analyze_org_issues_prs(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze issues and PRs across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide issues/PRs analysis
        """
        org_analysis = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_open_issues": 0,
                "total_closed_issues": 0,
                "total_open_prs": 0,
                "total_merged_prs": 0,
                "total_closed_prs": 0,
                "total_labels": 0,
                "total_milestones": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_analysis = self.analyze_repo_issues_prs(repo_full_name, max_items=30)
                        org_analysis["repositories"][repo_full_name] = repo_analysis
                        
                        # Update summary
                        org_analysis["summary"]["total_repos_analyzed"] += 1
                        org_analysis["summary"]["total_open_issues"] += len(repo_analysis["issues"]["open"])
                        org_analysis["summary"]["total_closed_issues"] += len(repo_analysis["issues"]["closed"])
                        org_analysis["summary"]["total_open_prs"] += len(repo_analysis["pull_requests"]["open"])
                        org_analysis["summary"]["total_merged_prs"] += len(repo_analysis["pull_requests"]["merged"])
                        org_analysis["summary"]["total_closed_prs"] += len(repo_analysis["pull_requests"]["closed"])
                        org_analysis["summary"]["total_labels"] += len(repo_analysis["labels"])
                        org_analysis["summary"]["total_milestones"] += len(repo_analysis["milestones"])
                    except Exception as e:
                        org_analysis["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_analysis["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_analysis

