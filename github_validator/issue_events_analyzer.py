"""
Issue Events/Timeline Analysis Module

Analyzes issue events and timeline including:
- Issue timeline events
- Event types and actors
- State change history
"""

from typing import Dict, List, Optional, Any
from collections import Counter
from .api_client import GitHubAPIClient


class IssueEventsAnalyzer:
    """Analyzes issue events and timeline."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_issue_events(self, repo_full_name: str, max_issues: int = 50) -> Dict[str, Any]:
        """
        Analyze issue events for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_issues: Maximum number of issues to analyze
            
        Returns:
            Dictionary with issue events analysis
        """
        events_data = {
            "repository": repo_full_name,
            "issues": [],
            "summary": {
                "total_issues_analyzed": 0,
                "total_events": 0,
                "event_types": Counter(),
                "actors": set()
            },
            "errors": []
        }
        
        try:
            # Get issues
            issues = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/issues",
                params={"state": "all", "per_page": 100}
            )
            
            for issue in issues[:max_issues]:
                issue_number = issue.get("number", "")
                is_pr = "pull_request" in issue
                
                # Get events for this issue
                try:
                    events = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/issues/{issue_number}/events"
                    )
                    
                    if events:
                        issue_info = {
                            "number": issue_number,
                            "title": issue.get("title", "")[:100],
                            "is_pr": is_pr,
                            "state": issue.get("state", ""),
                            "events": [],
                            "total_events": len(events)
                        }
                        
                        for event in events:
                            event_info = {
                                "id": event.get("id", ""),
                                "event": event.get("event", ""),  # closed, reopened, labeled, etc.
                                "actor": {
                                    "login": event.get("actor", {}).get("login", ""),
                                    "id": event.get("actor", {}).get("id", "")
                                } if event.get("actor") else {},
                                "created_at": event.get("created_at", ""),
                                "commit_id": event.get("commit_id", "")
                            }
                            issue_info["events"].append(event_info)
                            
                            events_data["summary"]["event_types"][event_info["event"]] += 1
                            if event_info["actor"].get("login"):
                                events_data["summary"]["actors"].add(event_info["actor"]["login"])
                        
                        events_data["issues"].append(issue_info)
                        events_data["summary"]["total_events"] += len(events)
                except Exception as e:
                    events_data["errors"].append(f"Failed to get events for issue #{issue_number}: {str(e)}")
                
                events_data["summary"]["total_issues_analyzed"] += 1
        except Exception as e:
            events_data["errors"].append(f"Failed to get issues: {str(e)}")
        
        # Convert Counter to dict and set to list
        events_data["summary"]["event_types"] = dict(events_data["summary"]["event_types"])
        events_data["summary"]["actors"] = list(events_data["summary"]["actors"])
        
        return events_data
    
    def analyze_org_issue_events(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze issue events across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide issue events analysis
        """
        org_events = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_events": 0,
                "event_types": Counter(),
                "unique_actors": set()
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_events = self.analyze_repo_issue_events(repo_full_name, max_issues=30)
                        org_events["repositories"][repo_full_name] = repo_events
                        
                        # Update summary
                        org_events["summary"]["total_repos_analyzed"] += 1
                        org_events["summary"]["total_events"] += repo_events["summary"]["total_events"]
                        org_events["summary"]["event_types"].update(repo_events["summary"]["event_types"])
                        org_events["summary"]["unique_actors"].update(repo_events["summary"]["actors"])
                    except Exception as e:
                        org_events["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_events["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert Counter to dict and set to list
        org_events["summary"]["event_types"] = dict(org_events["summary"]["event_types"])
        org_events["summary"]["unique_actors"] = len(org_events["summary"]["unique_actors"])
        
        return org_events

