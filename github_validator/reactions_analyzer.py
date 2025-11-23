"""
Reactions Analysis Module

Analyzes reactions including:
- Issue reactions
- PR reactions
- Comment reactions
- Reaction patterns
"""

from typing import Dict, List, Optional, Any
from collections import Counter
from .api_client import GitHubAPIClient


class ReactionsAnalyzer:
    """Analyzes reactions on issues, PRs, and comments."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_reactions(self, repo_full_name: str, max_items: int = 50) -> Dict[str, Any]:
        """
        Analyze reactions for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_items: Maximum number of issues/PRs to analyze
            
        Returns:
            Dictionary with reactions analysis
        """
        reactions_data = {
            "repository": repo_full_name,
            "issues_reactions": [],
            "prs_reactions": [],
            "summary": {
                "total_issues_analyzed": 0,
                "total_prs_analyzed": 0,
                "total_reactions": 0,
                "reaction_types": Counter(),
                "most_reacted_items": []
            },
            "errors": []
        }
        
        try:
            # Get issues with reactions
            issues = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/issues",
                params={"state": "all", "per_page": 100}
            )
            
            for issue in issues[:max_items]:
                issue_number = issue.get("number", "")
                is_pr = "pull_request" in issue
                
                # Get reactions for this issue/PR
                try:
                    reactions = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/issues/{issue_number}/reactions"
                    )
                    
                    reaction_summary = {
                        "number": issue_number,
                        "title": issue.get("title", "")[:100],
                        "is_pr": is_pr,
                        "total_reactions": len(reactions),
                        "reactions": Counter()
                    }
                    
                    for reaction in reactions:
                        reaction_type = reaction.get("content", "")  # +1, -1, laugh, hooray, confused, heart, rocket, eyes
                        reaction_summary["reactions"][reaction_type] += 1
                        reactions_data["summary"]["reaction_types"][reaction_type] += 1
                    
                    reactions_data["summary"]["total_reactions"] += reaction_summary["total_reactions"]
                    
                    if is_pr:
                        reactions_data["prs_reactions"].append(reaction_summary)
                        reactions_data["summary"]["total_prs_analyzed"] += 1
                    else:
                        reactions_data["issues_reactions"].append(reaction_summary)
                        reactions_data["summary"]["total_issues_analyzed"] += 1
                    
                    # Track most reacted items
                    if reaction_summary["total_reactions"] > 0:
                        reactions_data["summary"]["most_reacted_items"].append({
                            "number": issue_number,
                            "title": issue.get("title", "")[:100],
                            "is_pr": is_pr,
                            "reactions": reaction_summary["total_reactions"]
                        })
                except Exception as e:
                    reactions_data["errors"].append(f"Failed to get reactions for issue #{issue_number}: {str(e)}")
        except Exception as e:
            reactions_data["errors"].append(f"Failed to get issues: {str(e)}")
        
        # Sort most reacted items
        reactions_data["summary"]["most_reacted_items"].sort(key=lambda x: x["reactions"], reverse=True)
        reactions_data["summary"]["most_reacted_items"] = reactions_data["summary"]["most_reacted_items"][:20]  # Top 20
        
        # Convert Counter to dict for JSON serialization
        reactions_data["summary"]["reaction_types"] = dict(reactions_data["summary"]["reaction_types"])
        
        return reactions_data
    
    def analyze_org_reactions(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze reactions across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide reactions analysis
        """
        org_reactions = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_reactions": 0,
                "reaction_types": Counter()
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_reactions = self.analyze_repo_reactions(repo_full_name, max_items=30)
                        org_reactions["repositories"][repo_full_name] = repo_reactions
                        
                        # Update summary
                        org_reactions["summary"]["total_repos_analyzed"] += 1
                        org_reactions["summary"]["total_reactions"] += repo_reactions["summary"]["total_reactions"]
                        org_reactions["summary"]["reaction_types"].update(repo_reactions["summary"]["reaction_types"])
                    except Exception as e:
                        org_reactions["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_reactions["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert Counter to dict
        org_reactions["summary"]["reaction_types"] = dict(org_reactions["summary"]["reaction_types"])
        
        return org_reactions

