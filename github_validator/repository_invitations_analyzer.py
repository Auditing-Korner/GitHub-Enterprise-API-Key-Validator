"""
Repository Invitations Analysis Module

Analyzes repository invitations including:
- Pending invitations
- Invitation history
- Invitation permissions
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class RepositoryInvitationsAnalyzer:
    """Analyzes repository invitations."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_invitations(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze invitations for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with invitations analysis
        """
        invitations_data = {
            "repository": repo_full_name,
            "pending_invitations": [],
            "summary": {
                "total_pending": 0,
                "invitation_permissions": {}
            },
            "errors": []
        }
        
        try:
            # Get pending invitations
            invitations = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/invitations"
            )
            
            for invitation in invitations:
                invitation_info = {
                    "id": invitation.get("id", ""),
                    "invitee": {
                        "login": invitation.get("invitee", {}).get("login", ""),
                        "id": invitation.get("invitee", {}).get("id", ""),
                        "type": invitation.get("invitee", {}).get("type", "")
                    } if invitation.get("invitee") else {},
                    "inviter": {
                        "login": invitation.get("inviter", {}).get("login", ""),
                        "id": invitation.get("inviter", {}).get("id", "")
                    } if invitation.get("inviter") else {},
                    "permissions": invitation.get("permissions", ""),
                    "created_at": invitation.get("created_at", ""),
                    "expires_at": invitation.get("expires_at", "")
                }
                
                invitations_data["pending_invitations"].append(invitation_info)
                invitations_data["summary"]["total_pending"] += 1
                
                # Track permissions
                permission = invitation_info["permissions"]
                invitations_data["summary"]["invitation_permissions"][permission] = invitations_data["summary"]["invitation_permissions"].get(permission, 0) + 1
        except Exception as e:
            invitations_data["errors"].append(f"Failed to get invitations: {str(e)}")
        
        return invitations_data
    
    def analyze_org_repo_invitations(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze invitations across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide invitations analysis
        """
        org_invitations = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_pending_invitations": 0,
                "repos_with_invitations": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_invitations = self.analyze_repo_invitations(repo_full_name)
                        org_invitations["repositories"][repo_full_name] = repo_invitations
                        
                        # Update summary
                        org_invitations["summary"]["total_repos_analyzed"] += 1
                        org_invitations["summary"]["total_pending_invitations"] += repo_invitations["summary"]["total_pending"]
                        
                        if repo_invitations["summary"]["total_pending"] > 0:
                            org_invitations["summary"]["repos_with_invitations"] += 1
                    except Exception as e:
                        org_invitations["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_invitations["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_invitations

