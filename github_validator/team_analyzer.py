"""
Team Analysis Module

Analyzes organization teams including:
- Team members and permissions
- Team repositories and access levels
- Team organization structure
- Team settings and configurations
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class TeamAnalyzer:
    """Analyzes organization teams and team permissions."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_org_teams(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze all teams in an organization.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with team analysis
        """
        team_data = {
            "organization": org_name,
            "teams": [],
            "summary": {
                "total_teams": 0,
                "total_members": 0,
                "total_repositories": 0,
                "team_permissions": {}
            },
            "errors": []
        }
        
        try:
            teams = self.api_client.get_paginated(f"/orgs/{org_name}/teams")
            
            for team in teams:
                team_slug = team.get("slug", "")
                team_id = team.get("id", "")
                
                team_info = {
                    "id": team_id,
                    "name": team.get("name", ""),
                    "slug": team_slug,
                    "description": team.get("description", ""),
                    "privacy": team.get("privacy", ""),
                    "permission": team.get("permission", ""),
                    "members_count": team.get("members_count", 0),
                    "repos_count": team.get("repos_count", 0)
                }
                
                # Get team members
                try:
                    members = self.api_client.get_paginated(f"/orgs/{org_name}/teams/{team_slug}/members")
                    team_info["members"] = [
                        {
                            "login": m.get("login", ""),
                            "id": m.get("id", ""),
                            "type": m.get("type", ""),
                            "role": m.get("role", "")
                        }
                        for m in members
                    ]
                    team_data["summary"]["total_members"] += len(team_info["members"])
                except Exception:
                    team_info["members"] = []
                
                # Get team repositories
                try:
                    repos = self.api_client.get_paginated(f"/orgs/{org_name}/teams/{team_slug}/repos")
                    team_info["repositories"] = [
                        {
                            "full_name": r.get("full_name", ""),
                            "permissions": r.get("permissions", {}),
                            "role_name": r.get("role_name", "")
                        }
                        for r in repos
                    ]
                    team_data["summary"]["total_repositories"] += len(team_info["repositories"])
                except Exception:
                    team_info["repositories"] = []
                
                # Get team projects (if accessible)
                try:
                    projects = self.api_client.get_paginated(f"/orgs/{org_name}/teams/{team_slug}/projects")
                    team_info["projects"] = [
                        {
                            "id": p.get("id", ""),
                            "name": p.get("name", ""),
                            "body": p.get("body", "")
                        }
                        for p in projects[:20]  # Limit to 20
                    ]
                except Exception:
                    team_info["projects"] = []
                
                team_data["teams"].append(team_info)
                team_data["summary"]["total_teams"] += 1
                
                # Track permissions
                permission = team_info.get("permission", "unknown")
                team_data["summary"]["team_permissions"][permission] = team_data["summary"]["team_permissions"].get(permission, 0) + 1
        except Exception as e:
            team_data["errors"].append(f"Failed to get teams: {str(e)}")
        
        return team_data
    
    def analyze_team_permissions(self, org_name: str, team_slug: str) -> Dict[str, Any]:
        """
        Analyze detailed permissions for a specific team.
        
        Args:
            org_name: Organization name
            team_slug: Team slug
            
        Returns:
            Dictionary with detailed team permissions
        """
        permissions = {
            "organization": org_name,
            "team": team_slug,
            "repositories": [],
            "members": [],
            "permissions_summary": {},
            "errors": []
        }
        
        try:
            # Get team repositories with permissions
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/teams/{team_slug}/repos")
            for repo in repos:
                repo_perms = {
                    "full_name": repo.get("full_name", ""),
                    "permissions": repo.get("permissions", {}),
                    "role_name": repo.get("role_name", ""),
                    "admin": repo.get("permissions", {}).get("admin", False),
                    "push": repo.get("permissions", {}).get("push", False),
                    "pull": repo.get("permissions", {}).get("pull", False)
                }
                permissions["repositories"].append(repo_perms)
                
                # Track permission distribution
                if repo_perms["admin"]:
                    permissions["permissions_summary"]["admin"] = permissions["permissions_summary"].get("admin", 0) + 1
                elif repo_perms["push"]:
                    permissions["permissions_summary"]["push"] = permissions["permissions_summary"].get("push", 0) + 1
                else:
                    permissions["permissions_summary"]["pull"] = permissions["permissions_summary"].get("pull", 0) + 1
        except Exception as e:
            permissions["errors"].append(f"Failed to get team repositories: {str(e)}")
        
        try:
            # Get team members
            members = self.api_client.get_paginated(f"/orgs/{org_name}/teams/{team_slug}/members")
            permissions["members"] = [
                {
                    "login": m.get("login", ""),
                    "id": m.get("id", ""),
                    "role": m.get("role", "")
                }
                for m in members
            ]
        except Exception as e:
            permissions["errors"].append(f"Failed to get team members: {str(e)}")
        
        return permissions

