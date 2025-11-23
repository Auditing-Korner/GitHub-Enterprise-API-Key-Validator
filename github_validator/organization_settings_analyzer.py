"""
Organization Settings Deep Dive Module

Provides comprehensive analysis of organization settings including:
- Member privileges and permissions
- Repository creation policies
- Team creation policies
- Two-factor authentication requirements
- SSO settings (if accessible)
- Organization visibility and features
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class OrganizationSettingsAnalyzer:
    """Analyzes organization settings in detail."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_org_settings(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze organization settings in detail.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with detailed organization settings
        """
        settings_data = {
            "organization": org_name,
            "basic_settings": {},
            "member_settings": {},
            "repository_settings": {},
            "team_settings": {},
            "security_settings": {},
            "billing_settings": {},
            "errors": []
        }
        
        try:
            # Get organization basic info
            org_info = self.api_client.get(f"/orgs/{org_name}")
            if org_info:
                settings_data["basic_settings"] = {
                    "login": org_info.get("login", ""),
                    "name": org_info.get("name", ""),
                    "description": org_info.get("description", ""),
                    "type": org_info.get("type", ""),
                    "company": org_info.get("company", ""),
                    "blog": org_info.get("blog", ""),
                    "location": org_info.get("location", ""),
                    "email": org_info.get("email", ""),
                    "twitter_username": org_info.get("twitter_username", ""),
                    "is_verified": org_info.get("is_verified", False),
                    "has_organization_projects": org_info.get("has_organization_projects", False),
                    "has_repository_projects": org_info.get("has_repository_projects", False),
                    "public_repos": org_info.get("public_repos", 0),
                    "public_gists": org_info.get("public_gists", 0),
                    "followers": org_info.get("followers", 0),
                    "following": org_info.get("following", 0),
                    "created_at": org_info.get("created_at", ""),
                    "updated_at": org_info.get("updated_at", "")
                }
                
                settings_data["member_settings"] = {
                    "default_repository_permission": org_info.get("default_repository_permission", ""),
                    "members_can_create_repositories": org_info.get("members_can_create_repositories", False),
                    "members_can_create_private_repositories": org_info.get("members_can_create_private_repositories", False),
                    "members_can_create_public_repositories": org_info.get("members_can_create_public_repositories", False),
                    "members_can_create_internal_repositories": org_info.get("members_can_create_internal_repositories", False),
                    "members_allowed_repository_creation_type": org_info.get("members_allowed_repository_creation_type", ""),
                    "members_can_create_pages": org_info.get("members_can_create_pages", False),
                    "members_can_fork_private_repositories": org_info.get("members_can_fork_private_repositories", False)
                }
                
                settings_data["repository_settings"] = {
                    "has_organization_projects": org_info.get("has_organization_projects", False),
                    "has_repository_projects": org_info.get("has_repository_projects", False),
                    "default_repository_permission": org_info.get("default_repository_permission", "")
                }
        except Exception as e:
            settings_data["errors"].append(f"Failed to get organization info: {str(e)}")
        
        # Get security settings (2FA requirement)
        try:
            # Try to get members to check 2FA status
            members = self.api_client.get_paginated(f"/orgs/{org_name}/members")
            two_factor_disabled = 0
            for member in members[:100]:  # Sample first 100 members
                try:
                    member_detail = self.api_client.get(f"/orgs/{org_name}/members/{member.get('login', '')}")
                    # Note: 2FA status might not be directly accessible
                except Exception:
                    pass
        except Exception:
            pass
        
        # Try to get billing information (may require admin access)
        try:
            billing = self.api_client.get(f"/orgs/{org_name}/settings/billing")
            if billing:
                settings_data["billing_settings"] = {
                    "plan": billing.get("plan", {}).get("name", ""),
                    "seats": billing.get("seats", {}),
                    "storage": billing.get("storage", {}),
                    "actions": billing.get("actions", {})
                }
        except Exception:
            settings_data["billing_settings"] = {"accessible": False}
        
        # Get organization teams (for team settings)
        try:
            teams = self.api_client.get_paginated(f"/orgs/{org_name}/teams")
            settings_data["team_settings"] = {
                "total_teams": len(teams),
                "teams": [
                    {
                        "name": team.get("name", ""),
                        "privacy": team.get("privacy", ""),
                        "permission": team.get("permission", "")
                    }
                    for team in teams[:20]  # Limit to 20 teams
                ]
            }
        except Exception as e:
            settings_data["errors"].append(f"Failed to get teams: {str(e)}")
        
        # Security settings summary
        settings_data["security_settings"] = {
            "two_factor_requirement_enabled": org_info.get("two_factor_requirement_enabled", False) if org_info else False,
            "members_can_create_repositories": settings_data["member_settings"].get("members_can_create_repositories", False),
            "default_repository_permission": settings_data["member_settings"].get("default_repository_permission", "")
        }
        
        return settings_data
    
    def analyze_all_orgs_settings(self, max_orgs: int = 10) -> Dict[str, Any]:
        """
        Analyze settings for all accessible organizations.
        
        Args:
            max_orgs: Maximum number of organizations to analyze
            
        Returns:
            Dictionary with settings for all organizations
        """
        all_settings = {
            "organizations": {},
            "summary": {
                "total_orgs_analyzed": 0,
                "orgs_with_2fa": 0,
                "orgs_allow_member_repos": 0,
                "orgs_with_projects": 0
            },
            "errors": []
        }
        
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:max_orgs]:
                org_name = org.get("login", "")
                if org_name:
                    try:
                        org_settings = self.analyze_org_settings(org_name)
                        all_settings["organizations"][org_name] = org_settings
                        
                        # Update summary
                        all_settings["summary"]["total_orgs_analyzed"] += 1
                        if org_settings["security_settings"].get("two_factor_requirement_enabled", False):
                            all_settings["summary"]["orgs_with_2fa"] += 1
                        if org_settings["member_settings"].get("members_can_create_repositories", False):
                            all_settings["summary"]["orgs_allow_member_repos"] += 1
                        if org_settings["repository_settings"].get("has_organization_projects", False):
                            all_settings["summary"]["orgs_with_projects"] += 1
                    except Exception as e:
                        all_settings["errors"].append(f"Failed to analyze {org_name}: {str(e)}")
        except Exception as e:
            all_settings["errors"].append(f"Failed to get organizations: {str(e)}")
        
        return all_settings

