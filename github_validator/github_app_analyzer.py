"""
GitHub App Analysis Module

Analyzes GitHub Apps including:
- Installed GitHub Apps
- App permissions and access
- App installations
- App repositories
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class GitHubAppAnalyzer:
    """Analyzes GitHub Apps and installations."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_user_installations(self) -> Dict[str, Any]:
        """
        Analyze GitHub Apps installed for the user.
        
        Returns:
            Dictionary with installations analysis
        """
        installations_data = {
            "installations": [],
            "summary": {
                "total_installations": 0,
                "app_names": [],
                "target_types": {}
            },
            "errors": []
        }
        
        try:
            installations = self.api_client.get_paginated("/user/installations")
            
            for installation in installations:
                app = installation.get("app", {})
                
                installation_info = {
                    "id": installation.get("id", ""),
                    "app": {
                        "id": app.get("id", ""),
                        "slug": app.get("slug", ""),
                        "name": app.get("name", ""),
                        "description": app.get("description", "")
                    } if app else {},
                    "target_type": installation.get("target_type", ""),
                    "target": {
                        "login": installation.get("account", {}).get("login", ""),
                        "type": installation.get("account", {}).get("type", "")
                    } if installation.get("account") else {},
                    "permissions": installation.get("permissions", {}),
                    "created_at": installation.get("created_at", ""),
                    "updated_at": installation.get("updated_at", "")
                }
                
                # Get installation repositories
                try:
                    repos = self.api_client.get_paginated(
                        f"/user/installations/{installation.get('id')}/repositories"
                    )
                    installation_info["repositories"] = [
                        {
                            "full_name": r.get("full_name", ""),
                            "id": r.get("id", ""),
                            "private": r.get("private", False)
                        }
                        for r in repos
                    ]
                except Exception:
                    installation_info["repositories"] = []
                
                installations_data["installations"].append(installation_info)
                
                # Update summary
                installations_data["summary"]["total_installations"] += 1
                
                app_name = installation_info.get("app", {}).get("name", "")
                if app_name:
                    installations_data["summary"]["app_names"].append(app_name)
                
                target_type = installation_info.get("target_type", "unknown")
                installations_data["summary"]["target_types"][target_type] = installations_data["summary"]["target_types"].get(target_type, 0) + 1
        except Exception as e:
            installations_data["errors"].append(f"Failed to get installations: {str(e)}")
        
        return installations_data
    
    def analyze_org_installations(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze GitHub Apps installed for an organization.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with organization installations analysis
        """
        org_installations = {
            "organization": org_name,
            "installations": [],
            "summary": {
                "total_installations": 0,
                "app_names": []
            },
            "errors": []
        }
        
        try:
            installations = self.api_client.get_paginated(f"/orgs/{org_name}/installations")
            
            for installation in installations:
                app = installation.get("app", {})
                
                installation_info = {
                    "id": installation.get("id", ""),
                    "app": {
                        "id": app.get("id", ""),
                        "slug": app.get("slug", ""),
                        "name": app.get("name", "")
                    } if app else {},
                    "permissions": installation.get("permissions", {}),
                    "created_at": installation.get("created_at", "")
                }
                
                org_installations["installations"].append(installation_info)
                org_installations["summary"]["total_installations"] += 1
                
                app_name = installation_info.get("app", {}).get("name", "")
                if app_name:
                    org_installations["summary"]["app_names"].append(app_name)
        except Exception as e:
            org_installations["errors"].append(f"Failed to get org installations: {str(e)}")
        
        return org_installations

