"""
OAuth App Analysis Module

Analyzes OAuth applications including:
- Authorized OAuth apps
- OAuth app permissions and scopes
- OAuth app usage
- OAuth app tokens
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class OAuthAppAnalyzer:
    """Analyzes OAuth applications and authorizations."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_authorized_apps(self) -> Dict[str, Any]:
        """
        Analyze authorized OAuth applications.
        
        Returns:
            Dictionary with authorized apps analysis
        """
        apps_data = {
            "authorized_applications": [],
            "summary": {
                "total_apps": 0,
                "app_scopes": set(),
                "app_names": []
            },
            "errors": []
        }
        
        try:
            apps = self.api_client.get_paginated("/user/authorizations")
            
            for app in apps:
                app_info = {
                    "id": app.get("id", ""),
                    "app": {
                        "name": app.get("app", {}).get("name", ""),
                        "url": app.get("app", {}).get("url", ""),
                        "client_id": app.get("app", {}).get("client_id", "")
                    } if app.get("app") else {},
                    "scopes": app.get("scopes", []),
                    "token": app.get("token", "")[:10] + "..." if app.get("token") else None,  # Partial token
                    "token_last_eight": app.get("token_last_eight", ""),
                    "hashed_token": app.get("hashed_token", ""),
                    "note": app.get("note", ""),
                    "note_url": app.get("note_url", ""),
                    "updated_at": app.get("updated_at", ""),
                    "created_at": app.get("created_at", ""),
                    "fingerprint": app.get("fingerprint", "")
                }
                
                apps_data["authorized_applications"].append(app_info)
                
                # Update summary
                apps_data["summary"]["total_apps"] += 1
                for scope in app_info.get("scopes", []):
                    apps_data["summary"]["app_scopes"].add(scope)
                
                app_name = app_info.get("app", {}).get("name", "")
                if app_name:
                    apps_data["summary"]["app_names"].append(app_name)
        except Exception as e:
            apps_data["errors"].append(f"Failed to get authorized apps: {str(e)}")
        
        # Convert set to list
        apps_data["summary"]["app_scopes"] = list(apps_data["summary"]["app_scopes"])
        
        return apps_data
    
    def analyze_org_oauth_apps(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze organization OAuth applications.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with organization OAuth apps analysis
        """
        org_apps = {
            "organization": org_name,
            "oauth_applications": [],
            "summary": {
                "total_apps": 0,
                "app_names": []
            },
            "errors": []
        }
        
        try:
            apps = self.api_client.get_paginated(f"/orgs/{org_name}/oauth-applications")
            
            for app in apps:
                app_info = {
                    "id": app.get("id", ""),
                    "name": app.get("name", ""),
                    "url": app.get("url", ""),
                    "client_id": app.get("client_id", ""),
                    "description": app.get("description", ""),
                    "created_at": app.get("created_at", ""),
                    "updated_at": app.get("updated_at", "")
                }
                
                org_apps["oauth_applications"].append(app_info)
                org_apps["summary"]["total_apps"] += 1
                org_apps["summary"]["app_names"].append(app_info["name"])
        except Exception as e:
            org_apps["errors"].append(f"Failed to get org OAuth apps: {str(e)}")
        
        return org_apps

