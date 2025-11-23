"""
Codespaces Detection Module

Detects and analyzes GitHub Codespaces:
- Active and stopped codespaces
- Codespace secrets and variables
- Codespace billing and usage
- Codespace machine types and permissions
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class CodespacesDetector:
    """Detects and analyzes GitHub Codespaces."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def detect_user_codespaces(self) -> Dict[str, Any]:
        """
        Detect all user codespaces.
        
        Returns:
            Dictionary with codespaces information
        """
        codespaces_data = {
            "codespaces": [],
            "secrets": [],
            "variables": [],
            "usage": {},
            "errors": []
        }
        
        # Get user codespaces
        try:
            codespaces_response = self.api_client.get("/user/codespaces")
            if codespaces_response and codespaces_response.get("codespaces"):
                for cs in codespaces_response.get("codespaces", []):
                    codespace_data = {
                        "id": cs.get("id", ""),
                        "name": cs.get("name", ""),
                        "display_name": cs.get("display_name", ""),
                        "repository": {
                            "id": cs.get("repository", {}).get("id", ""),
                            "full_name": cs.get("repository", {}).get("full_name", ""),
                            "name": cs.get("repository", {}).get("name", "")
                        } if cs.get("repository") else {},
                        "machine": {
                            "name": cs.get("machine", {}).get("name", ""),
                            "display_name": cs.get("machine", {}).get("display_name", "")
                        } if cs.get("machine") else {},
                        "prebuild": cs.get("prebuild", False),
                        "state": cs.get("state", ""),
                        "web_url": cs.get("web_url", ""),
                        "created_at": cs.get("created_at", ""),
                        "updated_at": cs.get("updated_at", ""),
                        "last_used_at": cs.get("last_used_at", ""),
                        "git_status": {
                            "ahead": cs.get("git_status", {}).get("ahead", 0),
                            "behind": cs.get("git_status", {}).get("behind", 0),
                            "has_uncommitted_changes": cs.get("git_status", {}).get("has_uncommitted_changes", False),
                            "has_unpushed_changes": cs.get("git_status", {}).get("has_unpushed_changes", False),
                            "ref": cs.get("git_status", {}).get("ref", "")
                        } if cs.get("git_status") else {}
                    }
                    codespaces_data["codespaces"].append(codespace_data)
        except Exception as e:
            codespaces_data["errors"].append(f"Failed to get codespaces: {str(e)}")
        
        # Get codespace secrets
        try:
            secrets = self.api_client.get_paginated("/user/codespaces/secrets")
            codespaces_data["secrets"] = [
                {
                    "name": s.get("name", ""),
                    "created_at": s.get("created_at", ""),
                    "updated_at": s.get("updated_at", ""),
                    "visibility": s.get("visibility", ""),
                    "selected_repositories_url": s.get("selected_repositories_url", "")
                }
                for s in secrets
            ]
        except Exception:
            pass
        
        # Get codespace variables
        try:
            variables = self.api_client.get_paginated("/user/codespaces/variables")
            codespaces_data["variables"] = [
                {
                    "name": v.get("name", ""),
                    "value": v.get("value", ""),  # May be empty if no access
                    "created_at": v.get("created_at", ""),
                    "updated_at": v.get("updated_at", ""),
                    "visibility": v.get("visibility", ""),
                    "selected_repositories_url": v.get("selected_repositories_url", "")
                }
                for v in variables
            ]
        except Exception:
            pass
        
        # Calculate usage statistics
        active_codespaces = [cs for cs in codespaces_data["codespaces"] if cs.get("state") == "Available"]
        stopped_codespaces = [cs for cs in codespaces_data["codespaces"] if cs.get("state") == "Shutdown"]
        
        codespaces_data["usage"] = {
            "total": len(codespaces_data["codespaces"]),
            "active": len(active_codespaces),
            "stopped": len(stopped_codespaces),
            "total_secrets": len(codespaces_data["secrets"]),
            "total_variables": len(codespaces_data["variables"]),
            "repositories_with_codespaces": len(set(
                cs.get("repository", {}).get("full_name", "") 
                for cs in codespaces_data["codespaces"] 
                if cs.get("repository", {}).get("full_name", "")
            ))
        }
        
        return codespaces_data
    
    def detect_org_codespaces(self, org_name: str) -> Dict[str, Any]:
        """
        Detect organization codespaces.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with organization codespaces information
        """
        org_codespaces = {
            "organization": org_name,
            "secrets": [],
            "variables": [],
            "usage": {},
            "errors": []
        }
        
        # Get organization codespace secrets
        try:
            secrets = self.api_client.get_paginated(f"/orgs/{org_name}/codespaces/secrets")
            org_codespaces["secrets"] = [
                {
                    "name": s.get("name", ""),
                    "created_at": s.get("created_at", ""),
                    "updated_at": s.get("updated_at", ""),
                    "visibility": s.get("visibility", ""),
                    "selected_repositories_url": s.get("selected_repositories_url", "")
                }
                for s in secrets
            ]
        except Exception:
            pass
        
        # Get organization codespace variables
        try:
            variables = self.api_client.get_paginated(f"/orgs/{org_name}/codespaces/variables")
            org_codespaces["variables"] = [
                {
                    "name": v.get("name", ""),
                    "value": v.get("value", ""),
                    "created_at": v.get("created_at", ""),
                    "updated_at": v.get("updated_at", ""),
                    "visibility": v.get("visibility", ""),
                    "selected_repositories_url": v.get("selected_repositories_url", "")
                }
                for v in variables
            ]
        except Exception:
            pass
        
        # Get organization codespace billing (if accessible)
        try:
            billing = self.api_client.get(f"/orgs/{org_name}/codespaces/billing")
            if billing:
                org_codespaces["billing"] = {
                    "total_used_minutes": billing.get("total_used_minutes", 0),
                    "total_paid_minutes_used": billing.get("total_paid_minutes_used", 0),
                    "minutes_used_breakdown": billing.get("minutes_used_breakdown", {}),
                    "skus": billing.get("skus", [])
                }
        except Exception:
            pass
        
        org_codespaces["usage"] = {
            "total_secrets": len(org_codespaces["secrets"]),
            "total_variables": len(org_codespaces["variables"])
        }
        
        return org_codespaces
    
    def detect_all_codespaces(self) -> Dict[str, Any]:
        """
        Detect codespaces across user and all organizations.
        
        Returns:
            Dictionary with comprehensive codespaces detection
        """
        all_codespaces = {
            "user_codespaces": {},
            "organization_codespaces": {},
            "summary": {
                "total_codespaces": 0,
                "active_codespaces": 0,
                "total_secrets": 0,
                "total_variables": 0,
                "orgs_with_codespaces": 0
            },
            "errors": []
        }
        
        # Get user codespaces
        try:
            user_codespaces = self.detect_user_codespaces()
            all_codespaces["user_codespaces"] = user_codespaces
            all_codespaces["summary"]["total_codespaces"] = user_codespaces["usage"].get("total", 0)
            all_codespaces["summary"]["active_codespaces"] = user_codespaces["usage"].get("active", 0)
            all_codespaces["summary"]["total_secrets"] += user_codespaces["usage"].get("total_secrets", 0)
            all_codespaces["summary"]["total_variables"] += user_codespaces["usage"].get("total_variables", 0)
        except Exception as e:
            all_codespaces["errors"].append(f"Failed to get user codespaces: {str(e)}")
        
        # Get organization codespaces
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs:
                org_name = org.get("login", "")
                if org_name:
                    try:
                        org_codespaces = self.detect_org_codespaces(org_name)
                        all_codespaces["organization_codespaces"][org_name] = org_codespaces
                        
                        if org_codespaces["usage"]["total_secrets"] > 0 or org_codespaces["usage"]["total_variables"] > 0:
                            all_codespaces["summary"]["orgs_with_codespaces"] += 1
                            all_codespaces["summary"]["total_secrets"] += org_codespaces["usage"]["total_secrets"]
                            all_codespaces["summary"]["total_variables"] += org_codespaces["usage"]["total_variables"]
                    except Exception as e:
                        all_codespaces["errors"].append(f"Failed to get codespaces for {org_name}: {str(e)}")
        except Exception as e:
            all_codespaces["errors"].append(f"Failed to get organizations: {str(e)}")
        
        return all_codespaces

