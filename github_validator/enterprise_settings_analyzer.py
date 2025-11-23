"""
Enterprise Settings Analysis Module

Analyzes enterprise-level settings including:
- Enterprise-level settings
- Enterprise policies
- Enterprise billing
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class EnterpriseSettingsAnalyzer:
    """Analyzes enterprise settings."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_enterprise_settings(self, enterprise_slug: str) -> Dict[str, Any]:
        """
        Analyze enterprise settings.
        
        Args:
            enterprise_slug: Enterprise slug
            
        Returns:
            Dictionary with enterprise settings analysis
        """
        settings_data = {
            "enterprise": enterprise_slug,
            "enterprise_info": {},
            "settings": {},
            "billing": {},
            "summary": {
                "settings_accessible": False
            },
            "errors": []
        }
        
        try:
            # Get enterprise info
            enterprise_info = self.api_client.get(f"/enterprises/{enterprise_slug}")
            if enterprise_info:
                settings_data["enterprise_info"] = {
                    "slug": enterprise_info.get("slug", ""),
                    "name": enterprise_info.get("name", ""),
                    "description": enterprise_info.get("description", ""),
                    "website_url": enterprise_info.get("website_url", ""),
                    "html_url": enterprise_info.get("html_url", ""),
                    "created_at": enterprise_info.get("created_at", ""),
                    "updated_at": enterprise_info.get("updated_at", "")
                }
                settings_data["summary"]["settings_accessible"] = True
        except Exception as e:
            settings_data["errors"].append(f"Failed to get enterprise info: {str(e)}")
        
        # Try to get enterprise settings (may require admin access)
        try:
            # Note: Enterprise settings endpoints may vary
            # This is a placeholder for enterprise-specific settings
            settings_data["settings"] = {
                "accessible": False,
                "note": "Enterprise settings may require admin access"
            }
        except Exception:
            pass
        
        # Try to get enterprise billing (may require admin access)
        try:
            billing = self.api_client.get(f"/enterprises/{enterprise_slug}/settings/billing")
            if billing:
                settings_data["billing"] = {
                    "plan": billing.get("plan", {}).get("name", ""),
                    "seats": billing.get("seats", {}),
                    "storage": billing.get("storage", {}),
                    "actions": billing.get("actions", {})
                }
        except Exception:
            settings_data["billing"] = {"accessible": False}
        
        return settings_data

