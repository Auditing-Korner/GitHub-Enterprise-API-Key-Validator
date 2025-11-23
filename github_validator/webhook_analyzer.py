"""
Webhook Analysis Module

Provides detailed webhook analysis including:
- Webhook configurations and events
- Webhook payloads and delivery history
- Webhook security settings
- Webhook failures and retries
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class WebhookAnalyzer:
    """Analyzes webhooks in detail."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_webhooks(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze repository webhooks in detail.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with detailed webhook analysis
        """
        webhook_data = {
            "repository": repo_full_name,
            "webhooks": [],
            "summary": {
                "total_webhooks": 0,
                "active_webhooks": 0,
                "inactive_webhooks": 0,
                "event_types": set(),
                "content_types": set()
            },
            "errors": []
        }
        
        try:
            webhooks = self.api_client.get_paginated(f"/repos/{repo_full_name}/hooks")
            
            for webhook in webhooks:
                webhook_id = webhook.get("id", "")
                
                webhook_info = {
                    "id": webhook_id,
                    "name": webhook.get("name", ""),
                    "active": webhook.get("active", False),
                    "events": webhook.get("events", []),
                    "config": {
                        "url": webhook.get("config", {}).get("url", ""),
                        "content_type": webhook.get("config", {}).get("content_type", ""),
                        "insecure_ssl": webhook.get("config", {}).get("insecure_ssl", "0"),
                        "secret": "***" if webhook.get("config", {}).get("secret") else None
                    },
                    "created_at": webhook.get("created_at", ""),
                    "updated_at": webhook.get("updated_at", ""),
                    "url": webhook.get("url", "")
                }
                
                # Get webhook deliveries (recent)
                try:
                    deliveries = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/hooks/{webhook_id}/deliveries",
                        params={"per_page": 10}
                    )
                    webhook_info["recent_deliveries"] = [
                        {
                            "id": d.get("id", ""),
                            "status": d.get("status", ""),
                            "status_code": d.get("status_code", 0),
                            "delivered_at": d.get("delivered_at", ""),
                            "duration": d.get("duration", 0)
                        }
                        for d in deliveries[:10]  # Last 10 deliveries
                    ]
                except Exception:
                    webhook_info["recent_deliveries"] = []
                
                webhook_data["webhooks"].append(webhook_info)
                
                # Update summary
                webhook_data["summary"]["total_webhooks"] += 1
                if webhook_info["active"]:
                    webhook_data["summary"]["active_webhooks"] += 1
                else:
                    webhook_data["summary"]["inactive_webhooks"] += 1
                
                # Track event types
                for event in webhook_info.get("events", []):
                    webhook_data["summary"]["event_types"].add(event)
                
                # Track content types
                content_type = webhook_info.get("config", {}).get("content_type", "")
                if content_type:
                    webhook_data["summary"]["content_types"].add(content_type)
        except Exception as e:
            webhook_data["errors"].append(f"Failed to get webhooks: {str(e)}")
        
        # Convert sets to lists
        webhook_data["summary"]["event_types"] = list(webhook_data["summary"]["event_types"])
        webhook_data["summary"]["content_types"] = list(webhook_data["summary"]["content_types"])
        
        return webhook_data
    
    def analyze_org_webhooks(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze organization webhooks in detail.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with detailed organization webhook analysis
        """
        webhook_data = {
            "organization": org_name,
            "webhooks": [],
            "summary": {
                "total_webhooks": 0,
                "active_webhooks": 0,
                "event_types": set(),
                "content_types": set()
            },
            "errors": []
        }
        
        try:
            webhooks = self.api_client.get_paginated(f"/orgs/{org_name}/hooks")
            
            for webhook in webhooks:
                webhook_id = webhook.get("id", "")
                
                webhook_info = {
                    "id": webhook_id,
                    "name": webhook.get("name", ""),
                    "active": webhook.get("active", False),
                    "events": webhook.get("events", []),
                    "config": {
                        "url": webhook.get("config", {}).get("url", ""),
                        "content_type": webhook.get("config", {}).get("content_type", ""),
                        "insecure_ssl": webhook.get("config", {}).get("insecure_ssl", "0"),
                        "secret": "***" if webhook.get("config", {}).get("secret") else None
                    },
                    "created_at": webhook.get("created_at", ""),
                    "updated_at": webhook.get("updated_at", ""),
                    "url": webhook.get("url", "")
                }
                
                # Get webhook deliveries
                try:
                    deliveries = self.api_client.get_paginated(
                        f"/orgs/{org_name}/hooks/{webhook_id}/deliveries",
                        params={"per_page": 10}
                    )
                    webhook_info["recent_deliveries"] = [
                        {
                            "id": d.get("id", ""),
                            "status": d.get("status", ""),
                            "status_code": d.get("status_code", 0),
                            "delivered_at": d.get("delivered_at", "")
                        }
                        for d in deliveries[:10]
                    ]
                except Exception:
                    webhook_info["recent_deliveries"] = []
                
                webhook_data["webhooks"].append(webhook_info)
                
                # Update summary
                webhook_data["summary"]["total_webhooks"] += 1
                if webhook_info["active"]:
                    webhook_data["summary"]["active_webhooks"] += 1
                
                for event in webhook_info.get("events", []):
                    webhook_data["summary"]["event_types"].add(event)
                
                content_type = webhook_info.get("config", {}).get("content_type", "")
                if content_type:
                    webhook_data["summary"]["content_types"].add(content_type)
        except Exception as e:
            webhook_data["errors"].append(f"Failed to get webhooks: {str(e)}")
        
        # Convert sets to lists
        webhook_data["summary"]["event_types"] = list(webhook_data["summary"]["event_types"])
        webhook_data["summary"]["content_types"] = list(webhook_data["summary"]["content_types"])
        
        return webhook_data

