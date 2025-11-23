"""
Enterprise Audit Log Analyzer Module

Analyzes enterprise audit logs for:
- Security events and access patterns
- User activity and behavior
- Organization changes
- Repository access patterns
- Permission changes
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from .api_client import GitHubAPIClient


class EnterpriseAuditLogAnalyzer:
    """Analyzes enterprise audit logs."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_enterprise_audit_log(self, enterprise_slug: str, days: int = 7) -> Dict[str, Any]:
        """
        Analyze enterprise audit logs.
        
        Args:
            enterprise_slug: Enterprise slug
            days: Number of days to analyze (default: 7)
            
        Returns:
            Dictionary with audit log analysis
        """
        audit_data = {
            "enterprise": enterprise_slug,
            "events": [],
            "summary": {
                "total_events": 0,
                "event_types": {},
                "actors": {},
                "actions": {},
                "repositories": {},
                "organizations": {}
            },
            "errors": []
        }
        
        # Calculate date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        try:
            # Get audit log events
            # Note: This endpoint may require enterprise admin permissions
            events = self.api_client.get_paginated(
                f"/enterprises/{enterprise_slug}/audit-log",
                params={
                    "phrase": f"created:>={start_date.isoformat()}",
                    "per_page": 100
                }
            )
            
            for event in events:
                event_data = {
                    "timestamp": event.get("@timestamp", ""),
                    "action": event.get("action", ""),
                    "actor": {
                        "login": event.get("actor", ""),
                        "id": event.get("actor_id", "")
                    } if event.get("actor") else {},
                    "org": event.get("org", ""),
                    "repo": event.get("repo", ""),
                    "user": event.get("user", ""),
                    "created_at": event.get("created_at", ""),
                    "data": event.get("data", {})
                }
                audit_data["events"].append(event_data)
                
                # Update summary statistics
                audit_data["summary"]["total_events"] += 1
                
                # Count by action
                action = event.get("action", "unknown")
                audit_data["summary"]["actions"][action] = audit_data["summary"]["actions"].get(action, 0) + 1
                
                # Count by actor
                actor = event.get("actor", "unknown")
                audit_data["summary"]["actors"][actor] = audit_data["summary"]["actors"].get(actor, 0) + 1
                
                # Count by repository
                repo = event.get("repo", "")
                if repo:
                    audit_data["summary"]["repositories"][repo] = audit_data["summary"]["repositories"].get(repo, 0) + 1
                
                # Count by organization
                org = event.get("org", "")
                if org:
                    audit_data["summary"]["organizations"][org] = audit_data["summary"]["organizations"].get(org, 0) + 1
                
                # Categorize event types
                event_type = self._categorize_event(action)
                audit_data["summary"]["event_types"][event_type] = audit_data["summary"]["event_types"].get(event_type, 0) + 1
        except Exception as e:
            audit_data["errors"].append(f"Failed to get audit log: {str(e)}")
        
        return audit_data
    
    def analyze_org_audit_log(self, org_name: str, days: int = 7) -> Dict[str, Any]:
        """
        Analyze organization audit logs.
        
        Args:
            org_name: Organization name
            days: Number of days to analyze (default: 7)
            
        Returns:
            Dictionary with organization audit log analysis
        """
        audit_data = {
            "organization": org_name,
            "events": [],
            "summary": {
                "total_events": 0,
                "event_types": {},
                "actors": {},
                "actions": {},
                "repositories": {}
            },
            "errors": []
        }
        
        try:
            # Get organization audit log events
            events = self.api_client.get_paginated(
                f"/orgs/{org_name}/audit-log",
                params={"per_page": 100}
            )
            
            for event in events[:500]:  # Limit to 500 events for performance
                event_data = {
                    "timestamp": event.get("@timestamp", ""),
                    "action": event.get("action", ""),
                    "actor": {
                        "login": event.get("actor", ""),
                        "id": event.get("actor_id", "")
                    } if event.get("actor") else {},
                    "repo": event.get("repo", ""),
                    "user": event.get("user", ""),
                    "created_at": event.get("created_at", ""),
                    "data": event.get("data", {})
                }
                audit_data["events"].append(event_data)
                
                # Update summary statistics
                audit_data["summary"]["total_events"] += 1
                
                action = event.get("action", "unknown")
                audit_data["summary"]["actions"][action] = audit_data["summary"]["actions"].get(action, 0) + 1
                
                actor = event.get("actor", "unknown")
                audit_data["summary"]["actors"][actor] = audit_data["summary"]["actors"].get(actor, 0) + 1
                
                repo = event.get("repo", "")
                if repo:
                    audit_data["summary"]["repositories"][repo] = audit_data["summary"]["repositories"].get(repo, 0) + 1
                
                event_type = self._categorize_event(action)
                audit_data["summary"]["event_types"][event_type] = audit_data["summary"]["event_types"].get(event_type, 0) + 1
        except Exception as e:
            audit_data["errors"].append(f"Failed to get audit log: {str(e)}")
        
        return audit_data
    
    def _categorize_event(self, action: str) -> str:
        """Categorize audit log event by action type."""
        action_lower = action.lower()
        
        if any(keyword in action_lower for keyword in ["repo.create", "repo.delete", "repo.transfer"]):
            return "repository_management"
        elif any(keyword in action_lower for keyword in ["member", "team", "org"]):
            return "organization_management"
        elif any(keyword in action_lower for keyword in ["secret", "token", "key"]):
            return "security"
        elif any(keyword in action_lower for keyword in ["hook", "webhook"]):
            return "webhooks"
        elif any(keyword in action_lower for keyword in ["permission", "access"]):
            return "permissions"
        elif any(keyword in action_lower for keyword in ["billing", "payment"]):
            return "billing"
        else:
            return "other"

