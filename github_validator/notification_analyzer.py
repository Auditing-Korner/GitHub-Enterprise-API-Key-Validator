"""
Notification Analysis Module

Analyzes user notifications including:
- Notification threads and subscriptions
- Notification reasons and types
- Repository notifications
- Notification settings
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class NotificationAnalyzer:
    """Analyzes user notifications."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_notifications(self, all: bool = False, participating: bool = False, 
                             since: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze user notifications.
        
        Args:
            all: Include notifications marked as read
            participating: Only show notifications in which the user is participating
            since: Only show notifications updated after the given time (ISO 8601 format)
            
        Returns:
            Dictionary with notification analysis
        """
        notification_data = {
            "notifications": [],
            "summary": {
                "total": 0,
                "unread": 0,
                "read": 0,
                "reasons": {},
                "types": {},
                "repositories": set()
            },
            "errors": []
        }
        
        try:
            params = {}
            if all:
                params["all"] = "true"
            if participating:
                params["participating"] = "true"
            if since:
                params["since"] = since
            
            notifications = self.api_client.get_paginated("/notifications", params=params)
            
            for notification in notifications[:100]:  # Limit to 100 notifications
                notif_info = {
                    "id": notification.get("id", ""),
                    "repository": {
                        "full_name": notification.get("repository", {}).get("full_name", ""),
                        "id": notification.get("repository", {}).get("id", "")
                    } if notification.get("repository") else {},
                    "subject": {
                        "title": notification.get("subject", {}).get("title", ""),
                        "type": notification.get("subject", {}).get("type", ""),
                        "url": notification.get("subject", {}).get("url", "")
                    } if notification.get("subject") else {},
                    "reason": notification.get("reason", ""),
                    "unread": notification.get("unread", False),
                    "updated_at": notification.get("updated_at", ""),
                    "last_read_at": notification.get("last_read_at", ""),
                    "url": notification.get("url", "")
                }
                
                notification_data["notifications"].append(notif_info)
                
                # Update summary
                notification_data["summary"]["total"] += 1
                if notif_info["unread"]:
                    notification_data["summary"]["unread"] += 1
                else:
                    notification_data["summary"]["read"] += 1
                
                # Track reasons
                reason = notif_info.get("reason", "unknown")
                notification_data["summary"]["reasons"][reason] = notification_data["summary"]["reasons"].get(reason, 0) + 1
                
                # Track types
                notif_type = notif_info.get("subject", {}).get("type", "unknown")
                notification_data["summary"]["types"][notif_type] = notification_data["summary"]["types"].get(notif_type, 0) + 1
                
                # Track repositories
                repo_name = notif_info.get("repository", {}).get("full_name", "")
                if repo_name:
                    notification_data["summary"]["repositories"].add(repo_name)
        except Exception as e:
            notification_data["errors"].append(f"Failed to get notifications: {str(e)}")
        
        # Convert set to list
        notification_data["summary"]["repositories"] = list(notification_data["summary"]["repositories"])
        
        return notification_data
    
    def get_notification_thread(self, thread_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a notification thread.
        
        Args:
            thread_id: Notification thread ID
            
        Returns:
            Dictionary with thread details
        """
        thread_data = {
            "thread_id": thread_id,
            "thread": {},
            "subscription": {},
            "errors": []
        }
        
        try:
            thread = self.api_client.get(f"/notifications/threads/{thread_id}")
            if thread:
                thread_data["thread"] = {
                    "id": thread.get("id", ""),
                    "repository": thread.get("repository", {}).get("full_name", "") if thread.get("repository") else "",
                    "subject": thread.get("subject", {}),
                    "reason": thread.get("reason", ""),
                    "unread": thread.get("unread", False),
                    "updated_at": thread.get("updated_at", "")
                }
        except Exception as e:
            thread_data["errors"].append(f"Failed to get thread: {str(e)}")
        
        try:
            subscription = self.api_client.get(f"/notifications/threads/{thread_id}/subscription")
            if subscription:
                thread_data["subscription"] = {
                    "subscribed": subscription.get("subscribed", False),
                    "ignored": subscription.get("ignored", False),
                    "reason": subscription.get("reason", "")
                }
        except Exception:
            pass
        
        return thread_data

