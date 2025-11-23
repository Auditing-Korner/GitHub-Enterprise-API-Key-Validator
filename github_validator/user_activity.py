"""
User Activity Analysis Module

Analyzes user activity patterns including:
- User events and activity feed
- Followers and following
- Starred repositories
- User subscriptions
- Activity patterns and behavior
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from .api_client import GitHubAPIClient


class UserActivityAnalyzer:
    """Analyzes user activity and behavior patterns."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_user_activity(self, username: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze user activity.
        
        Args:
            username: Username to analyze (defaults to authenticated user)
            
        Returns:
            Dictionary with user activity analysis
        """
        activity_data = {
            "user": username or "authenticated_user",
            "profile": {},
            "events": [],
            "received_events": [],
            "public_events": [],
            "followers": [],
            "following": [],
            "starred_repos": [],
            "subscriptions": [],
            "summary": {
                "total_events": 0,
                "total_received_events": 0,
                "total_public_events": 0,
                "followers_count": 0,
                "following_count": 0,
                "starred_repos_count": 0,
                "subscriptions_count": 0,
                "event_types": {}
            },
            "errors": []
        }
        
        target_user = username or "user"
        
        # Get user profile
        try:
            profile = self.api_client.get(f"/{target_user}")
            if profile:
                activity_data["profile"] = {
                    "login": profile.get("login", ""),
                    "id": profile.get("id", ""),
                    "type": profile.get("type", ""),
                    "name": profile.get("name", ""),
                    "company": profile.get("company", ""),
                    "blog": profile.get("blog", ""),
                    "location": profile.get("location", ""),
                    "email": profile.get("email", ""),
                    "bio": profile.get("bio", ""),
                    "public_repos": profile.get("public_repos", 0),
                    "public_gists": profile.get("public_gists", 0),
                    "followers": profile.get("followers", 0),
                    "following": profile.get("following", 0),
                    "created_at": profile.get("created_at", ""),
                    "updated_at": profile.get("updated_at", "")
                }
        except Exception as e:
            activity_data["errors"].append(f"Profile: {str(e)}")
        
        # Get user events
        try:
            events = self.api_client.get_paginated(f"/{target_user}/events", params={"per_page": 100})
            for event in events[:100]:  # Limit to 100 events
                event_data = {
                    "id": event.get("id", ""),
                    "type": event.get("type", ""),
                    "actor": {
                        "login": event.get("actor", {}).get("login", ""),
                        "id": event.get("actor", {}).get("id", "")
                    } if event.get("actor") else {},
                    "repo": {
                        "name": event.get("repo", {}).get("name", ""),
                        "id": event.get("repo", {}).get("id", "")
                    } if event.get("repo") else {},
                    "created_at": event.get("created_at", ""),
                    "payload": {}  # Simplified payload
                }
                activity_data["events"].append(event_data)
                activity_data["summary"]["total_events"] += 1
                
                # Count event types
                event_type = event.get("type", "unknown")
                activity_data["summary"]["event_types"][event_type] = activity_data["summary"]["event_types"].get(event_type, 0) + 1
        except Exception as e:
            activity_data["errors"].append(f"Events: {str(e)}")
        
        # Get received events
        try:
            received = self.api_client.get_paginated(f"/{target_user}/received_events", params={"per_page": 100})
            for event in received[:100]:
                activity_data["received_events"].append({
                    "type": event.get("type", ""),
                    "actor": event.get("actor", {}).get("login", "") if event.get("actor") else "",
                    "created_at": event.get("created_at", "")
                })
                activity_data["summary"]["total_received_events"] += 1
        except Exception as e:
            activity_data["errors"].append(f"Received events: {str(e)}")
        
        # Get public events
        try:
            public = self.api_client.get_paginated(f"/{target_user}/events/public", params={"per_page": 100})
            for event in public[:100]:
                activity_data["public_events"].append({
                    "type": event.get("type", ""),
                    "repo": event.get("repo", {}).get("name", "") if event.get("repo") else "",
                    "created_at": event.get("created_at", "")
                })
                activity_data["summary"]["total_public_events"] += 1
        except Exception as e:
            activity_data["errors"].append(f"Public events: {str(e)}")
        
        # Get followers
        try:
            followers = self.api_client.get_paginated(f"/{target_user}/followers", params={"per_page": 100})
            activity_data["followers"] = [
                {
                    "login": f.get("login", ""),
                    "id": f.get("id", ""),
                    "type": f.get("type", "")
                }
                for f in followers[:100]
            ]
            activity_data["summary"]["followers_count"] = len(activity_data["followers"])
        except Exception as e:
            activity_data["errors"].append(f"Followers: {str(e)}")
        
        # Get following
        try:
            following = self.api_client.get_paginated(f"/{target_user}/following", params={"per_page": 100})
            activity_data["following"] = [
                {
                    "login": f.get("login", ""),
                    "id": f.get("id", ""),
                    "type": f.get("type", "")
                }
                for f in following[:100]
            ]
            activity_data["summary"]["following_count"] = len(activity_data["following"])
        except Exception as e:
            activity_data["errors"].append(f"Following: {str(e)}")
        
        # Get starred repositories
        try:
            starred = self.api_client.get_paginated(f"/{target_user}/starred", params={"per_page": 100})
            activity_data["starred_repos"] = [
                {
                    "full_name": repo.get("full_name", ""),
                    "id": repo.get("id", ""),
                    "private": repo.get("private", False),
                    "stargazers_count": repo.get("stargazers_count", 0)
                }
                for repo in starred[:100]
            ]
            activity_data["summary"]["starred_repos_count"] = len(activity_data["starred_repos"])
        except Exception as e:
            activity_data["errors"].append(f"Starred repos: {str(e)}")
        
        # Get subscriptions
        try:
            subscriptions = self.api_client.get_paginated(f"/{target_user}/subscriptions", params={"per_page": 100})
            activity_data["subscriptions"] = [
                {
                    "full_name": repo.get("full_name", ""),
                    "id": repo.get("id", ""),
                    "private": repo.get("private", False)
                }
                for repo in subscriptions[:100]
            ]
            activity_data["summary"]["subscriptions_count"] = len(activity_data["subscriptions"])
        except Exception as e:
            activity_data["errors"].append(f"Subscriptions: {str(e)}")
        
        return activity_data

