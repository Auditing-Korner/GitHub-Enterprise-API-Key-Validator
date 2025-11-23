"""
Token Metadata Analysis Module

Analyzes API token metadata:
- Token scopes (from response headers)
- Token expiration
- Token usage and rate limits
- Token creation information
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class TokenMetadataAnalyzer:
    """Analyzes API token metadata and usage."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_token_metadata(self) -> Dict[str, Any]:
        """
        Analyze token metadata from API responses.
        
        Returns:
            Dictionary with token metadata
        """
        metadata = {
            "scopes": [],
            "rate_limit": {},
            "user_info": {},
            "token_type": "unknown",
            "errors": []
        }
        
        # Get user info to extract scopes from headers
        try:
            # Make a request and capture headers
            response = self.api_client._make_request("GET", "/user")
            if response and response.status_code == 200:
                # Extract scopes from X-OAuth-Scopes header
                scopes_header = response.headers.get("X-OAuth-Scopes", "")
                if scopes_header:
                    metadata["scopes"] = [s.strip() for s in scopes_header.split(",") if s.strip()]
                
                # Extract accepted scopes
                accepted_scopes = response.headers.get("X-Accepted-OAuth-Scopes", "")
                if accepted_scopes:
                    metadata["accepted_scopes"] = [s.strip() for s in accepted_scopes.split(",") if s.strip()]
                
                # Get user info
                user_data = response.json()
                metadata["user_info"] = {
                    "login": user_data.get("login", ""),
                    "id": user_data.get("id", ""),
                    "type": user_data.get("type", ""),
                    "site_admin": user_data.get("site_admin", False),
                    "created_at": user_data.get("created_at", ""),
                    "updated_at": user_data.get("updated_at", "")
                }
        except Exception as e:
            metadata["errors"].append(f"Failed to get user info: {str(e)}")
        
        # Get rate limit information
        try:
            rate_limit = self.api_client.get("/rate_limit")
            if rate_limit:
                metadata["rate_limit"] = {
                    "limit": rate_limit.get("rate", {}).get("limit", 0),
                    "remaining": rate_limit.get("rate", {}).get("remaining", 0),
                    "reset": rate_limit.get("rate", {}).get("reset", 0),
                    "used": rate_limit.get("rate", {}).get("used", 0),
                    "core": rate_limit.get("resources", {}).get("core", {}),
                    "search": rate_limit.get("resources", {}).get("search", {}),
                    "graphql": rate_limit.get("resources", {}).get("graphql", {})
                }
        except Exception as e:
            metadata["errors"].append(f"Failed to get rate limit: {str(e)}")
        
        # Determine token type based on scopes
        if metadata["scopes"]:
            if "repo" in metadata["scopes"] or "admin:org" in metadata["scopes"]:
                metadata["token_type"] = "personal_access_token"
            elif "workflow" in metadata["scopes"]:
                metadata["token_type"] = "github_actions_token"
            else:
                metadata["token_type"] = "oauth_token"
        
        # Try to get token information (if accessible via GitHub Apps API)
        try:
            # Check if this is a GitHub App installation token
            installations = self.api_client.get("/user/installations")
            if installations and installations.get("installations"):
                metadata["token_type"] = "github_app_token"
                metadata["installations"] = [
                    {
                        "id": inst.get("id", ""),
                        "app_id": inst.get("app_id", ""),
                        "app_slug": inst.get("app_slug", ""),
                        "target_type": inst.get("target_type", ""),
                        "account": {
                            "login": inst.get("account", {}).get("login", ""),
                            "type": inst.get("account", {}).get("type", "")
                        } if inst.get("account") else {}
                    }
                    for inst in installations.get("installations", [])
                ]
        except Exception:
            pass
        
        return metadata
    
    def analyze_token_usage(self) -> Dict[str, Any]:
        """
        Analyze token usage patterns.
        
        Returns:
            Dictionary with token usage analysis
        """
        usage = {
            "rate_limit_usage": {},
            "api_calls_made": 0,
            "remaining_calls": 0,
            "reset_time": None,
            "usage_percentage": 0.0
        }
        
        try:
            rate_limit = self.api_client.get("/rate_limit")
            if rate_limit:
                core = rate_limit.get("resources", {}).get("core", {})
                limit = core.get("limit", 0)
                remaining = core.get("remaining", 0)
                used = core.get("used", 0)
                reset = core.get("reset", 0)
                
                usage["rate_limit_usage"] = {
                    "limit": limit,
                    "remaining": remaining,
                    "used": used,
                    "reset": reset
                }
                usage["api_calls_made"] = used
                usage["remaining_calls"] = remaining
                usage["reset_time"] = reset
                if limit > 0:
                    usage["usage_percentage"] = (used / limit) * 100
        except Exception as e:
            usage["error"] = str(e)
        
        return usage

