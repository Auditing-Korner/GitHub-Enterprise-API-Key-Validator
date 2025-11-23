"""
Rate Limit Monitoring and Management Module

Monitors GitHub API rate limits, provides visualizations, and implements
intelligent rate limit handling strategies.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import deque
import time
from .api_client import GitHubAPIClient


class RateLimitMonitor:
    """Monitors and manages GitHub API rate limits."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
        self.rate_limit_history: deque = deque(maxlen=1000)
        self.rate_limit_stats: Dict[str, Any] = {
            "total_requests": 0,
            "rate_limit_hits": 0,
            "rate_limit_resets": [],
            "lowest_remaining": float('inf'),
            "average_remaining": 0,
            "peak_usage": 0
        }
    
    def check_rate_limit(self) -> Dict[str, Any]:
        """
        Check current rate limit status.
        
        Returns:
            Dictionary with rate limit information
        """
        try:
            # Get rate limit from API
            rate_limit = self.api_client.get("/rate_limit")
            
            if not rate_limit:
                return {
                    "error": "Could not fetch rate limit",
                    "timestamp": datetime.utcnow().isoformat()
                }
            
            core = rate_limit.get("resources", {}).get("core", {})
            search = rate_limit.get("resources", {}).get("search", {})
            graphql = rate_limit.get("resources", {}).get("graphql", {})
            
            current_time = datetime.utcnow()
            reset_time = datetime.fromtimestamp(core.get("reset", 0))
            time_until_reset = (reset_time - current_time).total_seconds()
            
            # Calculate usage percentage
            limit = core.get("limit", 5000)
            remaining = core.get("remaining", 0)
            used = limit - remaining
            usage_percent = (used / limit * 100) if limit > 0 else 0
            
            # Update statistics
            self.rate_limit_stats["total_requests"] += 1
            if remaining < self.rate_limit_stats["lowest_remaining"]:
                self.rate_limit_stats["lowest_remaining"] = remaining
            if usage_percent > self.rate_limit_stats["peak_usage"]:
                self.rate_limit_stats["peak_usage"] = usage_percent
            
            # Record history
            self.rate_limit_history.append({
                "timestamp": current_time.isoformat(),
                "limit": limit,
                "remaining": remaining,
                "used": used,
                "usage_percent": usage_percent,
                "reset_time": reset_time.isoformat(),
                "time_until_reset": time_until_reset
            })
            
            # Calculate average remaining
            if self.rate_limit_history:
                avg_remaining = sum(h["remaining"] for h in self.rate_limit_history) / len(self.rate_limit_history)
                self.rate_limit_stats["average_remaining"] = avg_remaining
            
            # Determine status
            if remaining < limit * 0.1:  # Less than 10% remaining
                status = "critical"
            elif remaining < limit * 0.3:  # Less than 30% remaining
                status = "warning"
            else:
                status = "healthy"
            
            return {
                "core": {
                    "limit": limit,
                    "remaining": remaining,
                    "used": used,
                    "usage_percent": round(usage_percent, 2),
                    "reset_time": reset_time.isoformat(),
                    "time_until_reset": round(time_until_reset, 2),
                    "status": status
                },
                "search": {
                    "limit": search.get("limit", 30),
                    "remaining": search.get("remaining", 30),
                    "reset_time": datetime.fromtimestamp(search.get("reset", 0)).isoformat() if search.get("reset") else None
                },
                "graphql": {
                    "limit": graphql.get("limit", 5000),
                    "remaining": graphql.get("remaining", 5000),
                    "reset_time": datetime.fromtimestamp(graphql.get("reset", 0)).isoformat() if graphql.get("reset") else None
                },
                "timestamp": current_time.isoformat(),
                "recommendations": self._generate_recommendations(remaining, limit, usage_percent, time_until_reset)
            }
        except Exception as e:
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
    
    def _generate_recommendations(self, remaining: int, limit: int, usage_percent: float, time_until_reset: float) -> List[str]:
        """Generate recommendations based on rate limit status."""
        recommendations = []
        
        if remaining < limit * 0.1:
            recommendations.append("CRITICAL: Rate limit nearly exhausted. Consider pausing operations or using caching.")
            if time_until_reset > 0:
                recommendations.append(f"Rate limit resets in {int(time_until_reset / 60)} minutes.")
        elif remaining < limit * 0.3:
            recommendations.append("WARNING: Rate limit usage is high. Consider implementing request throttling.")
        
        if usage_percent > 80:
            recommendations.append("High rate limit usage detected. Review API call patterns and implement caching where possible.")
        
        if time_until_reset < 300 and remaining < limit * 0.5:  # Less than 5 minutes until reset
            recommendations.append("Rate limit will reset soon. Consider waiting before making additional requests.")
        
        if not recommendations:
            recommendations.append("Rate limit status is healthy. Continue normal operations.")
        
        return recommendations
    
    def get_rate_limit_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get rate limit history for the specified time period.
        
        Args:
            hours: Number of hours of history to retrieve
            
        Returns:
            List of rate limit snapshots
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        return [
            entry for entry in self.rate_limit_history
            if datetime.fromisoformat(entry["timestamp"]) >= cutoff_time
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rate limit statistics."""
        return {
            **self.rate_limit_stats,
            "history_count": len(self.rate_limit_history),
            "current_time": datetime.utcnow().isoformat()
        }
    
    def wait_for_reset(self, min_remaining: int = 100) -> bool:
        """
        Wait until rate limit resets or remaining is above threshold.
        
        Args:
            min_remaining: Minimum remaining requests required
            
        Returns:
            True if wait was successful, False otherwise
        """
        rate_limit = self.check_rate_limit()
        core = rate_limit.get("core", {})
        remaining = core.get("remaining", 0)
        time_until_reset = core.get("time_until_reset", 0)
        
        if remaining >= min_remaining:
            return True
        
        if time_until_reset > 0:
            wait_time = min(time_until_reset + 10, 3600)  # Wait up to 1 hour
            print(f"Rate limit low ({remaining} remaining). Waiting {int(wait_time)} seconds for reset...")
            time.sleep(wait_time)
            return True
        
        return False

