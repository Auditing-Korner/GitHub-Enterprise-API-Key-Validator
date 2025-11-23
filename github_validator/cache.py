"""
Caching Module

Provides caching for API responses to improve performance and reduce rate limit usage.
"""

from typing import Dict, Optional, Any
import time
import hashlib
import json
from datetime import datetime, timedelta


class APICache:
    """Simple in-memory cache for API responses."""
    
    def __init__(self, default_ttl: int = 300):
        """
        Initialize cache.
        
        Args:
            default_ttl: Default time-to-live in seconds (default: 5 minutes)
        """
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "evictions": 0
        }
    
    def _generate_key(self, endpoint: str, params: Optional[Dict] = None) -> str:
        """
        Generate cache key from endpoint and parameters.
        
        Args:
            endpoint: API endpoint
            params: Optional query parameters
            
        Returns:
            Cache key string
        """
        key_data = {
            "endpoint": endpoint,
            "params": params or {}
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Any]:
        """
        Get cached value.
        
        Args:
            endpoint: API endpoint
            params: Optional query parameters
            
        Returns:
            Cached value or None if not found/expired
        """
        key = self._generate_key(endpoint, params)
        
        if key in self.cache:
            entry = self.cache[key]
            
            # Check if expired
            if time.time() < entry["expires_at"]:
                self.stats["hits"] += 1
                return entry["value"]
            else:
                # Expired, remove it
                del self.cache[key]
                self.stats["evictions"] += 1
        
        self.stats["misses"] += 1
        return None
    
    def set(self, endpoint: str, value: Any, ttl: Optional[int] = None, params: Optional[Dict] = None):
        """
        Set cached value.
        
        Args:
            endpoint: API endpoint
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
            params: Optional query parameters
        """
        key = self._generate_key(endpoint, params)
        ttl = ttl or self.default_ttl
        
        self.cache[key] = {
            "value": value,
            "expires_at": time.time() + ttl,
            "created_at": time.time(),
            "endpoint": endpoint,
            "params": params
        }
        self.stats["sets"] += 1
    
    def clear(self):
        """Clear all cached entries."""
        self.cache.clear()
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "evictions": 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        hit_rate = 0.0
        if self.stats["hits"] + self.stats["misses"] > 0:
            hit_rate = self.stats["hits"] / (self.stats["hits"] + self.stats["misses"]) * 100
        
        return {
            **self.stats,
            "hit_rate": hit_rate,
            "size": len(self.cache),
            "memory_usage_estimate": len(self.cache) * 1024  # Rough estimate in bytes
        }
    
    def cleanup_expired(self):
        """Remove expired entries from cache."""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.cache.items()
            if entry["expires_at"] < current_time
        ]
        
        for key in expired_keys:
            del self.cache[key]
            self.stats["evictions"] += 1


# Global cache instance
_global_cache = APICache()


def get_cache() -> APICache:
    """Get global cache instance."""
    return _global_cache

