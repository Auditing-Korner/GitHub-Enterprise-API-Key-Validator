"""
GitHub Enterprise API Client Module

Handles authentication, API requests, error handling, and rate limiting.
"""

import time
import requests
from typing import Dict, Optional, Any, List
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .cache import get_cache
from .error_handler import handle_error


class GitHubAPIClient:
    """Client for interacting with GitHub Enterprise API."""
    
    def __init__(self, api_key: str, base_url: Optional[str] = None):
        """
        Initialize GitHub API client.
        
        Args:
            api_key: GitHub API token/key
            base_url: Base URL for GitHub Enterprise (defaults to github.com)
        """
        self.api_key = api_key
        self.base_url = base_url or "https://api.github.com"
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Authorization": f"token {api_key}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitHub-Enterprise-Validator/1.0"
        })
        
        # Rate limiting tracking
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
    
    def _handle_rate_limit(self, response: requests.Response) -> None:
        """Handle rate limiting from API response."""
        if "X-RateLimit-Remaining" in response.headers:
            self.rate_limit_remaining = int(response.headers["X-RateLimit-Remaining"])
        
        if "X-RateLimit-Reset" in response.headers:
            self.rate_limit_reset = int(response.headers["X-RateLimit-Reset"])
        
        # If rate limited, wait until reset
        if response.status_code == 403 and self.rate_limit_remaining == 0:
            wait_time = max(0, self.rate_limit_reset - time.time() + 1)
            if wait_time > 0:
                time.sleep(wait_time)
    
    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        headers: Optional[Dict] = None
    ) -> requests.Response:
        """
        Make an API request with error handling and rate limiting.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint (e.g., "/user" or "/orgs/company")
            params: Query parameters
            json_data: JSON body for POST/PUT requests
            headers: Additional headers
        
        Returns:
            Response object
        """
        url = f"{self.base_url}{endpoint}"
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=request_headers,
                timeout=30
            )
            
            self._handle_rate_limit(response)
            
            # Retry on rate limit
            if response.status_code == 403 and self.rate_limit_remaining == 0:
                return self._make_request(method, endpoint, params, json_data, headers)
            
            return response
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {str(e)}")
    
    def get(self, endpoint: str, params: Optional[Dict] = None, headers: Optional[Dict] = None, use_cache: bool = True) -> Dict[str, Any]:
        """
        Make a GET request with optional caching.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
            headers: Additional headers
            use_cache: Whether to use cache (default: True)
        
        Returns:
            JSON response as dictionary
        """
        # Check cache first
        if use_cache:
            cache = get_cache()
            cached_value = cache.get(endpoint, params)
            if cached_value is not None:
                return cached_value
        
        try:
            response = self._make_request("GET", endpoint, params=params, headers=headers)
            
            if response.status_code == 404:
                return None
            
            response.raise_for_status()
            result = response.json()
            
            # Cache successful responses
            if use_cache and response.status_code == 200:
                cache = get_cache()
                # Use shorter TTL for paginated endpoints
                ttl = 60 if "per_page" in (params or {}) else 300
                cache.set(endpoint, result, ttl=ttl, params=params)
            
            return result
        except Exception as e:
            error_info = handle_error(e, context=f"GET {endpoint}")
            raise Exception(f"{error_info['user_message']}: {str(e)}")
    
    def post(self, endpoint: str, json_data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make a POST request.
        
        Args:
            endpoint: API endpoint
            json_data: JSON body
            headers: Additional headers
        
        Returns:
            JSON response as dictionary
        """
        response = self._make_request("POST", endpoint, json_data=json_data, headers=headers)
        response.raise_for_status()
        return response.json()
    
    def put(self, endpoint: str, json_data: Optional[Dict] = None, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Make a PUT request.
        
        Args:
            endpoint: API endpoint
            json_data: JSON body
            headers: Additional headers
        
        Returns:
            JSON response as dictionary
        """
        response = self._make_request("PUT", endpoint, json_data=json_data, headers=headers)
        response.raise_for_status()
        return response.json()
    
    def delete(self, endpoint: str, headers: Optional[Dict] = None) -> bool:
        """
        Make a DELETE request.
        
        Args:
            endpoint: API endpoint
            headers: Additional headers
        
        Returns:
            True if successful (204 status)
        """
        response = self._make_request("DELETE", endpoint, headers=headers)
        return response.status_code == 204
    
    def get_paginated(self, endpoint: str, params: Optional[Dict] = None) -> List[Dict[str, Any]]:
        """
        Get all pages of a paginated endpoint.
        
        Args:
            endpoint: API endpoint
            params: Query parameters
        
        Returns:
            List of all items from all pages
        """
        all_items = []
        page = 1
        per_page = 100
        
        if params is None:
            params = {}
        params["per_page"] = per_page
        
        while True:
            params["page"] = page
            response = self._make_request("GET", endpoint, params=params)
            
            if response.status_code == 404:
                break
            
            response.raise_for_status()
            items = response.json()
            
            # Handle case where response is not a list
            if not isinstance(items, list):
                break
            
            if not items or len(items) == 0:
                break
            
            all_items.extend(items)
            
            # Check if there are more pages
            if len(items) < per_page:
                break
            
            page += 1
        
        return all_items
    
    def test_authentication(self) -> Dict[str, Any]:
        """
        Test if the API key is valid by getting authenticated user info.
        
        Returns:
            User information or None if authentication fails
        """
        try:
            return self.get("/user")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                return None
            raise
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """
        Get current rate limit information.
        
        Returns:
            Rate limit information
        """
        return self.get("/rate_limit")

