"""
Tests for API Client Module
"""

import pytest
import requests
from unittest.mock import Mock, patch, MagicMock
from github_validator.api_client import GitHubAPIClient


class TestGitHubAPIClient:
    """Test cases for GitHubAPIClient."""
    
    def test_init(self):
        """Test client initialization."""
        client = GitHubAPIClient("test-api-key")
        assert client.api_key == "test-api-key"
        assert client.base_url == "https://api.github.com"
        assert "Authorization" in client.session.headers
        assert client.session.headers["Authorization"] == "token test-api-key"
    
    def test_init_with_custom_url(self):
        """Test client initialization with custom base URL."""
        client = GitHubAPIClient("test-api-key", "https://github.example.com/api/v3")
        assert client.base_url == "https://github.example.com/api/v3"
    
    @patch('github_validator.api_client.requests.Session.request')
    def test_get_success(self, mock_request):
        """Test successful GET request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"login": "testuser"}
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response
        
        client = GitHubAPIClient("test-key")
        result = client.get("/user")
        
        assert result == {"login": "testuser"}
        mock_request.assert_called_once()
    
    @patch('github_validator.api_client.requests.Session.request')
    def test_get_404(self, mock_request):
        """Test GET request with 404 response."""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        client = GitHubAPIClient("test-key")
        result = client.get("/nonexistent")
        
        assert result is None
    
    @patch('github_validator.api_client.requests.Session.request')
    def test_get_paginated(self, mock_request):
        """Test paginated GET request."""
        # First page response
        mock_response_1 = Mock()
        mock_response_1.status_code = 200
        mock_response_1.json.return_value = [{"id": 1}, {"id": 2}]
        mock_response_1.headers = {}
        mock_response_1.raise_for_status = Mock()
        
        # Second page response (empty)
        mock_response_2 = Mock()
        mock_response_2.status_code = 200
        mock_response_2.json.return_value = []
        mock_response_2.headers = {}
        mock_response_2.raise_for_status = Mock()
        
        mock_request.side_effect = [mock_response_1, mock_response_2]
        
        client = GitHubAPIClient("test-key")
        result = client.get_paginated("/repos")
        
        assert len(result) == 2
        assert result[0]["id"] == 1
        assert result[1]["id"] == 2
    
    @patch('github_validator.api_client.requests.Session.request')
    def test_test_authentication_success(self, mock_request):
        """Test successful authentication."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"login": "testuser", "id": 123}
        mock_response.headers = {}
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response
        
        client = GitHubAPIClient("test-key")
        result = client.test_authentication()
        
        assert result == {"login": "testuser", "id": 123}
    
    @patch('github_validator.api_client.requests.Session.request')
    def test_test_authentication_failure(self, mock_request):
        """Test failed authentication."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_response)
        mock_request.return_value = mock_response
        
        client = GitHubAPIClient("invalid-key")
        result = client.test_authentication()
        
        assert result is None

