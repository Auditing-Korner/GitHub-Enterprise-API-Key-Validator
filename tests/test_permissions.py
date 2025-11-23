"""
Tests for Permission Validation Module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from github_validator.permissions import PermissionChecker
from github_validator.api_client import GitHubAPIClient


class TestPermissionChecker:
    """Test cases for PermissionChecker."""
    
    @pytest.fixture
    def mock_api_client(self):
        """Create a mock API client."""
        return Mock(spec=GitHubAPIClient)
    
    @pytest.fixture
    def permission_checker(self, mock_api_client):
        """Create a PermissionChecker instance with mocked API client."""
        return PermissionChecker(mock_api_client)
    
    def test_init(self, mock_api_client):
        """Test PermissionChecker initialization."""
        checker = PermissionChecker(mock_api_client)
        assert checker.api_client == mock_api_client
        assert checker.permission_results == {}
    
    def test_test_repo_access_granted(self, permission_checker, mock_api_client):
        """Test repository access when granted."""
        mock_api_client.get.return_value = [{"name": "test-repo"}]
        mock_api_client.get_paginated.return_value = [{"name": "test-repo"}]
        
        result = permission_checker._test_repo_access()
        
        assert result["granted"] is True
        assert "repositories" in result["message"].lower() or "access" in result["message"].lower()
    
    def test_test_repo_access_denied(self, permission_checker, mock_api_client):
        """Test repository access when denied."""
        mock_api_client.get.side_effect = Exception("403 Forbidden")
        mock_api_client.get_paginated.side_effect = Exception("403 Forbidden")
        
        result = permission_checker._test_repo_access()
        
        assert result["granted"] is False
        assert "denied" in result["message"].lower() or "error" in result["message"].lower()
    
    def test_test_user_info_access(self, permission_checker, mock_api_client):
        """Test user info access."""
        mock_api_client.get.return_value = {"login": "testuser", "id": 123}
        
        result = permission_checker._test_user_info_access()
        
        assert result["granted"] is True
        assert result["details"]["username"] == "testuser"
    
    def test_test_org_read_granted(self, permission_checker, mock_api_client):
        """Test organization read access when granted."""
        mock_api_client.get.return_value = {"login": "testorg", "name": "Test Org"}
        mock_api_client.get_paginated.return_value = [{"login": "testorg"}]
        
        result = permission_checker._test_org_read("testorg")
        
        assert result["granted"] is True
        assert "testorg" in result["message"]
    
    def test_validate_all_permissions(self, permission_checker, mock_api_client):
        """Test validating all permissions."""
        def mock_get(endpoint, params=None, headers=None):
            if endpoint == "/user":
                return {"login": "testuser"}
            if endpoint == "/rate_limit":
                return {"rate": {"remaining": 5000, "limit": 5000}}
            if endpoint.startswith("/user/codespaces"):
                return {"codespaces": []}
            if "codespaces/secrets" in endpoint:
                return {"secrets": []}
            if endpoint.startswith("/user/repos"):
                return [{"name": "repo1"}]
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/user/repos":
                return [
                    {
                        "name": "repo1",
                        "full_name": "org/repo1",
                        "private": False,
                        "archived": False,
                        "default_branch": "main",
                        "permissions": {"admin": True, "push": True, "pull": True}
                    }
                ]
            if endpoint == "/user/orgs":
                return [{"login": "testorg"}]
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated
        mock_api_client.test_authentication.return_value = {"login": "testuser"}
        mock_api_client.get_rate_limit_info.return_value = {"rate": {"remaining": 5000}}
        
        result = permission_checker.validate_all_permissions()
        
        assert "critical_permissions" in result
        assert "standard_permissions" in result
        assert "summary" in result
        assert result["summary"]["total_tested"] > 0
    
    def test_validate_all_permissions_with_org(self, permission_checker, mock_api_client):
        """Test validating permissions with organization name."""
        def mock_get(endpoint, params=None, headers=None):
            if endpoint == "/user":
                return {"login": "testuser"}
            if endpoint == "/rate_limit":
                return {"rate": {"remaining": 4000, "limit": 5000}}
            if endpoint.startswith("/user/codespaces"):
                return {"codespaces": []}
            if "codespaces/secrets" in endpoint:
                return {"secrets": []}
            if endpoint.startswith("/user/repos"):
                return [{"name": "repo1"}]
            if endpoint.startswith("/orgs/testorg"):
                return {}
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/user/repos":
                return [
                    {
                        "name": "repo1",
                        "full_name": "testorg/repo1",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "permissions": {"admin": False, "push": True, "pull": True}
                    }
                ]
            if endpoint == "/user/orgs":
                return [{"login": "testorg"}]
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated
        mock_api_client.test_authentication.return_value = {"login": "testuser"}
        
        result = permission_checker.validate_all_permissions(org_name="testorg")
        
        assert "critical_permissions" in result
        assert "admin:org" in result["critical_permissions"] or "read:org" in result["critical_permissions"]

    def test_manage_runners_enterprise_requires_slug(self, permission_checker):
        """Ensure enterprise runner checks require a slug."""
        result = permission_checker._test_manage_runners_enterprise()
        assert result["granted"] is False
        assert "slug" in result["message"]

    @patch("github_validator.permissions.EnterpriseRunnerInspector")
    def test_manage_runners_enterprise_with_slug(self, mock_inspector_cls, permission_checker):
        """Enterprise runner checks succeed when slug provided."""
        mock_inspector = mock_inspector_cls.return_value
        mock_inspector.fetch_runners.return_value = {"total_runners": 2}

        result = permission_checker._test_manage_runners_enterprise("enterprise")

        mock_inspector.fetch_runners.assert_called_once_with(max_pages=1)
        assert result["granted"] is True
        assert "enterprise" in result["message"]

    @patch("github_validator.permissions.EnterpriseRunnerInspector")
    def test_validate_all_permissions_with_enterprise_slug(self, mock_inspector_cls, permission_checker, mock_api_client):
        """Validate flow passes enterprise slug into inspector."""
        mock_inspector_cls.return_value.fetch_runners.return_value = {"total_runners": 1}
        mock_api_client.get.return_value = {"login": "testuser"}
        mock_api_client.get_paginated.return_value = []
        mock_api_client.test_authentication.return_value = {"login": "testuser"}

        result = permission_checker.validate_all_permissions(enterprise_slug="enterprise")

        assert mock_inspector_cls.call_count == 2
        assert "manage_runners:enterprise" in result["critical_permissions"]

