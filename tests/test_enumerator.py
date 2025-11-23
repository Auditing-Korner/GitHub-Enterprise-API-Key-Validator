"""
Tests for Company Enumeration Module
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from github_validator.enumerator import CompanyEnumerator
from github_validator.api_client import GitHubAPIClient


class TestCompanyEnumerator:
    """Test cases for CompanyEnumerator."""
    
    @pytest.fixture
    def mock_api_client(self):
        """Create a mock API client."""
        return Mock(spec=GitHubAPIClient)
    
    @pytest.fixture
    def enumerator(self, mock_api_client):
        """Create a CompanyEnumerator instance with mocked API client."""
        return CompanyEnumerator(mock_api_client)
    
    def test_init(self, mock_api_client):
        """Test CompanyEnumerator initialization."""
        enumerator = CompanyEnumerator(mock_api_client)
        assert enumerator.api_client == mock_api_client
    
    def test_enumerate_organization_basic(self, enumerator, mock_api_client):
        """Test basic organization enumeration."""
        def mock_get(endpoint, params=None):
            if endpoint == "/orgs/testorg":
                return {
                    "login": "testorg",
                    "name": "Test Organization",
                    "description": "Test Description",
                    "public_repos": 10
                }
            if endpoint == "/orgs/testorg/audit-log":
                return []
            return {}

        def mock_get_paginated(endpoint, params=None):
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated
        
        result = enumerator.enumerate_organization("testorg")
        
        assert result["organization_name"] == "testorg"
        assert "organization_info" in result
        assert result["organization_info"]["login"] == "testorg"
        assert "members" in result
        assert "teams" in result
        assert "repositories" in result
    
    def test_enumerate_organization_with_members(self, enumerator, mock_api_client):
        """Test organization enumeration with members."""
        def mock_get(endpoint, params=None):
            if endpoint == "/orgs/testorg":
                return {"login": "testorg", "name": "Test Org"}
            if endpoint == "/orgs/testorg/audit-log":
                return []
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/orgs/testorg/members":
                return [
                    {"login": "user1", "id": 1, "type": "User"},
                    {"login": "user2", "id": 2, "type": "User"}
                ]
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated
        
        result = enumerator.enumerate_organization("testorg")
        
        assert len(result["members"]) == 2
        assert result["members"][0]["login"] == "user1"
        assert result["members"][1]["login"] == "user2"
    
    def test_enumerate_organization_with_repos(self, enumerator, mock_api_client):
        """Test organization enumeration with repositories."""
        def mock_get(endpoint, params=None):
            if endpoint == "/orgs/testorg":
                return {"login": "testorg"}
            if endpoint == "/repos/testorg/repo1/actions/workflows":
                return {"workflows": [{"id": 1, "name": "CI", "path": "ci.yml", "state": "active"}]}
            if endpoint == "/orgs/testorg/audit-log":
                return []
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/orgs/testorg/repos":
                return [
                    {
                        "id": 1,
                        "name": "repo1",
                        "full_name": "testorg/repo1",
                        "private": False,
                        "stargazers_count": 10
                    }
                ]
            if endpoint == "/repos/testorg/repo1/actions/secrets":
                return [{"name": "SECRET"}]
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated
        
        result = enumerator.enumerate_organization("testorg")
        
        assert len(result["repositories"]) == 1
        assert result["repositories"][0]["name"] == "repo1"
        assert result["repositories"][0]["stargazers_count"] == 10
        assert result["actions_overview"]["workflow_repositories"] == 1
        assert result["actions_overview"]["repository_secrets"] == 1
        assert result["actions_overview"]["repository_count"] == 1
    
    def test_enumerate_organization_with_teams(self, enumerator, mock_api_client):
        """Test organization enumeration with teams."""
        def mock_get(endpoint, params=None):
            if endpoint == "/orgs/testorg":
                return {"login": "testorg"}
            if endpoint == "/orgs/testorg/audit-log":
                return []
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/orgs/testorg/teams":
                return [
                    {
                        "id": 1,
                        "name": "Developers",
                        "slug": "developers",
                        "permission": "push",
                        "members_count": 5,
                        "repos_count": 10
                    }
                ]
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated
        
        result = enumerator.enumerate_organization("testorg")
        
        assert len(result["teams"]) == 1
        assert result["teams"][0]["name"] == "Developers"
        assert result["teams"][0]["permission"] == "push"
    
    def test_enumerate_all_accessible_orgs(self, enumerator, mock_api_client):
        """Test enumerating all accessible organizations."""
        def mock_get(endpoint, params=None):
            if endpoint == "/orgs/org1":
                return {"login": "org1", "name": "Org 1"}
            if endpoint == "/orgs/org2":
                return {"login": "org2", "name": "Org 2"}
            if endpoint.endswith("/audit-log"):
                return []
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/user/orgs":
                return [{"login": "org1"}, {"login": "org2"}]
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated
        
        result = enumerator.enumerate_all_accessible_orgs()
        
        assert result["total_count"] == 2
        assert len(result["organizations"]) == 2
        assert result["organizations"][0]["organization_name"] == "org1"
        assert result["organizations"][1]["organization_name"] == "org2"
    
    def test_enumerate_organization_handles_errors(self, enumerator, mock_api_client):
        """Test that enumeration handles errors gracefully."""
        mock_api_client.get.side_effect = Exception("API Error")
        mock_api_client.get_paginated.return_value = []
        
        result = enumerator.enumerate_organization("testorg")
        
        assert result["organization_name"] == "testorg"
        assert len(result["errors"]) > 0
        assert "API Error" in result["errors"][0]

    def test_enumerate_organization_includes_org_runners(self, enumerator, mock_api_client):
        """Ensure organization-level runners are captured."""
        def mock_get(endpoint, params=None):
            if endpoint == "/orgs/testorg":
                return {"login": "testorg"}
            if endpoint == "/orgs/testorg/audit-log":
                return []
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/orgs/testorg/actions/runners":
                return [
                    {"id": 1, "name": "runner-1", "os": "linux", "status": "online", "labels": [{"name": "prod"}]}
                ]
            if endpoint == "/orgs/testorg/repos":
                return []
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated

        result = enumerator.enumerate_organization("testorg")

        assert len(result["organization_runners"]) == 1
        assert result["organization_runners"][0]["name"] == "runner-1"

    def test_enumerate_organization_includes_repo_runners(self, enumerator, mock_api_client):
        """Ensure repository-level runners are captured."""
        def mock_get(endpoint, params=None):
            if endpoint == "/orgs/testorg":
                return {"login": "testorg"}
            if endpoint == "/repos/testorg/repo1/actions/workflows":
                return {}
            if endpoint == "/orgs/testorg/audit-log":
                return []
            return {}

        def mock_get_paginated(endpoint, params=None):
            if endpoint == "/orgs/testorg/repos":
                return [
                    {
                        "id": 1,
                        "name": "repo1",
                        "full_name": "testorg/repo1",
                        "private": False
                    }
                ]
            if endpoint == "/repos/testorg/repo1/actions/runners":
                return [
                    {"id": 10, "name": "repo-runner", "os": "linux", "status": "offline", "labels": [{"name": "test"}]}
                ]
            return []

        mock_api_client.get.side_effect = mock_get
        mock_api_client.get_paginated.side_effect = mock_get_paginated

        result = enumerator.enumerate_organization("testorg")

        assert result["repositories"][0]["runners"]
        assert result["repositories"][0]["runners"][0]["name"] == "repo-runner"

