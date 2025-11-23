"""
Tests for Enterprise Runner Inspector.
"""

from unittest.mock import Mock

from github_validator.runners import EnterpriseRunnerInspector
from github_validator.api_client import GitHubAPIClient


class TestEnterpriseRunnerInspector:
    """Test cases for enterprise runner telemetry collection."""

    def test_fetch_runners_aggregates_status_and_labels(self):
        """Inspector should aggregate basic counts."""
        mock_client = Mock(spec=GitHubAPIClient)
        mock_client.get.side_effect = [
            {
                "runners": [
                    {"id": 1, "status": "online", "labels": [{"name": "appsec"}], "os": "linux"},
                    {"id": 2, "status": "offline", "labels": [{"name": "build"}], "os": "linux"},
                ]
            }
        ]

        inspector = EnterpriseRunnerInspector(mock_client, "enterprise")
        data = inspector.fetch_runners()

        assert data["total_runners"] == 2
        assert data["status_counts"]["online"] == 1
        assert data["label_counts"]["appsec"] == 1
        assert data["label_online_counts"]["appsec"] == 1
        mock_client.get.assert_called_once()

    def test_fetch_runners_respects_max_pages(self):
        """Inspector stops when max_pages reached even if more data available."""
        mock_client = Mock(spec=GitHubAPIClient)
        # First page returns 100 entries to trigger pagination
        first_page = [{"id": i, "status": "online", "labels": [], "os": "linux"} for i in range(100)]
        mock_client.get.side_effect = [
            {"runners": first_page},
            {"runners": [{"id": 200, "status": "online", "labels": [], "os": "linux"}]},
        ]

        inspector = EnterpriseRunnerInspector(mock_client, "enterprise")
        data = inspector.fetch_runners(max_pages=1)

        assert data["total_runners"] == 100
        assert mock_client.get.call_count == 1

