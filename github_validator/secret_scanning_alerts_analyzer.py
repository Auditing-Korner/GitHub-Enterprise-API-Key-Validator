"""
Secret Scanning Alerts Analysis Module

Analyzes secret scanning alerts including:
- Detailed secret scanning alerts
- Alert remediation status
- Alert severity and types
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class SecretScanningAlertsAnalyzer:
    """Analyzes secret scanning alerts."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_secret_alerts(self, repo_full_name: str, max_alerts: int = 50) -> Dict[str, Any]:
        """
        Analyze secret scanning alerts for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_alerts: Maximum number of alerts to analyze
            
        Returns:
            Dictionary with secret scanning alerts analysis
        """
        alerts_data = {
            "repository": repo_full_name,
            "alerts": [],
            "summary": {
                "total_alerts": 0,
                "open_alerts": 0,
                "resolved_alerts": 0,
                "alerts_by_secret_type": {},
                "alerts_by_severity": {}
            },
            "errors": []
        }
        
        try:
            # Get secret scanning alerts
            alerts = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/secret-scanning/alerts",
                params={"per_page": 100, "state": "all"}
            )
            
            for alert in alerts[:max_alerts]:
                alert_info = {
                    "number": alert.get("number", ""),
                    "state": alert.get("state", ""),
                    "secret_type": alert.get("secret_type", ""),
                    "secret_type_display_name": alert.get("secret_type_display_name", ""),
                    "created_at": alert.get("created_at", ""),
                    "updated_at": alert.get("updated_at", ""),
                    "resolved_at": alert.get("resolved_at", ""),
                    "resolution": alert.get("resolution", ""),
                    "location": {
                        "path": alert.get("location", {}).get("path", ""),
                        "start_line": alert.get("location", {}).get("start_line"),
                        "end_line": alert.get("location", {}).get("end_line")
                    } if alert.get("location") else {}
                }
                
                alerts_data["alerts"].append(alert_info)
                alerts_data["summary"]["total_alerts"] += 1
                
                if alert_info["state"] == "open":
                    alerts_data["summary"]["open_alerts"] += 1
                else:
                    alerts_data["summary"]["resolved_alerts"] += 1
                
                # Track by secret type
                secret_type = alert_info["secret_type"] or "unknown"
                alerts_data["summary"]["alerts_by_secret_type"][secret_type] = alerts_data["summary"]["alerts_by_secret_type"].get(secret_type, 0) + 1
        except Exception as e:
            alerts_data["errors"].append(f"Failed to get secret scanning alerts: {str(e)}")
        
        return alerts_data
    
    def analyze_org_secret_alerts(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze secret scanning alerts across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide secret scanning alerts analysis
        """
        org_alerts = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_alerts": 0,
                "open_alerts": 0,
                "resolved_alerts": 0,
                "repos_with_alerts": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_alerts = self.analyze_repo_secret_alerts(repo_full_name, max_alerts=30)
                        org_alerts["repositories"][repo_full_name] = repo_alerts
                        
                        # Update summary
                        org_alerts["summary"]["total_repos_analyzed"] += 1
                        org_alerts["summary"]["total_alerts"] += repo_alerts["summary"]["total_alerts"]
                        org_alerts["summary"]["open_alerts"] += repo_alerts["summary"]["open_alerts"]
                        org_alerts["summary"]["resolved_alerts"] += repo_alerts["summary"]["resolved_alerts"]
                        
                        if repo_alerts["summary"]["total_alerts"] > 0:
                            org_alerts["summary"]["repos_with_alerts"] += 1
                    except Exception as e:
                        org_alerts["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_alerts["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_alerts

