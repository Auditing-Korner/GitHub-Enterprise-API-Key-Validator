"""
Code Scanning Alerts Analysis Module

Analyzes code scanning alerts including:
- Detailed code scanning alerts
- Alert severity and status
- Alert rule information
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class CodeScanningAlertsAnalyzer:
    """Analyzes code scanning alerts."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_code_alerts(self, repo_full_name: str, max_alerts: int = 50) -> Dict[str, Any]:
        """
        Analyze code scanning alerts for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_alerts: Maximum number of alerts to analyze
            
        Returns:
            Dictionary with code scanning alerts analysis
        """
        alerts_data = {
            "repository": repo_full_name,
            "alerts": [],
            "summary": {
                "total_alerts": 0,
                "open_alerts": 0,
                "dismissed_alerts": 0,
                "fixed_alerts": 0,
                "alerts_by_severity": {},
                "alerts_by_rule": {}
            },
            "errors": []
        }
        
        try:
            # Get code scanning alerts
            alerts = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/code-scanning/alerts",
                params={"per_page": 100, "state": "all"}
            )
            
            for alert in alerts[:max_alerts]:
                alert_info = {
                    "number": alert.get("number", ""),
                    "state": alert.get("state", ""),
                    "severity": alert.get("rule", {}).get("severity", "") if alert.get("rule") else "",
                    "rule": {
                        "id": alert.get("rule", {}).get("id", ""),
                        "name": alert.get("rule", {}).get("name", ""),
                        "severity": alert.get("rule", {}).get("severity", "")
                    } if alert.get("rule") else {},
                    "tool": {
                        "name": alert.get("tool", {}).get("name", ""),
                        "version": alert.get("tool", {}).get("version", "")
                    } if alert.get("tool") else {},
                    "created_at": alert.get("created_at", ""),
                    "updated_at": alert.get("updated_at", ""),
                    "dismissed_at": alert.get("dismissed_at", ""),
                    "dismissed_by": alert.get("dismissed_by", {}).get("login", "") if alert.get("dismissed_by") else "",
                    "dismissed_reason": alert.get("dismissed_reason", ""),
                    "most_recent_instance": {
                        "ref": alert.get("most_recent_instance", {}).get("ref", ""),
                        "state": alert.get("most_recent_instance", {}).get("state", "")
                    } if alert.get("most_recent_instance") else {}
                }
                
                alerts_data["alerts"].append(alert_info)
                alerts_data["summary"]["total_alerts"] += 1
                
                # Track by state
                state = alert_info["state"]
                if state == "open":
                    alerts_data["summary"]["open_alerts"] += 1
                elif state == "dismissed":
                    alerts_data["summary"]["dismissed_alerts"] += 1
                elif state == "fixed":
                    alerts_data["summary"]["fixed_alerts"] += 1
                
                # Track by severity
                severity = alert_info["severity"] or "unknown"
                alerts_data["summary"]["alerts_by_severity"][severity] = alerts_data["summary"]["alerts_by_severity"].get(severity, 0) + 1
                
                # Track by rule
                rule_id = alert_info["rule"].get("id", "") or "unknown"
                alerts_data["summary"]["alerts_by_rule"][rule_id] = alerts_data["summary"]["alerts_by_rule"].get(rule_id, 0) + 1
        except Exception as e:
            alerts_data["errors"].append(f"Failed to get code scanning alerts: {str(e)}")
        
        return alerts_data
    
    def analyze_org_code_alerts(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze code scanning alerts across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide code scanning alerts analysis
        """
        org_alerts = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_alerts": 0,
                "open_alerts": 0,
                "dismissed_alerts": 0,
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
                        repo_alerts = self.analyze_repo_code_alerts(repo_full_name, max_alerts=30)
                        org_alerts["repositories"][repo_full_name] = repo_alerts
                        
                        # Update summary
                        org_alerts["summary"]["total_repos_analyzed"] += 1
                        org_alerts["summary"]["total_alerts"] += repo_alerts["summary"]["total_alerts"]
                        org_alerts["summary"]["open_alerts"] += repo_alerts["summary"]["open_alerts"]
                        org_alerts["summary"]["dismissed_alerts"] += repo_alerts["summary"]["dismissed_alerts"]
                        
                        if repo_alerts["summary"]["total_alerts"] > 0:
                            org_alerts["summary"]["repos_with_alerts"] += 1
                    except Exception as e:
                        org_alerts["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_alerts["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_alerts

