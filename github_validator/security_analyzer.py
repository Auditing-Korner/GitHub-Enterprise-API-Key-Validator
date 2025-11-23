"""
Security Analysis Module

Provides comprehensive security analysis including:
- Code scanning alerts
- Secret scanning alerts
- Dependabot alerts
- Security advisories
- Repository security settings
- Branch protection rules
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class SecurityAnalyzer:
    """Analyzes security-related resources and settings."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_security(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze security settings and alerts for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with security analysis results
        """
        security_data = {
            "repository": repo_full_name,
            "code_scanning_alerts": [],
            "secret_scanning_alerts": [],
            "dependabot_alerts": [],
            "security_advisories": [],
            "branch_protection": {},
            "vulnerability_alerts": False,
            "secret_scanning": False,
            "code_scanning": False,
            "errors": []
        }
        
        # Get code scanning alerts
        try:
            code_alerts = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/code-scanning/alerts",
                params={"state": "open"}
            )
            security_data["code_scanning_alerts"] = [
                {
                    "number": alert.get("number", ""),
                    "rule": alert.get("rule", {}).get("id", ""),
                    "severity": alert.get("rule", {}).get("severity", ""),
                    "state": alert.get("state", ""),
                    "created_at": alert.get("created_at", ""),
                    "tool": alert.get("tool", {}).get("name", ""),
                    "most_recent_instance": {
                        "ref": alert.get("most_recent_instance", {}).get("ref", ""),
                        "location": alert.get("most_recent_instance", {}).get("location", {})
                    } if alert.get("most_recent_instance") else {}
                }
                for alert in code_alerts[:50]  # Limit for performance
            ]
            security_data["code_scanning"] = len(security_data["code_scanning_alerts"]) > 0
        except Exception as e:
            security_data["errors"].append(f"Code scanning alerts: {str(e)}")
        
        # Get secret scanning alerts
        try:
            secret_alerts = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/secret-scanning/alerts",
                params={"state": "open"}
            )
            security_data["secret_scanning_alerts"] = [
                {
                    "number": alert.get("number", ""),
                    "secret_type": alert.get("secret_type", ""),
                    "state": alert.get("state", ""),
                    "created_at": alert.get("created_at", ""),
                    "updated_at": alert.get("updated_at", ""),
                    "resolved_at": alert.get("resolved_at", ""),
                    "resolution": alert.get("resolution", ""),
                    "location": alert.get("location", {})
                }
                for alert in secret_alerts[:50]  # Limit for performance
            ]
            security_data["secret_scanning"] = len(security_data["secret_scanning_alerts"]) > 0
        except Exception as e:
            security_data["errors"].append(f"Secret scanning alerts: {str(e)}")
        
        # Get Dependabot alerts
        try:
            dependabot_alerts = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/dependabot/alerts",
                params={"state": "open"}
            )
            security_data["dependabot_alerts"] = [
                {
                    "number": alert.get("number", ""),
                    "state": alert.get("state", ""),
                    "dependency": {
                        "package": alert.get("dependency", {}).get("package", {}).get("name", ""),
                        "ecosystem": alert.get("dependency", {}).get("package", {}).get("ecosystem", ""),
                        "manifest_path": alert.get("dependency", {}).get("manifest_path", "")
                    },
                    "security_advisory": {
                        "ghsa_id": alert.get("security_advisory", {}).get("ghsa_id", ""),
                        "severity": alert.get("security_advisory", {}).get("severity", ""),
                        "summary": alert.get("security_advisory", {}).get("summary", ""),
                        "cvss": alert.get("security_advisory", {}).get("cvss", {}).get("score", 0)
                    } if alert.get("security_advisory") else {},
                    "created_at": alert.get("created_at", ""),
                    "updated_at": alert.get("updated_at", "")
                }
                for alert in dependabot_alerts[:50]  # Limit for performance
            ]
        except Exception as e:
            security_data["errors"].append(f"Dependabot alerts: {str(e)}")
        
        # Get security advisories
        try:
            advisories = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/security-advisories"
            )
            security_data["security_advisories"] = [
                {
                    "ghsa_id": adv.get("ghsa_id", ""),
                    "cve_id": adv.get("cve_id", ""),
                    "summary": adv.get("summary", ""),
                    "severity": adv.get("severity", ""),
                    "state": adv.get("state", ""),
                    "created_at": adv.get("created_at", ""),
                    "updated_at": adv.get("updated_at", ""),
                    "published_at": adv.get("published_at", "")
                }
                for adv in advisories
            ]
        except Exception as e:
            security_data["errors"].append(f"Security advisories: {str(e)}")
        
        # Get branch protection rules
        try:
            branches = self.api_client.get_paginated(f"/repos/{repo_full_name}/branches")
            for branch in branches[:10]:  # Check first 10 branches
                branch_name = branch.get("name", "")
                if branch_name:
                    try:
                        protection = self.api_client.get(
                            f"/repos/{repo_full_name}/branches/{branch_name}/protection"
                        )
                        if protection:
                            security_data["branch_protection"][branch_name] = {
                                "required_status_checks": protection.get("required_status_checks", {}),
                                "enforce_admins": protection.get("enforce_admins", {}).get("enabled", False),
                                "required_pull_request_reviews": protection.get("required_pull_request_reviews", {}),
                                "restrictions": protection.get("restrictions", {}),
                                "allow_force_pushes": protection.get("allow_force_pushes", {}).get("enabled", False),
                                "allow_deletions": protection.get("allow_deletions", {}).get("enabled", False)
                            }
                    except Exception:
                        pass  # Branch may not have protection
        except Exception as e:
            security_data["errors"].append(f"Branch protection: {str(e)}")
        
        # Check if vulnerability alerts are enabled
        try:
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            security_data["vulnerability_alerts"] = repo_info.get("allow_vulnerability_alerts", False) if repo_info else False
        except Exception:
            pass
        
        return security_data
    
    def analyze_org_security(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze security settings for an organization.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with organization security analysis
        """
        org_security = {
            "organization": org_name,
            "code_scanning_default_setup": {},
            "secret_scanning_enabled": False,
            "advanced_security_enabled": False,
            "dependabot_alerts_enabled": False,
            "errors": []
        }
        
        # Get code scanning default setup
        try:
            code_scanning = self.api_client.get(f"/orgs/{org_name}/code-scanning/default-setup")
            if code_scanning:
                org_security["code_scanning_default_setup"] = {
                    "state": code_scanning.get("state", ""),
                    "query_suite": code_scanning.get("query_suite", ""),
                    "updated_at": code_scanning.get("updated_at", "")
                }
        except Exception:
            pass
        
        # Get organization settings (may require admin access)
        try:
            org_info = self.api_client.get(f"/orgs/{org_name}")
            if org_info:
                # Note: These fields may not be directly available in org info
                # They might require specific endpoints or admin access
                pass
        except Exception:
            pass
        
        return org_security
    
    def analyze_all_repos_security(self, max_repos: int = 100) -> Dict[str, Any]:
        """
        Analyze security across all accessible repositories.
        
        Args:
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with comprehensive security analysis
        """
        all_security = {
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_code_scanning_alerts": 0,
                "total_secret_scanning_alerts": 0,
                "total_dependabot_alerts": 0,
                "repos_with_vulnerabilities": 0,
                "repos_with_secrets_exposed": 0,
                "repos_with_code_issues": 0,
                "repos_with_branch_protection": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated("/user/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_security = self.analyze_repo_security(repo_full_name)
                        all_security["repositories"][repo_full_name] = repo_security
                        
                        # Update summary
                        all_security["summary"]["total_repos_analyzed"] += 1
                        all_security["summary"]["total_code_scanning_alerts"] += len(repo_security.get("code_scanning_alerts", []))
                        all_security["summary"]["total_secret_scanning_alerts"] += len(repo_security.get("secret_scanning_alerts", []))
                        all_security["summary"]["total_dependabot_alerts"] += len(repo_security.get("dependabot_alerts", []))
                        
                        if repo_security.get("dependabot_alerts"):
                            all_security["summary"]["repos_with_vulnerabilities"] += 1
                        if repo_security.get("secret_scanning_alerts"):
                            all_security["summary"]["repos_with_secrets_exposed"] += 1
                        if repo_security.get("code_scanning_alerts"):
                            all_security["summary"]["repos_with_code_issues"] += 1
                        if repo_security.get("branch_protection"):
                            all_security["summary"]["repos_with_branch_protection"] += 1
                    except Exception as e:
                        all_security["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            all_security["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return all_security

