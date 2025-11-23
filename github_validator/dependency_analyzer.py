"""
Dependency Analysis Module

Analyzes repository dependencies including:
- Dependency graph
- Dependency insights
- Vulnerable dependencies
- Dependency licenses
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class DependencyAnalyzer:
    """Analyzes repository dependencies and dependency graph."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_dependencies(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze repository dependencies.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with dependency analysis
        """
        dependency_data = {
            "repository": repo_full_name,
            "dependency_graph": {},
            "dependencies": [],
            "vulnerabilities": [],
            "summary": {
                "total_dependencies": 0,
                "vulnerable_dependencies": 0,
                "package_managers": set(),
                "licenses": set()
            },
            "errors": []
        }
        
        try:
            # Get dependency graph manifest files
            manifests = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/dependency-graph/manifests"
            )
            
            for manifest in manifests:
                manifest_info = {
                    "path": manifest.get("path", ""),
                    "resolved": manifest.get("resolved", {}),
                    "filename": manifest.get("filename", "")
                }
                
                # Get dependencies for this manifest
                try:
                    dependencies = self.api_client.get(
                        f"/repos/{repo_full_name}/dependency-graph/sbom"
                    )
                    if dependencies:
                        # Parse SBOM data if available
                        dependency_data["dependency_graph"][manifest.get("path", "")] = dependencies
                except Exception:
                    pass
        except Exception as e:
            dependency_data["errors"].append(f"Dependency graph: {str(e)}")
        
        # Get Dependabot alerts (which include dependency vulnerabilities)
        try:
            alerts = self.api_client.get_paginated(f"/repos/{repo_full_name}/dependabot/alerts")
            for alert in alerts[:50]:  # Limit to 50 alerts
                if alert.get("state") == "open":
                    vulnerability = {
                        "number": alert.get("number", ""),
                        "dependency": {
                            "package": alert.get("dependency", {}).get("package", {}).get("name", ""),
                            "ecosystem": alert.get("dependency", {}).get("package", {}).get("ecosystem", "")
                        } if alert.get("dependency") else {},
                        "security_vulnerability": {
                            "severity": alert.get("security_vulnerability", {}).get("severity", ""),
                            "summary": alert.get("security_vulnerability", {}).get("summary", "")
                        } if alert.get("security_vulnerability") else {},
                        "state": alert.get("state", ""),
                        "created_at": alert.get("created_at", "")
                    }
                    dependency_data["vulnerabilities"].append(vulnerability)
                    dependency_data["summary"]["vulnerable_dependencies"] += 1
        except Exception as e:
            dependency_data["errors"].append(f"Dependabot alerts: {str(e)}")
        
        return dependency_data
    
    def analyze_org_dependencies(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze dependencies across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide dependency analysis
        """
        org_dependencies = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_vulnerable_dependencies": 0,
                "repos_with_vulnerabilities": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_deps = self.analyze_repo_dependencies(repo_full_name)
                        org_dependencies["repositories"][repo_full_name] = repo_deps
                        
                        # Update summary
                        org_dependencies["summary"]["total_repos_analyzed"] += 1
                        org_dependencies["summary"]["total_vulnerable_dependencies"] += repo_deps["summary"]["vulnerable_dependencies"]
                        
                        if repo_deps["summary"]["vulnerable_dependencies"] > 0:
                            org_dependencies["summary"]["repos_with_vulnerabilities"] += 1
                    except Exception as e:
                        org_dependencies["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_dependencies["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_dependencies

