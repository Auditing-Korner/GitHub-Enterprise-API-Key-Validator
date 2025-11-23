"""
Artifact Details Analysis Module

Analyzes artifact details including:
- Artifact metadata
- Artifact download capabilities
- Artifact size and expiration
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class ArtifactDetailsAnalyzer:
    """Analyzes artifact details."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_artifacts(self, repo_full_name: str, max_artifacts: int = 50) -> Dict[str, Any]:
        """
        Analyze artifacts for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_artifacts: Maximum number of artifacts to analyze
            
        Returns:
            Dictionary with artifacts analysis
        """
        artifacts_data = {
            "repository": repo_full_name,
            "artifacts": [],
            "summary": {
                "total_artifacts": 0,
                "total_size": 0,
                "expired_artifacts": 0,
                "active_artifacts": 0,
                "artifacts_by_workflow": {}
            },
            "errors": []
        }
        
        try:
            # Get artifacts
            artifacts = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/actions/artifacts",
                params={"per_page": 100}
            )
            
            for artifact in artifacts[:max_artifacts]:
                artifact_info = {
                    "id": artifact.get("id", ""),
                    "name": artifact.get("name", ""),
                    "size_in_bytes": artifact.get("size_in_bytes", 0),
                    "archive_download_url": artifact.get("archive_download_url", ""),
                    "expired": artifact.get("expired", False),
                    "created_at": artifact.get("created_at", ""),
                    "updated_at": artifact.get("updated_at", ""),
                    "expires_at": artifact.get("expires_at", ""),
                    "workflow_run": {
                        "id": artifact.get("workflow_run", {}).get("id", ""),
                        "repository_id": artifact.get("workflow_run", {}).get("repository_id", "")
                    } if artifact.get("workflow_run") else {}
                }
                
                artifacts_data["artifacts"].append(artifact_info)
                artifacts_data["summary"]["total_artifacts"] += 1
                artifacts_data["summary"]["total_size"] += artifact_info["size_in_bytes"]
                
                if artifact_info["expired"]:
                    artifacts_data["summary"]["expired_artifacts"] += 1
                else:
                    artifacts_data["summary"]["active_artifacts"] += 1
                
                # Track by workflow run
                workflow_id = artifact_info["workflow_run"].get("id", "")
                if workflow_id:
                    artifacts_data["summary"]["artifacts_by_workflow"][workflow_id] = artifacts_data["summary"]["artifacts_by_workflow"].get(workflow_id, 0) + 1
        except Exception as e:
            artifacts_data["errors"].append(f"Failed to get artifacts: {str(e)}")
        
        return artifacts_data
    
    def analyze_org_artifacts(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze artifacts across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide artifacts analysis
        """
        org_artifacts = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_artifacts": 0,
                "total_size": 0,
                "repos_with_artifacts": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_artifacts = self.analyze_repo_artifacts(repo_full_name, max_artifacts=20)
                        org_artifacts["repositories"][repo_full_name] = repo_artifacts
                        
                        # Update summary
                        org_artifacts["summary"]["total_repos_analyzed"] += 1
                        org_artifacts["summary"]["total_artifacts"] += repo_artifacts["summary"]["total_artifacts"]
                        org_artifacts["summary"]["total_size"] += repo_artifacts["summary"]["total_size"]
                        
                        if repo_artifacts["summary"]["total_artifacts"] > 0:
                            org_artifacts["summary"]["repos_with_artifacts"] += 1
                    except Exception as e:
                        org_artifacts["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_artifacts["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_artifacts

