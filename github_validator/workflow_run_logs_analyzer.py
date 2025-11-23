"""
Workflow Run Logs Analysis Module

Analyzes workflow run logs including:
- Detailed workflow logs
- Log content analysis
- Workflow execution details
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class WorkflowRunLogsAnalyzer:
    """Analyzes workflow run logs."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_workflow_logs(self, repo_full_name: str, max_runs: int = 10) -> Dict[str, Any]:
        """
        Analyze workflow run logs for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_runs: Maximum number of workflow runs to analyze
            
        Returns:
            Dictionary with workflow logs analysis
        """
        logs_data = {
            "repository": repo_full_name,
            "workflow_runs": [],
            "summary": {
                "total_runs_analyzed": 0,
                "runs_with_logs": 0,
                "successful_runs": 0,
                "failed_runs": 0,
                "cancelled_runs": 0
            },
            "errors": []
        }
        
        try:
            # Get workflow runs
            runs = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/actions/runs",
                params={"per_page": 100}
            )
            
            for run in runs[:max_runs]:
                run_id = run.get("id", "")
                run_info = {
                    "id": run_id,
                    "name": run.get("name", ""),
                    "workflow_id": run.get("workflow_id", ""),
                    "status": run.get("status", ""),
                    "conclusion": run.get("conclusion", ""),
                    "created_at": run.get("created_at", ""),
                    "updated_at": run.get("updated_at", ""),
                    "run_started_at": run.get("run_started_at", ""),
                    "jobs": [],
                    "logs_accessible": False
                }
                
                # Get jobs for this run
                try:
                    jobs = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/actions/runs/{run_id}/jobs"
                    )
                    for job in jobs[:5]:  # Limit to 5 jobs per run
                        job_info = {
                            "id": job.get("id", ""),
                            "name": job.get("name", ""),
                            "status": job.get("status", ""),
                            "conclusion": job.get("conclusion", ""),
                            "steps": len(job.get("steps", []))
                        }
                        run_info["jobs"].append(job_info)
                    
                    # Check if logs are accessible (we can't download them, but check if they exist)
                    try:
                        # Try to get logs URL (this will fail if logs are expired)
                        logs_url = self.api_client.get(f"/repos/{repo_full_name}/actions/runs/{run_id}/logs")
                        run_info["logs_accessible"] = logs_url is not None
                        if run_info["logs_accessible"]:
                            logs_data["summary"]["runs_with_logs"] += 1
                    except Exception:
                        run_info["logs_accessible"] = False
                except Exception as e:
                    logs_data["errors"].append(f"Failed to get jobs for run {run_id}: {str(e)}")
                
                logs_data["workflow_runs"].append(run_info)
                logs_data["summary"]["total_runs_analyzed"] += 1
                
                # Track run status
                conclusion = run_info["conclusion"]
                if conclusion == "success":
                    logs_data["summary"]["successful_runs"] += 1
                elif conclusion == "failure":
                    logs_data["summary"]["failed_runs"] += 1
                elif conclusion == "cancelled":
                    logs_data["summary"]["cancelled_runs"] += 1
        except Exception as e:
            logs_data["errors"].append(f"Failed to get workflow runs: {str(e)}")
        
        return logs_data
    
    def analyze_org_workflow_logs(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze workflow logs across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide workflow logs analysis
        """
        org_logs = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_runs": 0,
                "runs_with_logs": 0,
                "successful_runs": 0,
                "failed_runs": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_logs = self.analyze_repo_workflow_logs(repo_full_name, max_runs=5)
                        org_logs["repositories"][repo_full_name] = repo_logs
                        
                        # Update summary
                        org_logs["summary"]["total_repos_analyzed"] += 1
                        org_logs["summary"]["total_runs"] += repo_logs["summary"]["total_runs_analyzed"]
                        org_logs["summary"]["runs_with_logs"] += repo_logs["summary"]["runs_with_logs"]
                        org_logs["summary"]["successful_runs"] += repo_logs["summary"]["successful_runs"]
                        org_logs["summary"]["failed_runs"] += repo_logs["summary"]["failed_runs"]
                    except Exception as e:
                        org_logs["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_logs["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_logs

