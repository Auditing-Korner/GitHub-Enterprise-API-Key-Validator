"""
GitHub Actions Detection Module

Provides comprehensive detection and enumeration of GitHub Actions:
workflows, runs, artifacts, secrets, and runner configurations.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from .api_client import GitHubAPIClient


class ActionsDetector:
    """Detects and enumerates GitHub Actions resources."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def detect_repo_actions(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Detect all GitHub Actions resources for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with workflows, runs, artifacts, secrets, etc.
        """
        actions_data = {
            "repository": repo_full_name,
            "workflows": [],
            "workflow_runs": [],
            "artifacts": [],
            "secrets": [],
            "variables": [],
            "runners": [],
            "permissions": {},
            "usage": {},
            "errors": []
        }
        
        # Get workflows
        try:
            workflows_response = self.api_client.get(f"/repos/{repo_full_name}/actions/workflows")
            if workflows_response and workflows_response.get("workflows"):
                for workflow in workflows_response.get("workflows", []):
                    workflow_id = workflow.get("id")
                    workflow_data = {
                        "id": workflow_id,
                        "name": workflow.get("name", ""),
                        "path": workflow.get("path", ""),
                        "state": workflow.get("state", ""),
                        "created_at": workflow.get("created_at", ""),
                        "updated_at": workflow.get("updated_at", ""),
                        "url": workflow.get("url", ""),
                        "html_url": workflow.get("html_url", ""),
                        "badge_url": workflow.get("badge_url", ""),
                        "runs": []
                    }
                    
                    # Get workflow runs (recent runs)
                    try:
                        runs_response = self.api_client.get(
                            f"/repos/{repo_full_name}/actions/workflows/{workflow_id}/runs",
                            params={"per_page": 10}
                        )
                        if runs_response and runs_response.get("workflow_runs"):
                            for run in runs_response.get("workflow_runs", [])[:10]:
                                run_data = {
                                    "id": run.get("id", ""),
                                    "name": run.get("name", ""),
                                    "head_branch": run.get("head_branch", ""),
                                    "head_sha": run.get("head_sha", ""),
                                    "status": run.get("status", ""),
                                    "conclusion": run.get("conclusion", ""),
                                    "created_at": run.get("created_at", ""),
                                    "updated_at": run.get("updated_at", ""),
                                    "run_number": run.get("run_number", 0),
                                    "event": run.get("event", ""),
                                    "actor": {
                                        "login": run.get("actor", {}).get("login", ""),
                                        "type": run.get("actor", {}).get("type", "")
                                    } if run.get("actor") else {},
                                    "artifacts": []
                                }
                                
                                # Get artifacts for this run
                                try:
                                    artifacts_response = self.api_client.get(
                                        f"/repos/{repo_full_name}/actions/runs/{run.get('id')}/artifacts"
                                    )
                                    if artifacts_response and artifacts_response.get("artifacts"):
                                        run_data["artifacts"] = [
                                            {
                                                "id": a.get("id", ""),
                                                "name": a.get("name", ""),
                                                "size_in_bytes": a.get("size_in_bytes", 0),
                                                "created_at": a.get("created_at", ""),
                                                "expires_at": a.get("expires_at", "")
                                            }
                                            for a in artifacts_response.get("artifacts", [])
                                        ]
                                        actions_data["artifacts"].extend(run_data["artifacts"])
                                except Exception:
                                    pass
                                
                                workflow_data["runs"].append(run_data)
                                actions_data["workflow_runs"].append(run_data)
                    except Exception as e:
                        actions_data["errors"].append(f"Failed to get runs for workflow {workflow_id}: {str(e)}")
                    
                    actions_data["workflows"].append(workflow_data)
        except Exception as e:
            actions_data["errors"].append(f"Failed to get workflows: {str(e)}")
        
        # Get repository secrets
        try:
            secrets = self.api_client.get_paginated(f"/repos/{repo_full_name}/actions/secrets")
            actions_data["secrets"] = [
                {
                    "name": s.get("name", ""),
                    "created_at": s.get("created_at", ""),
                    "updated_at": s.get("updated_at", "")
                }
                for s in secrets
            ]
        except Exception:
            pass
        
        # Get repository variables
        try:
            variables = self.api_client.get_paginated(f"/repos/{repo_full_name}/actions/variables")
            actions_data["variables"] = [
                {
                    "name": v.get("name", ""),
                    "value": v.get("value", ""),  # May be empty if no access
                    "created_at": v.get("created_at", ""),
                    "updated_at": v.get("updated_at", "")
                }
                for v in variables
            ]
        except Exception:
            pass
        
        # Get repository runners
        try:
            runners = self.api_client.get_paginated(f"/repos/{repo_full_name}/actions/runners")
            actions_data["runners"] = [
                {
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "os": r.get("os", ""),
                    "status": r.get("status", ""),
                    "busy": r.get("busy", False),
                    "labels": [label.get("name", "") for label in r.get("labels", [])]
                }
                for r in runners
            ]
        except Exception:
            pass
        
        # Get repository permissions (if accessible)
        try:
            permissions = self.api_client.get(f"/repos/{repo_full_name}/actions/permissions")
            if permissions:
                actions_data["permissions"] = {
                    "enabled": permissions.get("enabled", False),
                    "allowed_actions": permissions.get("allowed_actions", ""),
                    "selected_actions_url": permissions.get("selected_actions_url", "")
                }
        except Exception:
            pass
        
        # Calculate usage statistics
        actions_data["usage"] = {
            "total_workflows": len(actions_data["workflows"]),
            "total_runs": len(actions_data["workflow_runs"]),
            "total_artifacts": len(actions_data["artifacts"]),
            "total_secrets": len(actions_data["secrets"]),
            "total_variables": len(actions_data["variables"]),
            "total_runners": len(actions_data["runners"]),
            "active_workflows": len([w for w in actions_data["workflows"] if w.get("state") == "active"]),
            "recent_runs": len([r for r in actions_data["workflow_runs"] if self._is_recent(r.get("created_at", ""))])
        }
        
        return actions_data
    
    def detect_org_actions(self, org_name: str) -> Dict[str, Any]:
        """
        Detect all GitHub Actions resources for an organization.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with org-level Actions resources
        """
        org_actions = {
            "organization": org_name,
            "secrets": [],
            "variables": [],
            "runners": [],
            "runner_groups": [],
            "permissions": {},
            "usage": {},
            "errors": []
        }
        
        # Get organization secrets
        try:
            secrets = self.api_client.get_paginated(f"/orgs/{org_name}/actions/secrets")
            org_actions["secrets"] = [
                {
                    "name": s.get("name", ""),
                    "visibility": s.get("visibility", ""),
                    "selected_repositories_url": s.get("selected_repositories_url", ""),
                    "created_at": s.get("created_at", ""),
                    "updated_at": s.get("updated_at", "")
                }
                for s in secrets
            ]
        except Exception:
            pass
        
        # Get organization variables
        try:
            variables = self.api_client.get_paginated(f"/orgs/{org_name}/actions/variables")
            org_actions["variables"] = [
                {
                    "name": v.get("name", ""),
                    "visibility": v.get("visibility", ""),
                    "selected_repositories_url": v.get("selected_repositories_url", ""),
                    "created_at": v.get("created_at", ""),
                    "updated_at": v.get("updated_at", "")
                }
                for v in variables
            ]
        except Exception:
            pass
        
        # Get organization runners
        try:
            runners = self.api_client.get_paginated(f"/orgs/{org_name}/actions/runners")
            org_actions["runners"] = [
                {
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "os": r.get("os", ""),
                    "status": r.get("status", ""),
                    "busy": r.get("busy", False),
                    "labels": [label.get("name", "") for label in r.get("labels", [])]
                }
                for r in runners
            ]
        except Exception:
            pass
        
        # Get runner groups (if accessible)
        try:
            runner_groups = self.api_client.get_paginated(f"/orgs/{org_name}/actions/runner-groups")
            org_actions["runner_groups"] = [
                {
                    "id": rg.get("id", ""),
                    "name": rg.get("name", ""),
                    "visibility": rg.get("visibility", ""),
                    "default": rg.get("default", False),
                    "runners_url": rg.get("runners_url", ""),
                    "allows_public_repositories": rg.get("allows_public_repositories", False)
                }
                for rg in runner_groups
            ]
        except Exception:
            pass
        
        # Get organization permissions
        try:
            permissions = self.api_client.get(f"/orgs/{org_name}/actions/permissions")
            if permissions:
                org_actions["permissions"] = {
                    "enabled_repositories": permissions.get("enabled_repositories", ""),
                    "allowed_actions": permissions.get("allowed_actions", ""),
                    "selected_actions_url": permissions.get("selected_actions_url", "")
                }
        except Exception:
            pass
        
        # Calculate usage
        org_actions["usage"] = {
            "total_secrets": len(org_actions["secrets"]),
            "total_variables": len(org_actions["variables"]),
            "total_runners": len(org_actions["runners"]),
            "total_runner_groups": len(org_actions["runner_groups"]),
            "online_runners": len([r for r in org_actions["runners"] if r.get("status", "").lower() == "online"])
        }
        
        return org_actions
    
    def detect_all_accessible_actions(self) -> Dict[str, Any]:
        """
        Detect GitHub Actions across all accessible repositories and organizations.
        
        Returns:
            Dictionary with comprehensive Actions detection results
        """
        all_actions = {
            "repositories": {},
            "organizations": {},
            "summary": {
                "total_repos_with_actions": 0,
                "total_workflows": 0,
                "total_runs": 0,
                "total_artifacts": 0,
                "total_secrets": 0,
                "total_orgs_with_actions": 0
            },
            "errors": []
        }
        
        # Get all accessible repositories
        try:
            repos = self.api_client.get_paginated("/user/repos")
            # Limit to first 100 repos for performance
            for repo in repos[:100]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_actions = self.detect_repo_actions(repo_full_name)
                        all_actions["repositories"][repo_full_name] = repo_actions
                        
                        if repo_actions["usage"]["total_workflows"] > 0:
                            all_actions["summary"]["total_repos_with_actions"] += 1
                            all_actions["summary"]["total_workflows"] += repo_actions["usage"]["total_workflows"]
                            all_actions["summary"]["total_runs"] += repo_actions["usage"]["total_runs"]
                            all_actions["summary"]["total_artifacts"] += repo_actions["usage"]["total_artifacts"]
                            all_actions["summary"]["total_secrets"] += repo_actions["usage"]["total_secrets"]
                    except Exception as e:
                        all_actions["errors"].append(f"Failed to detect actions for {repo_full_name}: {str(e)}")
        except Exception as e:
            all_actions["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Get all accessible organizations
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs:
                org_name = org.get("login", "")
                if org_name:
                    try:
                        org_actions = self.detect_org_actions(org_name)
                        all_actions["organizations"][org_name] = org_actions
                        
                        if org_actions["usage"]["total_secrets"] > 0 or org_actions["usage"]["total_runners"] > 0:
                            all_actions["summary"]["total_orgs_with_actions"] += 1
                    except Exception as e:
                        all_actions["errors"].append(f"Failed to detect org actions for {org_name}: {str(e)}")
        except Exception as e:
            all_actions["errors"].append(f"Failed to get organizations: {str(e)}")
        
        return all_actions
    
    def _is_recent(self, date_str: str, days: int = 30) -> bool:
        """Check if a date string is within the last N days."""
        if not date_str:
            return False
        try:
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return (datetime.now(date_obj.tzinfo) - date_obj).days <= days
        except Exception:
            return False

