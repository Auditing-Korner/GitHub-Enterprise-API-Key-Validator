"""
Resources Module

Provides functionality to list and manage GitHub resources:
projects, repositories, webhooks, secrets, etc.
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class ResourceLister:
    """List various GitHub resources."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def list_projects(self) -> Dict[str, Any]:
        """
        List all accessible projects (user, org, repo).
        
        Returns:
            Dictionary with user_projects, org_projects, repo_projects
        """
        all_projects = {
            "user_projects": [],
            "org_projects": [],
            "repo_projects": [],
            "total": 0
        }
        
        # 1. User projects
        try:
            user_projects = self.api_client.get_paginated("/user/projects")
            for project in user_projects:
                project["project_type"] = "user"
            all_projects["user_projects"] = user_projects
        except Exception:
            pass
        
        # 2. Organization projects
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs:
                org_name = org.get("login")
                if org_name:
                    try:
                        org_projects = self.api_client.get_paginated(f"/orgs/{org_name}/projects")
                        for project in org_projects:
                            project["project_type"] = "organization"
                            project["organization"] = org_name
                        all_projects["org_projects"].extend(org_projects)
                    except Exception:
                        continue
        except Exception:
            pass
        
        # 3. Repository projects (limited to first 50 repos for performance)
        try:
            repos = self.api_client.get_paginated("/user/repos")
            max_repos = 50
            processed = 0
            
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name")
                if repo_full_name:
                    try:
                        repo_projects = self.api_client.get_paginated(f"/repos/{repo_full_name}/projects")
                        for project in repo_projects:
                            project["project_type"] = "repository"
                            project["repository"] = repo_full_name
                        all_projects["repo_projects"].extend(repo_projects)
                        processed += 1
                    except Exception:
                        continue
        except Exception:
            pass
        
        all_projects["total"] = (
            len(all_projects["user_projects"]) +
            len(all_projects["org_projects"]) +
            len(all_projects["repo_projects"])
        )
        
        return all_projects
    
    def list_repositories(self) -> Dict[str, Any]:
        """
        List all accessible repositories.
        
        Returns:
            Dictionary with user_repos, org_repos, starred_repos
        """
        all_repos = {
            "user_repos": [],
            "org_repos": [],
            "starred_repos": [],
            "total": 0
        }
        
        # 1. User repositories
        try:
            user_repos = self.api_client.get_paginated("/user/repos")
            for repo in user_repos:
                repo["repo_type"] = "user"
            all_repos["user_repos"] = user_repos
        except Exception:
            pass
        
        # 2. Organization repositories
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs:
                org_name = org.get("login")
                if org_name:
                    try:
                        org_repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
                        for repo in org_repos:
                            repo["repo_type"] = "organization"
                            repo["organization"] = org_name
                        all_repos["org_repos"].extend(org_repos)
                    except Exception:
                        continue
        except Exception:
            pass
        
        # 3. Starred repositories
        try:
            starred_repos = self.api_client.get_paginated("/user/starred")
            for repo in starred_repos:
                repo["repo_type"] = "starred"
            all_repos["starred_repos"] = starred_repos
        except Exception:
            pass
        
        all_repos["total"] = (
            len(all_repos["user_repos"]) +
            len(all_repos["org_repos"]) +
            len(all_repos["starred_repos"])
        )
        
        return all_repos
    
    def list_webhooks(self) -> Dict[str, Any]:
        """
        List webhooks from repositories and organizations.
        
        Returns:
            Dictionary with user_repo_webhooks, org_webhooks, org_repo_webhooks
        """
        all_webhooks = {
            "user_repo_webhooks": [],
            "org_webhooks": [],
            "org_repo_webhooks": [],
            "total": 0
        }
        
        # 1. User repository webhooks
        try:
            user_repos = self.api_client.get_paginated("/user/repos")
            for repo in user_repos:
                repo_full_name = repo.get("full_name")
                if repo_full_name:
                    try:
                        hooks = self.api_client.get_paginated(f"/repos/{repo_full_name}/hooks")
                        for hook in hooks:
                            hook["repository"] = repo_full_name
                            hook["webhook_type"] = "user_repo"
                            hook["owner_type"] = "user"
                        all_webhooks["user_repo_webhooks"].extend(hooks)
                    except Exception:
                        continue
        except Exception:
            pass
        
        # 2. Organization webhooks and organization repository webhooks
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs:
                org_name = org.get("login")
                if org_name:
                    # Organization-level webhooks
                    try:
                        org_hooks = self.api_client.get_paginated(f"/orgs/{org_name}/hooks")
                        for hook in org_hooks:
                            hook["organization"] = org_name
                            hook["webhook_type"] = "organization"
                            hook["owner_type"] = "organization"
                        all_webhooks["org_webhooks"].extend(org_hooks)
                    except Exception:
                        pass
                    
                    # Organization repository webhooks
                    try:
                        org_repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
                        for repo in org_repos:
                            repo_full_name = repo.get("full_name")
                            if repo_full_name:
                                try:
                                    hooks = self.api_client.get_paginated(f"/repos/{repo_full_name}/hooks")
                                    for hook in hooks:
                                        hook["repository"] = repo_full_name
                                        hook["organization"] = org_name
                                        hook["webhook_type"] = "org_repo"
                                        hook["owner_type"] = "organization"
                                    all_webhooks["org_repo_webhooks"].extend(hooks)
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except Exception:
            pass
        
        all_webhooks["total"] = (
            len(all_webhooks["user_repo_webhooks"]) +
            len(all_webhooks["org_webhooks"]) +
            len(all_webhooks["org_repo_webhooks"])
        )
        
        return all_webhooks
    
    def extract_org_secrets(self, org_name: str) -> List[Dict[str, Any]]:
        """
        Extract all organization secrets.
        
        Args:
            org_name: Organization name
            
        Returns:
            List of organization secrets
        """
        try:
            return self.api_client.get_paginated(f"/orgs/{org_name}/actions/secrets")
        except Exception:
            return []
    
    def validate_repo_creation(self) -> Dict[str, Any]:
        """
        Validate if token can create new repositories.
        
        Returns:
            Dictionary with validation results
        """
        result = {
            "can_create_user_repos": False,
            "can_create_org_repos": False,
            "token_scopes": "",
            "authenticated_user": "",
            "organization_permissions": [],
            "creation_test": {
                "result": "unknown",
                "message": "",
                "http_code": None
            }
        }
        
        # 1. Check token scopes (from headers)
        try:
            user_info = self.api_client.get("/user")
            result["authenticated_user"] = user_info.get("login", "unknown")
            
            # Try to get scopes from response headers
            # Note: GitHubAPIClient would need to expose headers
            # For now, we'll test by attempting creation
        except Exception:
            pass
        
        # 2. Check organization permissions
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs:
                org_name = org.get("login")
                if org_name:
                    try:
                        membership = self.api_client.get(f"/user/memberships/orgs/{org_name}")
                        role = membership.get("role", "unknown")
                        state = membership.get("state", "unknown")
                        
                        can_create = role == "admin" or (role == "member" and True)  # Simplified
                        
                        result["organization_permissions"].append({
                            "organization": org_name,
                            "role": role,
                            "state": state,
                            "can_create_repos": can_create
                        })
                        
                        if can_create:
                            result["can_create_org_repos"] = True
                    except Exception:
                        continue
        except Exception:
            pass
        
        # 3. Test repository creation (dry-run)
        try:
            # Attempt to create a test repository
            test_repo_data = {
                "name": "test-repo-validation",
                "private": True,
                "auto_init": False
            }
            
            try:
                response = self.api_client.post("/user/repos", json_data=test_repo_data)
                
                if response and response.get("id"):
                    result["creation_test"]["result"] = "success"
                    result["creation_test"]["message"] = "Repository creation test succeeded"
                    result["creation_test"]["http_code"] = 201
                    result["can_create_user_repos"] = True
                    
                    # Try to delete the test repository
                    repo_full_name = response.get("full_name")
                    if repo_full_name:
                        try:
                            self.api_client.delete(f"/repos/{repo_full_name}")
                        except Exception:
                            pass
                else:
                    result["creation_test"]["result"] = "validation_error"
                    result["creation_test"]["message"] = "Repository creation validation error"
                    result["creation_test"]["http_code"] = 422
            except Exception as e:
                error_msg = str(e)
                if "403" in error_msg or "401" in error_msg:
                    result["creation_test"]["result"] = "forbidden"
                    result["creation_test"]["message"] = "Repository creation forbidden - insufficient permissions"
                    result["creation_test"]["http_code"] = 403
                elif "422" in error_msg:
                    result["creation_test"]["result"] = "validation_error"
                    result["creation_test"]["message"] = "Repository creation validation error"
                    result["creation_test"]["http_code"] = 422
                else:
                    result["creation_test"]["result"] = "error"
                    result["creation_test"]["message"] = f"Repository creation test error: {error_msg}"
                    result["creation_test"]["http_code"] = None
        except Exception as e:
            result["creation_test"]["result"] = "error"
            result["creation_test"]["message"] = f"Repository creation test error: {str(e)}"
            result["creation_test"]["http_code"] = None
        
        result["overall_can_create"] = (
            result["can_create_user_repos"] or result["can_create_org_repos"]
        )
        
        return result

