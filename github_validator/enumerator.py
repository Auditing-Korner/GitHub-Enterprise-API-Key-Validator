"""
Company Enumeration Module

Enumerates all accessible company/organization information based on API key permissions.
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class CompanyEnumerator:
    """Enumerates all accessible company information."""
    
    def __init__(self, api_client: GitHubAPIClient):
        """
        Initialize company enumerator.
        
        Args:
            api_client: GitHubAPIClient instance
        """
        self.api_client = api_client
    
    def enumerate_organization(self, org_name: str) -> Dict[str, Any]:
        """
        Enumerate all information about a specific organization.
        
        Args:
            org_name: Name of the organization/company
        
        Returns:
            Dictionary containing all accessible organization information
        """
        org_data = {
            "organization_name": org_name,
            "organization_info": {},
            "members": [],
            "teams": [],
            "repositories": [],
            "webhooks": [],
            "secrets": [],
            "audit_logs": [],
            "organization_runners": [],
            "actions_overview": {
                "repository_count": 0,
                "workflow_repositories": 0,
                "workflow_total": 0,
                "repository_secrets": 0,
                "repository_runners": 0,
                "org_secrets": 0,
            },
            "errors": []
        }
        
        # Get organization basic info
        try:
            org_info = self.api_client.get(f"/orgs/{org_name}")
            if org_info:
                org_data["organization_info"] = {
                    "login": org_info.get("login", ""),
                    "name": org_info.get("name", ""),
                    "description": org_info.get("description", ""),
                    "email": org_info.get("email", ""),
                    "blog": org_info.get("blog", ""),
                    "location": org_info.get("location", ""),
                    "company": org_info.get("company", ""),
                    "type": org_info.get("type", ""),
                    "public_repos": org_info.get("public_repos", 0),
                    "public_gists": org_info.get("public_gists", 0),
                    "followers": org_info.get("followers", 0),
                    "following": org_info.get("following", 0),
                    "created_at": org_info.get("created_at", ""),
                    "updated_at": org_info.get("updated_at", ""),
                    "plan": org_info.get("plan", {})
                }
        except Exception as e:
            org_data["errors"].append(f"Failed to get org info: {str(e)}")
        
        # Get organization members
        try:
            members = self.api_client.get_paginated(f"/orgs/{org_name}/members")
            org_data["members"] = [
                {
                    "login": m.get("login", ""),
                    "id": m.get("id", ""),
                    "type": m.get("type", ""),
                    "site_admin": m.get("site_admin", False),
                    "avatar_url": m.get("avatar_url", "")
                }
                for m in members
            ]
        except Exception as e:
            org_data["errors"].append(f"Failed to get members: {str(e)}")
        
        # Get organization teams
        try:
            teams = self.api_client.get_paginated(f"/orgs/{org_name}/teams")
            for team in teams:
                team_data = {
                    "id": team.get("id", ""),
                    "name": team.get("name", ""),
                    "slug": team.get("slug", ""),
                    "description": team.get("description", ""),
                    "privacy": team.get("privacy", ""),
                    "permission": team.get("permission", ""),
                    "members_count": team.get("members_count", 0),
                    "repos_count": team.get("repos_count", 0),
                    "members": [],
                    "repositories": []
                }
                
                # Get team members
                try:
                    team_members = self.api_client.get_paginated(f"/teams/{team['id']}/members")
                    team_data["members"] = [
                        {
                            "login": m.get("login", ""),
                            "id": m.get("id", "")
                        }
                        for m in team_members
                    ]
                except:
                    pass
                
                # Get team repositories
                try:
                    team_repos = self.api_client.get_paginated(f"/teams/{team['id']}/repos")
                    team_data["repositories"] = [
                        {
                            "name": r.get("name", ""),
                            "full_name": r.get("full_name", ""),
                            "permissions": r.get("permissions", {})
                        }
                        for r in team_repos
                    ]
                except:
                    pass
                
                org_data["teams"].append(team_data)
        except Exception as e:
            org_data["errors"].append(f"Failed to get teams: {str(e)}")
        
        # Get organization repositories
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos:
                repo_data = {
                    "id": repo.get("id", ""),
                    "name": repo.get("name", ""),
                    "full_name": repo.get("full_name", ""),
                    "private": repo.get("private", False),
                    "description": repo.get("description", ""),
                    "fork": repo.get("fork", False),
                    "archived": repo.get("archived", False),
                    "disabled": repo.get("disabled", False),
                    "default_branch": repo.get("default_branch", ""),
                    "language": repo.get("language", ""),
                    "stargazers_count": repo.get("stargazers_count", 0),
                    "watchers_count": repo.get("watchers_count", 0),
                    "forks_count": repo.get("forks_count", 0),
                    "open_issues_count": repo.get("open_issues_count", 0),
                    "created_at": repo.get("created_at", ""),
                    "updated_at": repo.get("updated_at", ""),
                    "pushed_at": repo.get("pushed_at", ""),
                    "permissions": repo.get("permissions", {}),
                    "topics": repo.get("topics", []),
                    "runners": [],
                    "webhooks": [],
                    "secrets": [],
                    "workflows": []
                }
                
                org_data["actions_overview"]["repository_count"] += 1

                # Get repository webhooks
                try:
                    webhooks = self.api_client.get_paginated(f"/repos/{repo['full_name']}/hooks")
                    repo_data["webhooks"] = [
                        {
                            "id": w.get("id", ""),
                            "name": w.get("name", ""),
                            "active": w.get("active", False),
                            "events": w.get("events", []),
                            "config": {
                                "url": w.get("config", {}).get("url", ""),
                                "content_type": w.get("config", {}).get("content_type", "")
                            }
                        }
                        for w in webhooks
                    ]
                except:
                    pass
                
                # Get repository secrets (if accessible)
                try:
                    secrets = self.api_client.get_paginated(f"/repos/{repo['full_name']}/actions/secrets")
                    repo_data["secrets"] = [
                        {
                            "name": s.get("name", ""),
                            "created_at": s.get("created_at", ""),
                            "updated_at": s.get("updated_at", "")
                        }
                        for s in secrets
                    ]
                    if secrets:
                        org_data["actions_overview"]["repository_secrets"] += 1
                except:
                    pass
                
                # Get GitHub Actions workflows
                try:
                    workflows = self.api_client.get(f"/repos/{repo['full_name']}/actions/workflows")
                    if workflows and workflows.get("workflows"):
                        repo_data["workflows"] = [
                            {
                                "id": w.get("id", ""),
                                "name": w.get("name", ""),
                                "path": w.get("path", ""),
                                "state": w.get("state", ""),
                                "created_at": w.get("created_at", ""),
                                "updated_at": w.get("updated_at", "")
                            }
                            for w in workflows["workflows"]
                        ]
                        org_data["actions_overview"]["workflow_repositories"] += 1
                        org_data["actions_overview"]["workflow_total"] += len(repo_data["workflows"])
                except:
                    pass

                # Get repository self-hosted runners
                try:
                    runners = self.api_client.get_paginated(f"/repos/{repo['full_name']}/actions/runners")
                    repo_data["runners"] = [
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
                    if repo_data["runners"]:
                        org_data["actions_overview"]["repository_runners"] += 1
                except:
                    pass
                
                org_data["repositories"].append(repo_data)
        except Exception as e:
            org_data["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Get organization webhooks (if accessible)
        try:
            org_webhooks = self.api_client.get_paginated(f"/orgs/{org_name}/hooks")
            org_data["webhooks"] = [
                {
                    "id": w.get("id", ""),
                    "name": w.get("name", ""),
                    "active": w.get("active", False),
                    "events": w.get("events", []),
                    "config": {
                        "url": w.get("config", {}).get("url", ""),
                        "content_type": w.get("config", {}).get("content_type", "")
                    }
                }
                for w in org_webhooks
            ]
        except:
            pass
        
        # Get organization secrets (if accessible)
        try:
            org_secrets = self.api_client.get_paginated(f"/orgs/{org_name}/actions/secrets")
            org_data["secrets"] = [
                {
                    "name": s.get("name", ""),
                    "visibility": s.get("visibility", ""),
                    "selected_repositories_url": s.get("selected_repositories_url", ""),
                    "created_at": s.get("created_at", ""),
                    "updated_at": s.get("updated_at", "")
                }
                for s in org_secrets
            ]
            org_data["actions_overview"]["org_secrets"] = len(org_data["secrets"])
        except:
            pass
        
        # Try to get audit logs (Enterprise only, may not be accessible)
        try:
            # Note: Audit logs endpoint may vary for Enterprise
            audit_logs = self.api_client.get(f"/orgs/{org_name}/audit-log")
            if audit_logs:
                org_data["audit_logs"] = audit_logs
        except:
            pass

        # Get organization-level self-hosted runners
        try:
            org_runners = self.api_client.get_paginated(f"/orgs/{org_name}/actions/runners")
            org_data["organization_runners"] = [
                {
                    "id": r.get("id", ""),
                    "name": r.get("name", ""),
                    "os": r.get("os", ""),
                    "status": r.get("status", ""),
                    "busy": r.get("busy", False),
                    "labels": [label.get("name", "") for label in r.get("labels", [])]
                }
                for r in org_runners
            ]
        except Exception as e:
            org_data["errors"].append(f"Failed to get organization runners: {str(e)}")
        
        return org_data
    
    def enumerate_all_accessible_orgs(self) -> Dict[str, Any]:
        """
        Enumerate all organizations accessible by the API key with comprehensive details.
        
        Returns:
            Dictionary containing all accessible organizations and their data
        """
        all_orgs_data = {
            "organizations": [],
            "total_count": 0,
            "summary": {
                "total_orgs": 0,
                "total_members": 0,
                "total_repos": 0,
                "total_teams": 0,
                "total_secrets": 0,
                "total_runners": 0
            },
            "errors": []
        }
        
        try:
            # Get all organizations the user has access to
            orgs = self.api_client.get_paginated("/user/orgs")
            
            for org in orgs:
                org_name = org.get("login", "")
                if org_name:
                    try:
                        org_data = self.enumerate_organization(org_name)
                        
                        # Add enhanced organization information
                        org_data["enhanced_info"] = self._get_enhanced_org_info(org_name)
                        
                        all_orgs_data["organizations"].append(org_data)
                        
                        # Update summary
                        all_orgs_data["summary"]["total_members"] += len(org_data.get("members", []))
                        all_orgs_data["summary"]["total_repos"] += len(org_data.get("repositories", []))
                        all_orgs_data["summary"]["total_teams"] += len(org_data.get("teams", []))
                        all_orgs_data["summary"]["total_secrets"] += len(org_data.get("secrets", []))
                        all_orgs_data["summary"]["total_runners"] += len(org_data.get("organization_runners", []))
                    except Exception as e:
                        all_orgs_data["errors"].append(f"Failed to enumerate {org_name}: {str(e)}")
            
            all_orgs_data["total_count"] = len(all_orgs_data["organizations"])
            all_orgs_data["summary"]["total_orgs"] = all_orgs_data["total_count"]
            
        except Exception as e:
            all_orgs_data["errors"].append(f"Failed to get organizations: {str(e)}")
        
        return all_orgs_data
    
    def _get_enhanced_org_info(self, org_name: str) -> Dict[str, Any]:
        """
        Get enhanced organization information.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with enhanced org information
        """
        enhanced = {
            "packages": [],
            "installations": [],
            "projects": [],
            "settings": {},
            "billing": {},
            "errors": []
        }
        
        # Get organization packages
        try:
            packages = self.api_client.get_paginated(f"/orgs/{org_name}/packages")
            enhanced["packages"] = [
                {
                    "id": p.get("id", ""),
                    "name": p.get("name", ""),
                    "package_type": p.get("package_type", ""),
                    "owner": p.get("owner", {}).get("login", ""),
                    "version_count": p.get("version_count", 0),
                    "visibility": p.get("visibility", "")
                }
                for p in packages[:50]  # Limit for performance
            ]
        except Exception:
            pass
        
        # Get organization installations (GitHub Apps)
        try:
            installations = self.api_client.get_paginated(f"/orgs/{org_name}/installations")
            enhanced["installations"] = [
                {
                    "id": i.get("id", ""),
                    "app_id": i.get("app_id", ""),
                    "app_slug": i.get("app_slug", ""),
                    "target_type": i.get("target_type", ""),
                    "account": {
                        "login": i.get("account", {}).get("login", ""),
                        "type": i.get("account", {}).get("type", "")
                    } if i.get("account") else {},
                    "permissions": i.get("permissions", {}),
                    "created_at": i.get("created_at", "")
                }
                for i in installations
            ]
        except Exception:
            pass
        
        # Get organization projects
        try:
            projects = self.api_client.get_paginated(f"/orgs/{org_name}/projects")
            enhanced["projects"] = [
                {
                    "id": p.get("id", ""),
                    "name": p.get("name", ""),
                    "body": p.get("body", ""),
                    "number": p.get("number", 0),
                    "state": p.get("state", ""),
                    "created_at": p.get("created_at", ""),
                    "updated_at": p.get("updated_at", "")
                }
                for p in projects[:50]  # Limit for performance
            ]
        except Exception:
            pass
        
        # Get organization settings (if accessible)
        try:
            # Note: Some settings may require admin access
            settings = self.api_client.get(f"/orgs/{org_name}")
            if settings:
                enhanced["settings"] = {
                    "has_organization_projects": settings.get("has_organization_projects", False),
                    "has_repository_projects": settings.get("has_repository_projects", False),
                    "default_repository_permission": settings.get("default_repository_permission", ""),
                    "members_can_create_repositories": settings.get("members_can_create_repositories", False),
                    "two_factor_requirement_enabled": settings.get("two_factor_requirement_enabled", False),
                    "members_allowed_repository_creation_type": settings.get("members_allowed_repository_creation_type", ""),
                    "members_can_create_private_repositories": settings.get("members_can_create_private_repositories", False),
                    "members_can_create_public_repositories": settings.get("members_can_create_public_repositories", False),
                    "members_can_create_internal_repositories": settings.get("members_can_create_internal_repositories", False)
                }
        except Exception:
            pass
        
        # Try to get billing information (may not be accessible)
        try:
            billing = self.api_client.get(f"/orgs/{org_name}/settings/billing")
            if billing:
                enhanced["billing"] = {
                    "plan": billing.get("plan", {}).get("name", ""),
                    "seats": billing.get("seats", {}),
                    "storage": billing.get("storage", {}),
                    "actions": billing.get("actions", {})
                }
        except Exception:
            pass
        
        return enhanced

