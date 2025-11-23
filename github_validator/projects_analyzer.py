"""
GitHub Projects Analysis Module

Analyzes GitHub Projects including:
- Organization projects
- Repository projects
- Project columns and cards
- Project permissions
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class ProjectsAnalyzer:
    """Analyzes GitHub Projects."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_org_projects(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze organization projects.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with organization projects analysis
        """
        projects_data = {
            "organization": org_name,
            "projects": [],
            "summary": {
                "total_projects": 0,
                "open_projects": 0,
                "closed_projects": 0,
                "projects_with_cards": 0
            },
            "errors": []
        }
        
        try:
            # Get organization projects
            projects = self.api_client.get_paginated(f"/orgs/{org_name}/projects", params={"state": "all"})
            
            for project in projects:
                project_id = project.get("id", "")
                project_info = {
                    "id": project_id,
                    "name": project.get("name", ""),
                    "body": project.get("body", "")[:500] if project.get("body") else "",
                    "state": project.get("state", ""),
                    "created_at": project.get("created_at", ""),
                    "updated_at": project.get("updated_at", ""),
                    "columns": [],
                    "total_cards": 0
                }
                
                # Get project columns
                try:
                    columns = self.api_client.get_paginated(f"/projects/{project_id}/columns")
                    for column in columns:
                        column_id = column.get("id", "")
                        column_info = {
                            "id": column_id,
                            "name": column.get("name", ""),
                            "cards_count": 0
                        }
                        
                        # Get column cards
                        try:
                            cards = self.api_client.get_paginated(f"/projects/columns/{column_id}/cards")
                            column_info["cards_count"] = len(cards)
                            project_info["total_cards"] += len(cards)
                        except Exception:
                            pass
                        
                        project_info["columns"].append(column_info)
                    
                    if project_info["total_cards"] > 0:
                        projects_data["summary"]["projects_with_cards"] += 1
                except Exception as e:
                    projects_data["errors"].append(f"Failed to get columns for project {project_id}: {str(e)}")
                
                projects_data["projects"].append(project_info)
                projects_data["summary"]["total_projects"] += 1
                
                if project_info["state"] == "open":
                    projects_data["summary"]["open_projects"] += 1
                else:
                    projects_data["summary"]["closed_projects"] += 1
        except Exception as e:
            projects_data["errors"].append(f"Failed to get organization projects: {str(e)}")
        
        return projects_data
    
    def analyze_repo_projects(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze repository projects.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with repository projects analysis
        """
        projects_data = {
            "repository": repo_full_name,
            "projects": [],
            "summary": {
                "total_projects": 0,
                "open_projects": 0,
                "closed_projects": 0
            },
            "errors": []
        }
        
        try:
            # Get repository projects
            projects = self.api_client.get_paginated(f"/repos/{repo_full_name}/projects", params={"state": "all"})
            
            for project in projects:
                project_info = {
                    "id": project.get("id", ""),
                    "name": project.get("name", ""),
                    "body": project.get("body", "")[:500] if project.get("body") else "",
                    "state": project.get("state", ""),
                    "created_at": project.get("created_at", "")
                }
                
                projects_data["projects"].append(project_info)
                projects_data["summary"]["total_projects"] += 1
                
                if project_info["state"] == "open":
                    projects_data["summary"]["open_projects"] += 1
                else:
                    projects_data["summary"]["closed_projects"] += 1
        except Exception as e:
            projects_data["errors"].append(f"Failed to get repository projects: {str(e)}")
        
        return projects_data
    
    def analyze_org_repo_projects(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze projects across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide projects analysis
        """
        org_projects = {
            "organization": org_name,
            "organization_projects": {},
            "repository_projects": {},
            "summary": {
                "org_projects": 0,
                "repo_projects": 0,
                "repos_with_projects": 0
            },
            "errors": []
        }
        
        # Get organization projects
        try:
            org_projects["organization_projects"] = self.analyze_org_projects(org_name)
            org_projects["summary"]["org_projects"] = org_projects["organization_projects"]["summary"]["total_projects"]
        except Exception as e:
            org_projects["errors"].append(f"Failed to get org projects: {str(e)}")
        
        # Get repository projects
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_projects = self.analyze_repo_projects(repo_full_name)
                        org_projects["repository_projects"][repo_full_name] = repo_projects
                        
                        org_projects["summary"]["repo_projects"] += repo_projects["summary"]["total_projects"]
                        if repo_projects["summary"]["total_projects"] > 0:
                            org_projects["summary"]["repos_with_projects"] += 1
                    except Exception as e:
                        org_projects["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_projects["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_projects

