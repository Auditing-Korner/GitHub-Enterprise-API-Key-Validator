"""
Environment Secrets & Variables Analysis Module

Analyzes environment-level secrets and variables including:
- Environment secrets
- Environment variables
- Environment protection rules
- Environment deployment branches
- Environment reviewers
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class EnvironmentSecretsAnalyzer:
    """Analyzes environment secrets and variables."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_environments(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze environments for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with environment analysis
        """
        env_data = {
            "repository": repo_full_name,
            "environments": [],
            "summary": {
                "total_environments": 0,
                "environments_with_secrets": 0,
                "environments_with_variables": 0,
                "environments_with_protection": 0,
                "total_secrets": 0,
                "total_variables": 0
            },
            "errors": []
        }
        
        try:
            # Get environments
            environments = self.api_client.get_paginated(f"/repos/{repo_full_name}/environments")
            
            for env in environments:
                env_name = env.get("name", "")
                env_info = {
                    "name": env_name,
                    "protection_rules": env.get("protection_rules", []),
                    "secrets": [],
                    "variables": [],
                    "deployment_branch_policy": env.get("deployment_branch_policy", {}),
                    "reviewers": []
                }
                
                # Get environment secrets
                try:
                    secrets = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/environments/{env_name}/secrets"
                    )
                    for secret in secrets:
                        secret_info = {
                            "name": secret.get("name", ""),
                            "created_at": secret.get("created_at", ""),
                            "updated_at": secret.get("updated_at", "")
                        }
                        env_info["secrets"].append(secret_info)
                        env_data["summary"]["total_secrets"] += 1
                    
                    if env_info["secrets"]:
                        env_data["summary"]["environments_with_secrets"] += 1
                except Exception as e:
                    env_data["errors"].append(f"Failed to get secrets for {env_name}: {str(e)}")
                
                # Get environment variables
                try:
                    variables = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/environments/{env_name}/variables"
                    )
                    for variable in variables:
                        variable_info = {
                            "name": variable.get("name", ""),
                            "created_at": variable.get("created_at", ""),
                            "updated_at": variable.get("updated_at", "")
                        }
                        env_info["variables"].append(variable_info)
                        env_data["summary"]["total_variables"] += 1
                    
                    if env_info["variables"]:
                        env_data["summary"]["environments_with_variables"] += 1
                except Exception as e:
                    env_data["errors"].append(f"Failed to get variables for {env_name}: {str(e)}")
                
                # Check protection rules
                if env_info["protection_rules"]:
                    env_data["summary"]["environments_with_protection"] += 1
                    # Extract reviewers from protection rules
                    for rule in env_info["protection_rules"]:
                        if rule.get("type") == "required_reviewers":
                            reviewers = rule.get("reviewers", [])
                            for reviewer in reviewers:
                                env_info["reviewers"].append({
                                    "type": reviewer.get("type", ""),
                                    "id": reviewer.get("id", "")
                                })
                
                env_data["environments"].append(env_info)
                env_data["summary"]["total_environments"] += 1
        except Exception as e:
            env_data["errors"].append(f"Failed to get environments: {str(e)}")
        
        return env_data
    
    def analyze_org_environments(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze environments across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide environment analysis
        """
        org_envs = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_environments": 0,
                "total_secrets": 0,
                "total_variables": 0,
                "repos_with_environments": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_envs = self.analyze_repo_environments(repo_full_name)
                        org_envs["repositories"][repo_full_name] = repo_envs
                        
                        # Update summary
                        org_envs["summary"]["total_repos_analyzed"] += 1
                        org_envs["summary"]["total_environments"] += repo_envs["summary"]["total_environments"]
                        org_envs["summary"]["total_secrets"] += repo_envs["summary"]["total_secrets"]
                        org_envs["summary"]["total_variables"] += repo_envs["summary"]["total_variables"]
                        
                        if repo_envs["summary"]["total_environments"] > 0:
                            org_envs["summary"]["repos_with_environments"] += 1
                    except Exception as e:
                        org_envs["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_envs["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_envs

