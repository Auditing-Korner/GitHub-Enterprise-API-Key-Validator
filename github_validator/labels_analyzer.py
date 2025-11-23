"""
Labels Analysis Module

Analyzes repository and organization labels including:
- Label details and colors
- Label usage statistics
- Label distribution across repositories
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class LabelsAnalyzer:
    """Analyzes repository and organization labels."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_labels(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze labels for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with labels analysis
        """
        labels_data = {
            "repository": repo_full_name,
            "labels": [],
            "summary": {
                "total_labels": 0,
                "label_colors": {},
                "label_names": []
            },
            "errors": []
        }
        
        try:
            # Get repository labels
            labels = self.api_client.get_paginated(f"/repos/{repo_full_name}/labels")
            
            for label in labels:
                label_info = {
                    "id": label.get("id", ""),
                    "name": label.get("name", ""),
                    "color": label.get("color", ""),
                    "default": label.get("default", False),
                    "description": label.get("description", "")[:200] if label.get("description") else ""
                }
                
                labels_data["labels"].append(label_info)
                labels_data["summary"]["total_labels"] += 1
                labels_data["summary"]["label_names"].append(label_info["name"])
                
                # Track color distribution
                color = label_info["color"]
                labels_data["summary"]["label_colors"][color] = labels_data["summary"]["label_colors"].get(color, 0) + 1
        except Exception as e:
            labels_data["errors"].append(f"Failed to get labels: {str(e)}")
        
        return labels_data
    
    def analyze_org_labels(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze organization labels.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with organization labels analysis
        """
        org_labels_data = {
            "organization": org_name,
            "labels": [],
            "summary": {
                "total_labels": 0,
                "label_colors": {},
                "label_names": []
            },
            "errors": []
        }
        
        try:
            # Get organization labels
            labels = self.api_client.get_paginated(f"/orgs/{org_name}/labels")
            
            for label in labels:
                label_info = {
                    "id": label.get("id", ""),
                    "name": label.get("name", ""),
                    "color": label.get("color", ""),
                    "default": label.get("default", False),
                    "description": label.get("description", "")[:200] if label.get("description") else ""
                }
                
                org_labels_data["labels"].append(label_info)
                org_labels_data["summary"]["total_labels"] += 1
                org_labels_data["summary"]["label_names"].append(label_info["name"])
                
                # Track color distribution
                color = label_info["color"]
                org_labels_data["summary"]["label_colors"][color] = org_labels_data["summary"]["label_colors"].get(color, 0) + 1
        except Exception as e:
            org_labels_data["errors"].append(f"Failed to get organization labels: {str(e)}")
        
        return org_labels_data
    
    def analyze_org_repo_labels(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze labels across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide labels analysis
        """
        org_labels = {
            "organization": org_name,
            "repositories": {},
            "organization_labels": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_labels": 0,
                "unique_labels": set(),
                "repos_with_labels": 0
            },
            "errors": []
        }
        
        # Get organization labels
        try:
            org_labels["organization_labels"] = self.analyze_org_labels(org_name)
        except Exception as e:
            org_labels["errors"].append(f"Failed to get org labels: {str(e)}")
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_labels = self.analyze_repo_labels(repo_full_name)
                        org_labels["repositories"][repo_full_name] = repo_labels
                        
                        # Update summary
                        org_labels["summary"]["total_repos_analyzed"] += 1
                        org_labels["summary"]["total_labels"] += repo_labels["summary"]["total_labels"]
                        org_labels["summary"]["unique_labels"].update(repo_labels["summary"]["label_names"])
                        
                        if repo_labels["summary"]["total_labels"] > 0:
                            org_labels["summary"]["repos_with_labels"] += 1
                    except Exception as e:
                        org_labels["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_labels["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert set to list
        org_labels["summary"]["unique_labels"] = list(org_labels["summary"]["unique_labels"])
        
        return org_labels

