"""
Repository Languages Breakdown Analysis Module

Analyzes repository languages including:
- Detailed language statistics
- Language distribution
- Language percentages
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class RepositoryLanguagesAnalyzer:
    """Analyzes repository languages in detail."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_languages(self, repo_full_name: str) -> Dict[str, Any]:
        """
        Analyze languages for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            
        Returns:
            Dictionary with languages analysis
        """
        languages_data = {
            "repository": repo_full_name,
            "languages": {},
            "summary": {
                "total_bytes": 0,
                "total_languages": 0,
                "top_languages": []
            },
            "errors": []
        }
        
        try:
            # Get repository languages
            languages = self.api_client.get(f"/repos/{repo_full_name}/languages")
            if languages:
                languages_data["languages"] = languages
                languages_data["summary"]["total_bytes"] = sum(languages.values())
                languages_data["summary"]["total_languages"] = len(languages)
                
                # Calculate percentages and sort
                for lang, bytes_count in languages.items():
                    percentage = (bytes_count / languages_data["summary"]["total_bytes"] * 100) if languages_data["summary"]["total_bytes"] > 0 else 0
                    languages_data["summary"]["top_languages"].append({
                        "language": lang,
                        "bytes": bytes_count,
                        "percentage": round(percentage, 2)
                    })
                
                # Sort by bytes
                languages_data["summary"]["top_languages"].sort(key=lambda x: x["bytes"], reverse=True)
        except Exception as e:
            languages_data["errors"].append(f"Failed to get repository languages: {str(e)}")
        
        return languages_data
    
    def analyze_org_languages(self, org_name: str, max_repos: int = 50) -> Dict[str, Any]:
        """
        Analyze languages across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide languages analysis
        """
        org_languages = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "unique_languages": set(),
                "language_usage": {},
                "total_bytes_by_language": {}
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_languages = self.analyze_repo_languages(repo_full_name)
                        org_languages["repositories"][repo_full_name] = repo_languages
                        
                        # Update summary
                        org_languages["summary"]["total_repos_analyzed"] += 1
                        languages = repo_languages.get("languages", {})
                        
                        for lang, bytes_count in languages.items():
                            org_languages["summary"]["unique_languages"].add(lang)
                            org_languages["summary"]["language_usage"][lang] = org_languages["summary"]["language_usage"].get(lang, 0) + 1
                            org_languages["summary"]["total_bytes_by_language"][lang] = org_languages["summary"]["total_bytes_by_language"].get(lang, 0) + bytes_count
                    except Exception as e:
                        org_languages["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_languages["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert set to list
        org_languages["summary"]["unique_languages"] = list(org_languages["summary"]["unique_languages"])
        
        return org_languages

