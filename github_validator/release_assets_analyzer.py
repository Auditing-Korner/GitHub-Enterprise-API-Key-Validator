"""
Release Assets Analysis Module

Analyzes release assets including:
- Release asset details
- Asset download statistics
- Asset permissions
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class ReleaseAssetsAnalyzer:
    """Analyzes release assets."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_release_assets(self, repo_full_name: str, max_releases: int = 30) -> Dict[str, Any]:
        """
        Analyze release assets for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_releases: Maximum number of releases to analyze
            
        Returns:
            Dictionary with release assets analysis
        """
        assets_data = {
            "repository": repo_full_name,
            "releases": [],
            "summary": {
                "total_releases": 0,
                "releases_with_assets": 0,
                "total_assets": 0,
                "total_asset_size": 0,
                "asset_types": {}
            },
            "errors": []
        }
        
        try:
            # Get releases
            releases = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/releases",
                params={"per_page": 100}
            )
            
            for release in releases[:max_releases]:
                release_id = release.get("id", "")
                release_info = {
                    "id": release_id,
                    "tag_name": release.get("tag_name", ""),
                    "name": release.get("name", ""),
                    "draft": release.get("draft", False),
                    "prerelease": release.get("prerelease", False),
                    "created_at": release.get("created_at", ""),
                    "published_at": release.get("published_at", ""),
                    "assets": [],
                    "total_assets": 0,
                    "total_size": 0
                }
                
                # Get release assets
                assets = release.get("assets", [])
                for asset in assets:
                    asset_info = {
                        "id": asset.get("id", ""),
                        "name": asset.get("name", ""),
                        "label": asset.get("label", ""),
                        "content_type": asset.get("content_type", ""),
                        "size": asset.get("size", 0),
                        "download_count": asset.get("download_count", 0),
                        "created_at": asset.get("created_at", ""),
                        "updated_at": asset.get("updated_at", ""),
                        "browser_download_url": asset.get("browser_download_url", "")
                    }
                    
                    release_info["assets"].append(asset_info)
                    release_info["total_assets"] += 1
                    release_info["total_size"] += asset_info["size"]
                    
                    # Track asset types
                    content_type = asset_info["content_type"] or "unknown"
                    assets_data["summary"]["asset_types"][content_type] = assets_data["summary"]["asset_types"].get(content_type, 0) + 1
                
                if release_info["total_assets"] > 0:
                    assets_data["summary"]["releases_with_assets"] += 1
                
                assets_data["releases"].append(release_info)
                assets_data["summary"]["total_releases"] += 1
                assets_data["summary"]["total_assets"] += release_info["total_assets"]
                assets_data["summary"]["total_asset_size"] += release_info["total_size"]
        except Exception as e:
            assets_data["errors"].append(f"Failed to get releases: {str(e)}")
        
        return assets_data
    
    def analyze_org_release_assets(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze release assets across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide release assets analysis
        """
        org_assets = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_releases": 0,
                "total_assets": 0,
                "total_asset_size": 0,
                "repos_with_assets": 0
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_assets = self.analyze_repo_release_assets(repo_full_name, max_releases=20)
                        org_assets["repositories"][repo_full_name] = repo_assets
                        
                        # Update summary
                        org_assets["summary"]["total_repos_analyzed"] += 1
                        org_assets["summary"]["total_releases"] += repo_assets["summary"]["total_releases"]
                        org_assets["summary"]["total_assets"] += repo_assets["summary"]["total_assets"]
                        org_assets["summary"]["total_asset_size"] += repo_assets["summary"]["total_asset_size"]
                        
                        if repo_assets["summary"]["total_assets"] > 0:
                            org_assets["summary"]["repos_with_assets"] += 1
                    except Exception as e:
                        org_assets["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_assets["errors"].append(f"Failed to get repositories: {str(e)}")
        
        return org_assets

