"""
Repository Content Analysis Module

Analyzes repository content including:
- File contents and directory structure
- README, LICENSE, CODEOWNERS files
- Security policy files
- Repository languages and topics
- Code search capabilities
"""

from typing import Dict, List, Optional, Any
import base64
from .api_client import GitHubAPIClient


class ContentAnalyzer:
    """Analyzes repository content and files."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_content(self, repo_full_name: str, branch: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze repository content.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            branch: Branch name (defaults to default branch)
            
        Returns:
            Dictionary with content analysis
        """
        content_data = {
            "repository": repo_full_name,
            "branch": branch,
            "readme": {},
            "license": {},
            "codeowners": {},
            "security_policy": {},
            "contributing": {},
            "languages": {},
            "topics": [],
            "files": [],
            "structure": {},
            "errors": []
        }
        
        # Get repository info to determine default branch
        try:
            repo_info = self.api_client.get(f"/repos/{repo_full_name}")
            if repo_info:
                default_branch = branch or repo_info.get("default_branch", "main")
                content_data["branch"] = default_branch
                content_data["languages"] = repo_info.get("language", "")
                content_data["topics"] = repo_info.get("topics", [])
        except Exception as e:
            content_data["errors"].append(f"Repository info: {str(e)}")
            default_branch = branch or "main"
            content_data["branch"] = default_branch
        
        # Get README
        try:
            readme = self.api_client.get(f"/repos/{repo_full_name}/readme")
            if readme:
                content_data["readme"] = {
                    "name": readme.get("name", ""),
                    "path": readme.get("path", ""),
                    "sha": readme.get("sha", ""),
                    "size": readme.get("size", 0),
                    "content": self._decode_content(readme.get("content", "")),
                    "encoding": readme.get("encoding", "")
                }
        except Exception:
            pass
        
        # Get LICENSE
        try:
            license_file = self.api_client.get(f"/repos/{repo_full_name}/license")
            if license_file:
                content_data["license"] = {
                    "name": license_file.get("license", {}).get("name", ""),
                    "key": license_file.get("license", {}).get("key", ""),
                    "spdx_id": license_file.get("license", {}).get("spdx_id", ""),
                    "html_url": license_file.get("html_url", ""),
                    "path": license_file.get("path", "")
                }
        except Exception:
            pass
        
        # Get root directory contents
        try:
            contents = self.api_client.get(
                f"/repos/{repo_full_name}/contents",
                params={"ref": content_data["branch"]}
            )
            if contents:
                if isinstance(contents, list):
                    content_data["files"] = [
                        {
                            "name": item.get("name", ""),
                            "path": item.get("path", ""),
                            "type": item.get("type", ""),
                            "size": item.get("size", 0),
                            "sha": item.get("sha", ""),
                            "url": item.get("url", ""),
                            "html_url": item.get("html_url", "")
                        }
                        for item in contents[:100]  # Limit for performance
                    ]
                elif isinstance(contents, dict):
                    content_data["files"] = [contents]
        except Exception as e:
            content_data["errors"].append(f"Root contents: {str(e)}")
        
        # Try to get CODEOWNERS file
        try:
            codeowners = self.api_client.get(
                f"/repos/{repo_full_name}/contents/.github/CODEOWNERS",
                params={"ref": content_data["branch"]}
            )
            if codeowners:
                content_data["codeowners"] = {
                    "path": codeowners.get("path", ""),
                    "sha": codeowners.get("sha", ""),
                    "size": codeowners.get("size", 0),
                    "content": self._decode_content(codeowners.get("content", ""))
                }
        except Exception:
            pass
        
        # Try to get SECURITY.md
        try:
            security_policy = self.api_client.get(
                f"/repos/{repo_full_name}/contents/SECURITY.md",
                params={"ref": content_data["branch"]}
            )
            if security_policy:
                content_data["security_policy"] = {
                    "path": security_policy.get("path", ""),
                    "sha": security_policy.get("sha", ""),
                    "size": security_policy.get("size", 0),
                    "content": self._decode_content(security_policy.get("content", ""))
                }
        except Exception:
            pass
        
        # Try to get CONTRIBUTING.md
        try:
            contributing = self.api_client.get(
                f"/repos/{repo_full_name}/contents/CONTRIBUTING.md",
                params={"ref": content_data["branch"]}
            )
            if contributing:
                content_data["contributing"] = {
                    "path": contributing.get("path", ""),
                    "sha": contributing.get("sha", ""),
                    "size": contributing.get("size", 0),
                    "content": self._decode_content(contributing.get("content", ""))
                }
        except Exception:
            pass
        
        # Get repository languages
        try:
            languages = self.api_client.get(f"/repos/{repo_full_name}/languages")
            if languages:
                content_data["languages"] = languages
        except Exception:
            pass
        
        return content_data
    
    def search_repo_content(self, repo_full_name: str, query: str) -> Dict[str, Any]:
        """
        Search repository content (code search).
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            query: Search query
            
        Returns:
            Dictionary with search results
        """
        search_results = {
            "repository": repo_full_name,
            "query": query,
            "results": [],
            "total_count": 0,
            "errors": []
        }
        
        try:
            # Use code search API
            search_query = f"{query} repo:{repo_full_name}"
            results = self.api_client.get(
                "/search/code",
                params={"q": search_query, "per_page": 100}
            )
            if results:
                search_results["total_count"] = results.get("total_count", 0)
                search_results["results"] = [
                    {
                        "name": item.get("name", ""),
                        "path": item.get("path", ""),
                        "sha": item.get("sha", ""),
                        "url": item.get("url", ""),
                        "html_url": item.get("html_url", ""),
                        "repository": {
                            "full_name": item.get("repository", {}).get("full_name", "")
                        } if item.get("repository") else {}
                    }
                    for item in results.get("items", [])[:50]  # Limit for performance
                ]
        except Exception as e:
            search_results["errors"].append(f"Search failed: {str(e)}")
        
        return search_results
    
    def analyze_org_content(self, org_name: str, max_repos: int = 20) -> Dict[str, Any]:
        """
        Analyze content across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization content analysis
        """
        org_content = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "repos_with_readme": 0,
                "repos_with_license": 0,
                "repos_with_codeowners": 0,
                "repos_with_security_policy": 0,
                "total_languages": set(),
                "total_topics": set()
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_content = self.analyze_repo_content(repo_full_name)
                        org_content["repositories"][repo_full_name] = repo_content
                        
                        # Update summary
                        org_content["summary"]["total_repos_analyzed"] += 1
                        if repo_content.get("readme"):
                            org_content["summary"]["repos_with_readme"] += 1
                        if repo_content.get("license"):
                            org_content["summary"]["repos_with_license"] += 1
                        if repo_content.get("codeowners"):
                            org_content["summary"]["repos_with_codeowners"] += 1
                        if repo_content.get("security_policy"):
                            org_content["summary"]["repos_with_security_policy"] += 1
                        
                        if isinstance(repo_content.get("languages"), dict):
                            org_content["summary"]["total_languages"].update(repo_content["languages"].keys())
                        if isinstance(repo_content.get("topics"), list):
                            org_content["summary"]["total_topics"].update(repo_content["topics"])
                    except Exception as e:
                        org_content["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_content["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert sets to lists for JSON serialization
        org_content["summary"]["total_languages"] = list(org_content["summary"]["total_languages"])
        org_content["summary"]["total_topics"] = list(org_content["summary"]["total_topics"])
        
        return org_content
    
    def _decode_content(self, encoded_content: str, encoding: str = "base64") -> str:
        """Decode base64 encoded content."""
        if not encoded_content:
            return ""
        try:
            if encoding == "base64":
                decoded = base64.b64decode(encoded_content)
                return decoded.decode('utf-8', errors='ignore')
            return encoded_content
        except Exception:
            return ""

