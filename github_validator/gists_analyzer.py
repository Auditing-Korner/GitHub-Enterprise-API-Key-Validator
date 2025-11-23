"""
Gists Analysis Module

Analyzes GitHub Gists for:
- Public, private, and secret gists
- Gist contents and files
- Gist forks and comments
- Code snippets and potential secrets
"""

from typing import Dict, List, Optional, Any
import base64
from .api_client import GitHubAPIClient


class GistsAnalyzer:
    """Analyzes GitHub Gists."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_user_gists(self, max_gists: int = 100) -> Dict[str, Any]:
        """
        Analyze user gists.
        
        Args:
            max_gists: Maximum number of gists to analyze
            
        Returns:
            Dictionary with gists analysis
        """
        gists_data = {
            "gists": [],
            "summary": {
                "total_gists": 0,
                "public_gists": 0,
                "private_gists": 0,
                "secret_gists": 0,
                "total_files": 0,
                "total_forks": 0,
                "total_comments": 0,
                "languages": {}
            },
            "errors": []
        }
        
        try:
            # Get all gists
            gists = self.api_client.get_paginated("/gists", params={"per_page": 100})
            
            for gist in gists[:max_gists]:
                gist_data = {
                    "id": gist.get("id", ""),
                    "description": gist.get("description", ""),
                    "public": gist.get("public", False),
                    "html_url": gist.get("html_url", ""),
                    "git_pull_url": gist.get("git_pull_url", ""),
                    "git_push_url": gist.get("git_push_url", ""),
                    "created_at": gist.get("created_at", ""),
                    "updated_at": gist.get("updated_at", ""),
                    "comments": gist.get("comments", 0),
                    "forks": [],
                    "files": {},
                    "owner": {
                        "login": gist.get("owner", {}).get("login", ""),
                        "id": gist.get("owner", {}).get("id", "")
                    } if gist.get("owner") else {}
                }
                
                # Get gist files
                files = gist.get("files", {})
                gist_data["files"] = {
                    filename: {
                        "filename": file_data.get("filename", ""),
                        "type": file_data.get("type", ""),
                        "language": file_data.get("language", ""),
                        "size": file_data.get("size", 0),
                        "content": file_data.get("content", "")[:1000]  # First 1000 chars
                    }
                    for filename, file_data in files.items()
                }
                
                # Count languages
                for file_data in files.values():
                    lang = file_data.get("language", "Unknown")
                    if lang:
                        gists_data["summary"]["languages"][lang] = gists_data["summary"]["languages"].get(lang, 0) + 1
                
                # Get forks (limited)
                try:
                    forks = self.api_client.get_paginated(f"/gists/{gist.get('id')}/forks")
                    gist_data["forks"] = [
                        {
                            "user": {
                                "login": f.get("user", {}).get("login", ""),
                                "id": f.get("user", {}).get("id", "")
                            } if f.get("user") else {},
                            "created_at": f.get("created_at", "")
                        }
                        for f in forks[:10]  # Limit to 10 forks
                    ]
                except Exception:
                    pass
                
                # Get comments (limited)
                try:
                    comments = self.api_client.get_paginated(f"/gists/{gist.get('id')}/comments")
                    gist_data["comments_list"] = [
                        {
                            "user": {
                                "login": c.get("user", {}).get("login", ""),
                                "id": c.get("user", {}).get("id", "")
                            } if c.get("user") else {},
                            "body": c.get("body", "")[:500],  # First 500 chars
                            "created_at": c.get("created_at", "")
                        }
                        for c in comments[:10]  # Limit to 10 comments
                    ]
                except Exception:
                    pass
                
                gists_data["gists"].append(gist_data)
                
                # Update summary
                gists_data["summary"]["total_gists"] += 1
                if gist.get("public", False):
                    gists_data["summary"]["public_gists"] += 1
                else:
                    gists_data["summary"]["private_gists"] += 1
                
                gists_data["summary"]["total_files"] += len(files)
                gists_data["summary"]["total_forks"] += len(gist_data.get("forks", []))
                gists_data["summary"]["total_comments"] += gist.get("comments", 0)
        except Exception as e:
            gists_data["errors"].append(f"Failed to get gists: {str(e)}")
        
        return gists_data
    
    def analyze_starred_gists(self, max_gists: int = 50) -> Dict[str, Any]:
        """
        Analyze starred gists.
        
        Args:
            max_gists: Maximum number of starred gists to analyze
            
        Returns:
            Dictionary with starred gists analysis
        """
        starred_data = {
            "gists": [],
            "total": 0,
            "errors": []
        }
        
        try:
            starred = self.api_client.get_paginated("/gists/starred", params={"per_page": 100})
            
            for gist in starred[:max_gists]:
                gist_data = {
                    "id": gist.get("id", ""),
                    "description": gist.get("description", ""),
                    "public": gist.get("public", False),
                    "html_url": gist.get("html_url", ""),
                    "owner": {
                        "login": gist.get("owner", {}).get("login", ""),
                        "id": gist.get("owner", {}).get("id", "")
                    } if gist.get("owner") else {},
                    "created_at": gist.get("created_at", ""),
                    "updated_at": gist.get("updated_at", "")
                }
                starred_data["gists"].append(gist_data)
                starred_data["total"] += 1
        except Exception as e:
            starred_data["errors"].append(f"Failed to get starred gists: {str(e)}")
        
        return starred_data

