"""
PR Reviews Analysis Module

Provides detailed analysis of pull request reviews including:
- Review comments and feedback
- Review approvals and rejections
- Review requests and reviewers
- Review state and conditions
- Review timeline
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class PRReviewsAnalyzer:
    """Analyzes pull request reviews in detail."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_repo_pr_reviews(self, repo_full_name: str, max_prs: int = 20) -> Dict[str, Any]:
        """
        Analyze PR reviews for a repository.
        
        Args:
            repo_full_name: Full repository name (owner/repo)
            max_prs: Maximum number of PRs to analyze
            
        Returns:
            Dictionary with PR reviews analysis
        """
        reviews_data = {
            "repository": repo_full_name,
            "pull_requests": [],
            "summary": {
                "total_prs_analyzed": 0,
                "total_reviews": 0,
                "approved": 0,
                "changes_requested": 0,
                "commented": 0,
                "dismissed": 0,
                "reviewers": set(),
                "review_comments": 0
            },
            "errors": []
        }
        
        try:
            # Get pull requests
            prs = self.api_client.get_paginated(
                f"/repos/{repo_full_name}/pulls",
                params={"state": "all", "per_page": 100}
            )
            
            for pr in prs[:max_prs]:
                pr_number = pr.get("number", "")
                pr_info = {
                    "number": pr_number,
                    "title": pr.get("title", ""),
                    "state": pr.get("state", ""),
                    "merged": pr.get("merged", False),
                    "draft": pr.get("draft", False),
                    "author": {
                        "login": pr.get("user", {}).get("login", ""),
                        "id": pr.get("user", {}).get("id", "")
                    } if pr.get("user") else {},
                    "created_at": pr.get("created_at", ""),
                    "updated_at": pr.get("updated_at", ""),
                    "reviews": [],
                    "review_requests": [],
                    "review_comments": []
                }
                
                # Get PR reviews
                try:
                    reviews = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/pulls/{pr_number}/reviews"
                    )
                    for review in reviews:
                        review_info = {
                            "id": review.get("id", ""),
                            "user": {
                                "login": review.get("user", {}).get("login", ""),
                                "id": review.get("user", {}).get("id", "")
                            } if review.get("user") else {},
                            "body": review.get("body", "")[:500] if review.get("body") else "",  # First 500 chars
                            "state": review.get("state", ""),  # APPROVED, CHANGES_REQUESTED, COMMENTED, DISMISSED
                            "submitted_at": review.get("submitted_at", ""),
                            "commit_id": review.get("commit_id", "")
                        }
                        pr_info["reviews"].append(review_info)
                        
                        # Update summary
                        reviews_data["summary"]["total_reviews"] += 1
                        state = review_info["state"]
                        if state == "APPROVED":
                            reviews_data["summary"]["approved"] += 1
                        elif state == "CHANGES_REQUESTED":
                            reviews_data["summary"]["changes_requested"] += 1
                        elif state == "COMMENTED":
                            reviews_data["summary"]["commented"] += 1
                        elif state == "DISMISSED":
                            reviews_data["summary"]["dismissed"] += 1
                        
                        if review_info["user"].get("login"):
                            reviews_data["summary"]["reviewers"].add(review_info["user"]["login"])
                except Exception as e:
                    reviews_data["errors"].append(f"Failed to get reviews for PR #{pr_number}: {str(e)}")
                
                # Get review requests
                try:
                    review_requests = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/pulls/{pr_number}/requested_reviewers"
                    )
                    for req in review_requests:
                        if isinstance(req, dict):
                            pr_info["review_requests"].append({
                                "login": req.get("login", ""),
                                "id": req.get("id", ""),
                                "type": req.get("type", "")
                            })
                except Exception:
                    pass
                
                # Get review comments
                try:
                    review_comments = self.api_client.get_paginated(
                        f"/repos/{repo_full_name}/pulls/{pr_number}/comments"
                    )
                    for comment in review_comments[:50]:  # Limit to 50 comments per PR
                        comment_info = {
                            "id": comment.get("id", ""),
                            "user": {
                                "login": comment.get("user", {}).get("login", ""),
                                "id": comment.get("user", {}).get("id", "")
                            } if comment.get("user") else {},
                            "body": comment.get("body", "")[:300] if comment.get("body") else "",  # First 300 chars
                            "path": comment.get("path", ""),
                            "line": comment.get("line"),
                            "created_at": comment.get("created_at", "")
                        }
                        pr_info["review_comments"].append(comment_info)
                        reviews_data["summary"]["review_comments"] += 1
                except Exception as e:
                    reviews_data["errors"].append(f"Failed to get review comments for PR #{pr_number}: {str(e)}")
                
                reviews_data["pull_requests"].append(pr_info)
                reviews_data["summary"]["total_prs_analyzed"] += 1
        except Exception as e:
            reviews_data["errors"].append(f"Failed to get pull requests: {str(e)}")
        
        # Convert set to list
        reviews_data["summary"]["reviewers"] = list(reviews_data["summary"]["reviewers"])
        
        return reviews_data
    
    def analyze_org_pr_reviews(self, org_name: str, max_repos: int = 10) -> Dict[str, Any]:
        """
        Analyze PR reviews across organization repositories.
        
        Args:
            org_name: Organization name
            max_repos: Maximum number of repositories to analyze
            
        Returns:
            Dictionary with organization-wide PR reviews analysis
        """
        org_reviews = {
            "organization": org_name,
            "repositories": {},
            "summary": {
                "total_repos_analyzed": 0,
                "total_prs": 0,
                "total_reviews": 0,
                "approved": 0,
                "changes_requested": 0,
                "unique_reviewers": set()
            },
            "errors": []
        }
        
        try:
            repos = self.api_client.get_paginated(f"/orgs/{org_name}/repos")
            for repo in repos[:max_repos]:
                repo_full_name = repo.get("full_name", "")
                if repo_full_name:
                    try:
                        repo_reviews = self.analyze_repo_pr_reviews(repo_full_name, max_prs=10)
                        org_reviews["repositories"][repo_full_name] = repo_reviews
                        
                        # Update summary
                        org_reviews["summary"]["total_repos_analyzed"] += 1
                        org_reviews["summary"]["total_prs"] += repo_reviews["summary"]["total_prs_analyzed"]
                        org_reviews["summary"]["total_reviews"] += repo_reviews["summary"]["total_reviews"]
                        org_reviews["summary"]["approved"] += repo_reviews["summary"]["approved"]
                        org_reviews["summary"]["changes_requested"] += repo_reviews["summary"]["changes_requested"]
                        org_reviews["summary"]["unique_reviewers"].update(repo_reviews["summary"]["reviewers"])
                    except Exception as e:
                        org_reviews["errors"].append(f"Failed to analyze {repo_full_name}: {str(e)}")
        except Exception as e:
            org_reviews["errors"].append(f"Failed to get repositories: {str(e)}")
        
        # Convert set to list
        org_reviews["summary"]["unique_reviewers"] = len(org_reviews["summary"]["unique_reviewers"])
        
        return org_reviews

