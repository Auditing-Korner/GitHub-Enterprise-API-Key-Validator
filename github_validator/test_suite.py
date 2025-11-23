"""
Test Suite Module

Runs comprehensive tests of all features.
"""

from typing import Dict, Any, Optional
from datetime import datetime
from .api_client import GitHubAPIClient
from .runner_operations import RunnerOperations
from .resources import ResourceLister
from .runners import EnterpriseRunnerInspector


class TestSuite:
    """Comprehensive test suite for all features."""
    
    def __init__(self, api_client: GitHubAPIClient, enterprise_slug: Optional[str] = None):
        self.api_client = api_client
        self.enterprise_slug = enterprise_slug
        self.runner_ops = RunnerOperations(api_client)
        self.resources = ResourceLister(api_client)
        self.runner_inspector = None
        if enterprise_slug:
            self.runner_inspector = EnterpriseRunnerInspector(api_client, enterprise_slug)
    
    def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all feature tests.
        
        Returns:
            Dictionary with test results for all features
        """
        results = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tests": {}
        }
        
        # Test 1: Runners
        results["tests"]["runners"] = self._test_runners()
        
        # Test 2: SSH Keys
        results["tests"]["ssh_keys"] = self._test_ssh_keys()
        
        # Test 3: Projects
        results["tests"]["projects"] = self._test_projects()
        
        # Test 4: Repositories
        results["tests"]["repositories"] = self._test_repositories()
        
        # Test 5: Repository Creation Validation
        results["tests"]["repo_creation"] = self._test_repo_creation()
        
        # Test 6: Webhooks
        results["tests"]["webhooks"] = self._test_webhooks()
        
        # Test 7: Organization Access
        results["tests"]["organization_access"] = self._test_org_access()
        
        # Calculate summary
        total_tests = len(results["tests"])
        passed = sum(1 for test in results["tests"].values() if test.get("success", False))
        failed = total_tests - passed
        
        results["summary"] = {
            "total_tests": total_tests,
            "passed": passed,
            "failed": failed,
            "success_rate": (passed / total_tests * 100) if total_tests > 0 else 0
        }
        
        return results
    
    def _test_runners(self) -> Dict[str, Any]:
        """Test runner fetching."""
        try:
            if not self.runner_inspector:
                return {
                    "success": False,
                    "error": "Enterprise slug not provided",
                    "message": "Cannot test runners without enterprise_slug"
                }
            
            runner_data = self.runner_inspector.fetch_runners()
            return {
                "success": True,
                "message": f"Successfully fetched {runner_data.get('total_runners', 0)} runner(s)",
                "data": {
                    "total_runners": runner_data.get("total_runners", 0),
                    "online_runners": runner_data.get("online_runners", 0),
                    "offline_runners": runner_data.get("offline_runners", 0)
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to fetch runners"
            }
    
    def _test_ssh_keys(self) -> Dict[str, Any]:
        """Test SSH keys listing."""
        try:
            ssh_keys = self.runner_ops.list_ssh_keys()
            return {
                "success": True,
                "message": f"Successfully listed {len(ssh_keys)} SSH key(s)",
                "data": {"count": len(ssh_keys)}
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to list SSH keys",
                "warning": True
            }
    
    def _test_projects(self) -> Dict[str, Any]:
        """Test projects listing."""
        try:
            projects = self.resources.list_projects()
            return {
                "success": True,
                "message": f"Successfully listed {projects.get('total', 0)} project(s)",
                "data": {
                    "total": projects.get("total", 0),
                    "user_projects": len(projects.get("user_projects", [])),
                    "org_projects": len(projects.get("org_projects", [])),
                    "repo_projects": len(projects.get("repo_projects", []))
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to list projects",
                "warning": True
            }
    
    def _test_repositories(self) -> Dict[str, Any]:
        """Test repositories listing."""
        try:
            repos = self.resources.list_repositories()
            return {
                "success": True,
                "message": f"Successfully listed {repos.get('total', 0)} repository/repositories",
                "data": {
                    "total": repos.get("total", 0),
                    "user_repos": len(repos.get("user_repos", [])),
                    "org_repos": len(repos.get("org_repos", [])),
                    "starred_repos": len(repos.get("starred_repos", []))
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to list repositories",
                "warning": True
            }
    
    def _test_repo_creation(self) -> Dict[str, Any]:
        """Test repository creation validation."""
        try:
            validation = self.resources.validate_repo_creation()
            return {
                "success": True,
                "message": "Successfully validated repository creation permissions",
                "data": validation
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to validate repository creation",
                "warning": True
            }
    
    def _test_webhooks(self) -> Dict[str, Any]:
        """Test webhooks listing."""
        try:
            webhooks = self.resources.list_webhooks()
            return {
                "success": True,
                "message": f"Successfully listed {webhooks.get('total', 0)} webhook(s)",
                "data": {
                    "total": webhooks.get("total", 0),
                    "user_repo_webhooks": len(webhooks.get("user_repo_webhooks", [])),
                    "org_webhooks": len(webhooks.get("org_webhooks", [])),
                    "org_repo_webhooks": len(webhooks.get("org_repo_webhooks", []))
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to list webhooks",
                "warning": True
            }
    
    def _test_org_access(self) -> Dict[str, Any]:
        """Test organization access."""
        try:
            user_info = self.api_client.get("/user")
            orgs = self.api_client.get_paginated("/user/orgs")
            
            return {
                "success": True,
                "message": f"Successfully accessed {len(orgs)} organization(s)",
                "data": {
                    "authenticated_user": user_info.get("login", "unknown"),
                    "organization_count": len(orgs),
                    "organizations": [org.get("login") for org in orgs]
                }
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "Failed to test organization access",
                "warning": True
            }

