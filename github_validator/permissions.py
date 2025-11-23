"""
Permission Validation Module

Validates all available scopes and critical permissions for a GitHub API key.
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient
from .runners import EnterpriseRunnerInspector


class PermissionChecker:
    """Validates GitHub API key permissions."""
    
    # Critical permissions that should be highlighted
    CRITICAL_PERMISSIONS = [
        "admin:org",
        "delete_repo",
        "admin:repo_hook",
        "admin:org_hook",
        "write:repo_hook",
        "read:repo_hook",
        "read:org_hook",
        "admin:public_key",
        "write:public_key",
        "admin:gpg_key",
        "write:gpg_key",
        "workflow",
        "write:packages",
        "delete:packages",
        "manage_billing:enterprise",
        "admin:enterprise",
        "enterprise_admin",
        "manage_runners:enterprise",
        "read:runners:enterprise",
        "read:audit_log",
        "write:audit_log"
    ]
    
    # Standard permissions to check
    STANDARD_PERMISSIONS = [
        "repo",
        "read:org",
        "read:user",
        "read:gpg_key",
        "read:public_key",
        "gist",
        "notifications",
        "user:email",
        "user:follow",
        "read:packages",
        "write:discussion",
        "read:discussion",
        "user",
        "codespace",
        "codespaces_metadata",
        "codespaces_user",
        "codespaces_lifecycle_admin",
        "security_events",
        "secret_scanning_alerts"
    ]
    
    def __init__(self, api_client: GitHubAPIClient, enterprise_slug: Optional[str] = None):
        """
        Initialize permission checker.
        
        Args:
            api_client: GitHubAPIClient instance
        """
        self.api_client = api_client
        self.permission_results = {}
        self.enterprise_slug = enterprise_slug
    
    def _test_permission(self, permission_name: str, test_func) -> Dict[str, Any]:
        """
        Test a specific permission.
        
        Args:
            permission_name: Name of the permission
            test_func: Function that tests the permission
        
        Returns:
            Dictionary with permission test results
        """
        try:
            result = test_func()
            return {
                "permission": permission_name,
                "granted": result.get("granted", False),
                "message": result.get("message", ""),
                "details": result.get("details", {})
            }
        except Exception as e:
            return {
                "permission": permission_name,
                "granted": False,
                "message": f"Error testing permission: {str(e)}",
                "details": {}
            }
    
    def _test_repo_access(self) -> Dict[str, Any]:
        """Test repository access permissions."""
        try:
            # Try to list repositories
            repos = self.api_client.get("/user/repos", params={"per_page": 1})
            if repos:
                return {"granted": True, "message": "Can access repositories"}
            
            # Try to get user's repos via paginated endpoint
            try:
                repos_list = self.api_client.get_paginated("/user/repos")
                if repos_list:
                    return {
                        "granted": True,
                        "message": f"Can access {len(repos_list)} repositories",
                        "details": {"repo_count": len(repos_list)}
                    }
            except:
                pass
            
            return {"granted": False, "message": "Cannot access repositories"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Repository access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_repo_write(self) -> Dict[str, Any]:
        """Test repository write permissions."""
        try:
            # Try to get user's repos and check if we can see private repos
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                private_repos = [r for r in repos if r.get("private", False)]
                if private_repos:
                    return {
                        "granted": True,
                        "message": "Can access private repositories (write access likely)",
                        "details": {"private_repo_count": len(private_repos)}
                    }
            
            # Try to check if we can create a test repo (we won't actually create it)
            # Instead, check if we have admin access to any repo
            for repo in repos[:5]:  # Check first 5 repos
                try:
                    repo_info = self.api_client.get(f"/repos/{repo['full_name']}")
                    if repo_info and repo_info.get("permissions", {}).get("admin", False):
                        return {
                            "granted": True,
                            "message": "Has admin access to repositories",
                            "details": {"admin_repos": [repo["full_name"]]}
                        }
                except:
                    continue
            
            return {"granted": False, "message": "No write/admin access detected"}
        except Exception as e:
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_org_read(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test organization read permissions."""
        try:
            if org_name:
                org = self.api_client.get(f"/orgs/{org_name}")
                if org:
                    return {
                        "granted": True,
                        "message": f"Can read organization: {org_name}",
                        "details": {"org": org_name}
                    }
            
            # Try to list user's organizations
            orgs = self.api_client.get_paginated("/user/orgs")
            if orgs:
                return {
                    "granted": True,
                    "message": f"Can read {len(orgs)} organizations",
                    "details": {"org_count": len(orgs), "orgs": [o["login"] for o in orgs]}
                }
            
            return {"granted": False, "message": "Cannot read organizations"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Organization read access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_org_admin(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test organization admin permissions."""
        try:
            if org_name:
                # Try to access org settings (admin only)
                try:
                    org_hooks = self.api_client.get(f"/orgs/{org_name}/hooks")
                    return {
                        "granted": True,
                        "message": f"Has admin access to organization: {org_name}",
                        "details": {"org": org_name}
                    }
                except:
                    # Try to get org members (admin can see all)
                    try:
                        members = self.api_client.get_paginated(f"/orgs/{org_name}/members")
                        return {
                            "granted": True,
                            "message": f"Can access org members (admin access likely)",
                            "details": {"org": org_name, "member_count": len(members)}
                        }
                    except:
                        pass
            
            return {"granted": False, "message": "No organization admin access detected"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Organization admin access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_workflow_access(self) -> Dict[str, Any]:
        """Test GitHub Actions workflow permissions."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            workflow_repos = []
            
            for repo in repos[:10]:  # Check first 10 repos
                try:
                    workflows = self.api_client.get(f"/repos/{repo['full_name']}/actions/workflows")
                    if workflows and workflows.get("workflows"):
                        workflow_repos.append(repo["full_name"])
                except:
                    continue
            
            if workflow_repos:
                return {
                    "granted": True,
                    "message": f"Can access workflows in {len(workflow_repos)} repositories",
                    "details": {"workflow_repos": workflow_repos}
                }
            
            return {"granted": False, "message": "Cannot access workflows"}
        except Exception as e:
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_codespaces_access(self) -> Dict[str, Any]:
        """Test general Codespaces access (codespace scope)."""
        try:
            codespaces = self.api_client.get("/user/codespaces")
            if codespaces is None:
                return {"granted": False, "message": "Codespaces API unavailable"}
            total = len(codespaces.get("codespaces", [])) if isinstance(codespaces, dict) else 0
            return {
                "granted": True,
                "message": f"Can access Codespaces (count: {total})",
                "details": {"codespaces": codespaces}
            }
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Codespaces access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_codespaces_metadata(self) -> Dict[str, Any]:
        """Test Codespaces metadata access (codespaces_metadata scope)."""
        try:
            metadata = self.api_client.get("/user/codespaces?per_page=1")
            if metadata is not None:
                return {
                    "granted": True,
                    "message": "Can read Codespaces metadata",
                    "details": {"metadata": metadata}
                }
            return {"granted": False, "message": "Cannot read Codespaces metadata"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Codespaces metadata access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_codespaces_user(self) -> Dict[str, Any]:
        """Test Codespaces user secrets access (codespaces_user scope)."""
        try:
            secrets = self.api_client.get("/user/codespaces/secrets")
            if secrets is not None:
                return {
                    "granted": True,
                    "message": "Can read Codespaces user secrets",
                    "details": {"secret_names": [s.get("name") for s in secrets.get("secrets", [])] if isinstance(secrets, dict) else []}
                }
            return {"granted": False, "message": "Cannot access Codespaces secrets"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Codespaces user access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_codespaces_lifecycle_admin(self) -> Dict[str, Any]:
        """Test Codespaces lifecycle admin access (codespaces_lifecycle_admin scope)."""
        try:
            codespaces = self.api_client.get("/user/codespaces")
            if codespaces and isinstance(codespaces, dict):
                if codespaces.get("codespaces"):
                    return {
                        "granted": True,
                        "message": "Can administer Codespaces lifecycle",
                        "details": {"codespaces": codespaces.get("codespaces", [])}
                    }
            return {"granted": False, "message": "No Codespaces lifecycle access detected"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Codespaces lifecycle access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_gist_access(self) -> Dict[str, Any]:
        """Test Gist access permissions."""
        try:
            gists = self.api_client.get_paginated("/gists")
            if gists:
                return {
                    "granted": True,
                    "message": f"Can access {len(gists)} gists",
                    "details": {"gist_count": len(gists)}
                }
            return {"granted": False, "message": "Cannot access gists"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Gist access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_packages_access(self) -> Dict[str, Any]:
        """Test packages access permissions."""
        try:
            # Try to list packages for authenticated user
            packages = self.api_client.get_paginated("/user/packages")
            if packages:
                return {
                    "granted": True,
                    "message": f"Can access {len(packages)} packages",
                    "details": {"package_count": len(packages)}
                }
            return {"granted": False, "message": "Cannot access packages"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Package access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_user_info_access(self) -> Dict[str, Any]:
        """Test user information access."""
        try:
            user = self.api_client.get("/user")
            if user:
                return {
                    "granted": True,
                    "message": "Can access user information",
                    "details": {"username": user.get("login", "")}
                }
            return {"granted": False, "message": "Cannot access user information"}
        except Exception as e:
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_user_full_profile(self) -> Dict[str, Any]:
        """Test full user scope access (user scope)."""
        result = self._test_user_info_access()
        if result["granted"]:
            try:
                emails = self.api_client.get_paginated("/user/emails")
                result["details"]["email_count"] = len(emails)
                result["message"] = "Can access full user profile information"
            except Exception:
                pass
        return result
    
    def _test_repo_delete(self) -> Dict[str, Any]:
        """Test repository delete permissions."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                # Check if we have admin permissions (required for delete)
                for repo in repos[:5]:
                    try:
                        repo_info = self.api_client.get(f"/repos/{repo['full_name']}")
                        if repo_info and repo_info.get("permissions", {}).get("admin", False):
                            return {
                                "granted": True,
                                "message": "Has admin access (can delete repositories)",
                                "details": {"admin_repos": [repo["full_name"]]}
                            }
                    except:
                        continue
            return {"granted": False, "message": "No delete repository access detected"}
        except Exception as e:
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_repo_hooks_admin(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test repository webhook admin permissions."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        hooks = self.api_client.get_paginated(f"/repos/{repo['full_name']}/hooks")
                        if hooks is not None:
                            return {
                                "granted": True,
                                "message": "Can manage repository webhooks",
                                "details": {"repo": repo["full_name"], "hook_count": len(hooks)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot manage repository webhooks"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Repository webhook access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_repo_hooks_write(self) -> Dict[str, Any]:
        """Test repository webhook write permissions."""
        result = self._test_repo_hooks_admin()
        if result["granted"]:
            result["message"] = "Can manage repository webhooks (write access)"
            return result
        return {"granted": False, "message": "Cannot write repository webhooks", "details": {}}

    def _test_repo_hooks_read(self) -> Dict[str, Any]:
        """Test repository webhook read permissions."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        hooks = self.api_client.get_paginated(f"/repos/{repo['full_name']}/hooks")
                        if hooks is not None:
                            return {
                                "granted": True,
                                "message": "Can read repository webhooks",
                                "details": {"repo": repo["full_name"], "hook_count": len(hooks)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot read repository webhooks"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Repository webhook read access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_org_hooks_admin(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test organization webhook admin permissions."""
        try:
            if org_name:
                hooks = self.api_client.get_paginated(f"/orgs/{org_name}/hooks")
                if hooks is not None:
                    return {
                        "granted": True,
                        "message": f"Can manage organization webhooks: {org_name}",
                        "details": {"org": org_name, "hook_count": len(hooks)}
                    }
            
            # Try to get orgs and test
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:3]:
                try:
                    hooks = self.api_client.get_paginated(f"/orgs/{org['login']}/hooks")
                    if hooks is not None:
                        return {
                            "granted": True,
                            "message": f"Can manage organization webhooks: {org['login']}",
                            "details": {"org": org["login"], "hook_count": len(hooks)}
                        }
                except:
                    continue
            
            return {"granted": False, "message": "Cannot manage organization webhooks"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Organization webhook access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_org_hooks_read(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test organization webhook read permissions."""
        try:
            if org_name:
                hooks = self.api_client.get_paginated(f"/orgs/{org_name}/hooks")
                if hooks is not None:
                    return {
                        "granted": True,
                        "message": f"Can read organization webhooks: {org_name}",
                        "details": {"org": org_name, "hook_count": len(hooks)}
                    }
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:3]:
                try:
                    hooks = self.api_client.get_paginated(f"/orgs/{org['login']}/hooks")
                    if hooks is not None:
                        return {
                            "granted": True,
                            "message": f"Can read organization webhooks: {org['login']}",
                            "details": {"org": org["login"], "hook_count": len(hooks)}
                        }
                except:
                    continue
            return {"granted": False, "message": "Cannot read organization webhooks"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Organization webhook read access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_repo_secrets(self) -> Dict[str, Any]:
        """Test repository secrets access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        secrets = self.api_client.get_paginated(f"/repos/{repo['full_name']}/actions/secrets")
                        if secrets is not None:
                            return {
                                "granted": True,
                                "message": "Can access repository secrets",
                                "details": {"repo": repo["full_name"], "secret_count": len(secrets)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access repository secrets"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Repository secrets access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_org_secrets(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test organization secrets access."""
        try:
            if org_name:
                secrets = self.api_client.get_paginated(f"/orgs/{org_name}/actions/secrets")
                if secrets is not None:
                    return {
                        "granted": True,
                        "message": f"Can access organization secrets: {org_name}",
                        "details": {"org": org_name, "secret_count": len(secrets)}
                    }
            
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:3]:
                try:
                    secrets = self.api_client.get_paginated(f"/orgs/{org['login']}/actions/secrets")
                    if secrets is not None:
                        return {
                            "granted": True,
                            "message": f"Can access organization secrets: {org['login']}",
                            "details": {"org": org["login"], "secret_count": len(secrets)}
                        }
                except:
                    continue
            
            return {"granted": False, "message": "Cannot access organization secrets"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Organization secrets access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_team_management(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test team management permissions."""
        try:
            if org_name:
                teams = self.api_client.get_paginated(f"/orgs/{org_name}/teams")
                if teams:
                    # Try to get team details (requires read access)
                    try:
                        team_details = self.api_client.get(f"/teams/{teams[0]['id']}")
                        if team_details:
                            return {
                                "granted": True,
                                "message": f"Can access teams in organization: {org_name}",
                                "details": {"org": org_name, "team_count": len(teams)}
                            }
                    except:
                        pass
            
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:3]:
                try:
                    teams = self.api_client.get_paginated(f"/orgs/{org['login']}/teams")
                    if teams:
                        return {
                            "granted": True,
                            "message": f"Can access teams in organization: {org['login']}",
                            "details": {"org": org["login"], "team_count": len(teams)}
                        }
                except:
                    continue
            
            return {"granted": False, "message": "Cannot access teams"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Team access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_issues_access(self) -> Dict[str, Any]:
        """Test issues and pull requests access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        issues = self.api_client.get(f"/repos/{repo['full_name']}/issues", params={"state": "open", "per_page": 1})
                        if issues is not None:
                            return {
                                "granted": True,
                                "message": "Can access issues and pull requests",
                                "details": {"repo": repo["full_name"]}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access issues"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Issues access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_notifications_access(self) -> Dict[str, Any]:
        """Test notifications access."""
        try:
            notifications = self.api_client.get_paginated("/notifications")
            if notifications is not None:
                return {
                    "granted": True,
                    "message": f"Can access {len(notifications)} notifications",
                    "details": {"notification_count": len(notifications)}
                }
            return {"granted": False, "message": "Cannot access notifications"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Notifications access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_user_email_access(self) -> Dict[str, Any]:
        """Test user email access."""
        try:
            emails = self.api_client.get_paginated("/user/emails")
            if emails:
                return {
                    "granted": True,
                    "message": f"Can access {len(emails)} email addresses",
                    "details": {"email_count": len(emails)}
                }
            return {"granted": False, "message": "Cannot access user emails"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "User email access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_user_follow(self) -> Dict[str, Any]:
        """Test user follow/unfollow permissions."""
        try:
            # Try to get following list
            following = self.api_client.get_paginated("/user/following")
            if following is not None:
                return {
                    "granted": True,
                    "message": f"Can access following list ({len(following)} users)",
                    "details": {"following_count": len(following)}
                }
            return {"granted": False, "message": "Cannot access follow information"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Follow access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_discussions_read(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test discussions read access."""
        try:
            if org_name:
                try:
                    discussions = self.api_client.get_paginated(f"/orgs/{org_name}/discussions")
                    if discussions is not None:
                        return {
                            "granted": True,
                            "message": f"Can read discussions in organization: {org_name}",
                            "details": {"org": org_name, "discussion_count": len(discussions)}
                        }
                except:
                    pass
            
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:3]:
                try:
                    discussions = self.api_client.get_paginated(f"/orgs/{org['login']}/discussions")
                    if discussions is not None:
                        return {
                            "granted": True,
                            "message": f"Can read discussions in organization: {org['login']}",
                            "details": {"org": org["login"], "discussion_count": len(discussions)}
                        }
                except:
                    continue
            
            return {"granted": False, "message": "Cannot access discussions"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Discussions access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_discussions_write(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test discussions write access (requires write:discussion scope)."""
        # Write access is harder to test without actually creating content
        # We'll check if we can read discussions as a proxy
        return self._test_discussions_read(org_name)
    
    def _test_gpg_keys_read(self) -> Dict[str, Any]:
        """Test GPG keys read access."""
        try:
            gpg_keys = self.api_client.get_paginated("/user/gpg_keys")
            if gpg_keys is not None:
                return {
                    "granted": True,
                    "message": f"Can access {len(gpg_keys)} GPG keys",
                    "details": {"gpg_key_count": len(gpg_keys)}
                }
            return {"granted": False, "message": "Cannot access GPG keys"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "GPG keys access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_gpg_keys_admin(self) -> Dict[str, Any]:
        """Test GPG keys admin access (admin:gpg_key scope)."""
        # Admin access requires write operations, which we can't safely test
        # So we check read access as a proxy
        return self._test_gpg_keys_read()

    def _test_gpg_keys_write(self) -> Dict[str, Any]:
        """Test GPG keys write access (write:gpg_key scope)."""
        result = self._test_gpg_keys_read()
        if result["granted"]:
            result["message"] = "Can manage GPG keys (write access assumed)"
        return result
    
    def _test_ssh_keys_read(self) -> Dict[str, Any]:
        """Test SSH keys read access."""
        try:
            ssh_keys = self.api_client.get_paginated("/user/keys")
            if ssh_keys is not None:
                return {
                    "granted": True,
                    "message": f"Can access {len(ssh_keys)} SSH keys",
                    "details": {"ssh_key_count": len(ssh_keys)}
                }
            return {"granted": False, "message": "Cannot access SSH keys"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "SSH keys access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_ssh_keys_admin(self) -> Dict[str, Any]:
        """Test SSH keys admin access (admin:public_key scope)."""
        # Admin access requires write operations, which we can't safely test
        # So we check read access as a proxy
        return self._test_ssh_keys_read()

    def _test_ssh_keys_write(self) -> Dict[str, Any]:
        """Test SSH keys write access (write:public_key scope)."""
        result = self._test_ssh_keys_read()
        if result["granted"]:
            result["message"] = "Can manage SSH keys (write access assumed)"
        return result
    
    def _test_packages_write(self) -> Dict[str, Any]:
        """Test packages write access."""
        # Write access is harder to test without actually creating packages
        # We'll check read access as a proxy
        return self._test_packages_access()
    
    def _test_packages_delete(self) -> Dict[str, Any]:
        """Test packages delete access."""
        # Delete access requires write operations, which we can't safely test
        # We'll check read access as a proxy
        return self._test_packages_access()
    
    def _test_branch_protection(self) -> Dict[str, Any]:
        """Test branch protection rules access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        # Try to get branch protection rules
                        branches = self.api_client.get(f"/repos/{repo['full_name']}/branches")
                        if branches:
                            default_branch = repo.get("default_branch", "main")
                            try:
                                protection = self.api_client.get(
                                    f"/repos/{repo['full_name']}/branches/{default_branch}/protection"
                                )
                                if protection is not None:
                                    return {
                                        "granted": True,
                                        "message": "Can access branch protection rules",
                                        "details": {"repo": repo["full_name"]}
                                    }
                            except:
                                # Protection might not exist, but we can access branches
                                if branches:
                                    return {
                                        "granted": True,
                                        "message": "Can access branches (protection access likely)",
                                        "details": {"repo": repo["full_name"]}
                                    }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access branch protection"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Branch protection access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_code_scanning(self) -> Dict[str, Any]:
        """Test code scanning alerts access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        alerts = self.api_client.get_paginated(f"/repos/{repo['full_name']}/code-scanning/alerts")
                        if alerts is not None:
                            return {
                                "granted": True,
                                "message": "Can access code scanning alerts",
                                "details": {"repo": repo["full_name"], "alert_count": len(alerts)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access code scanning"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Code scanning access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_dependabot_alerts(self) -> Dict[str, Any]:
        """Test Dependabot alerts access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        alerts = self.api_client.get_paginated(f"/repos/{repo['full_name']}/dependabot/alerts")
                        if alerts is not None:
                            return {
                                "granted": True,
                                "message": "Can access Dependabot alerts",
                                "details": {"repo": repo["full_name"], "alert_count": len(alerts)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access Dependabot alerts"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Dependabot alerts access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_security_advisories(self) -> Dict[str, Any]:
        """Test security advisories access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        advisories = self.api_client.get_paginated(f"/repos/{repo['full_name']}/security-advisories")
                        if advisories is not None:
                            return {
                                "granted": True,
                                "message": "Can access security advisories",
                                "details": {"repo": repo["full_name"], "advisory_count": len(advisories)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access security advisories"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Security advisories access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_secret_scanning_alerts(self) -> Dict[str, Any]:
        """Test secret scanning alerts access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        alerts = self.api_client.get_paginated(f"/repos/{repo['full_name']}/secret-scanning/alerts")
                        if alerts is not None:
                            return {
                                "granted": True,
                                "message": "Can access secret scanning alerts",
                                "details": {"repo": repo["full_name"], "alert_count": len(alerts)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access secret scanning alerts"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Secret scanning access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_security_events(self) -> Dict[str, Any]:
        """Test consolidated security events scope."""
        code_scanning = self._test_code_scanning()
        dependabot = self._test_dependabot_alerts()
        secret_scanning = self._test_secret_scanning_alerts()
        granted = any(result["granted"] for result in [code_scanning, dependabot, secret_scanning])
        details = {
            "code_scanning": code_scanning,
            "dependabot": dependabot,
            "secret_scanning": secret_scanning
        }
        if granted:
            return {
                "granted": True,
                "message": "Can access security events data",
                "details": details
            }
        return {
            "granted": False,
            "message": "Security events access not detected",
            "details": details
        }
    
    def _test_projects_access(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test projects access."""
        try:
            if org_name:
                try:
                    projects = self.api_client.get_paginated(f"/orgs/{org_name}/projects")
                    if projects is not None:
                        return {
                            "granted": True,
                            "message": f"Can access projects in organization: {org_name}",
                            "details": {"org": org_name, "project_count": len(projects)}
                        }
                except:
                    pass
            
            # Try user projects
            try:
                projects = self.api_client.get_paginated("/user/projects")
                if projects is not None:
                    return {
                        "granted": True,
                        "message": f"Can access {len(projects)} user projects",
                        "details": {"project_count": len(projects)}
                    }
            except:
                pass
            
            return {"granted": False, "message": "Cannot access projects"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Projects access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_enterprise_admin(self) -> Dict[str, Any]:
        """Test enterprise admin access (Enterprise only)."""
        try:
            # Try to access enterprise API endpoints
            # Note: This may not work for regular GitHub.com
            enterprise = self.api_client.get("/enterprise/settings")
            if enterprise:
                return {
                    "granted": True,
                    "message": "Has enterprise admin access",
                    "details": {}
                }
            return {"granted": False, "message": "No enterprise admin access"}
        except Exception as e:
            # Enterprise endpoints may not exist on github.com
            if "404" in str(e):
                return {"granted": False, "message": "Enterprise API not available (not Enterprise instance)"}
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Enterprise admin access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_repo_status(self) -> Dict[str, Any]:
        """Test repo:status permission (access commit status)."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        # Try to get commit statuses
                        statuses = self.api_client.get(f"/repos/{repo['full_name']}/commits/{repo.get('default_branch', 'main')}/statuses")
                        if statuses is not None:
                            return {
                                "granted": True,
                                "message": "Can access commit statuses",
                                "details": {"repo": repo["full_name"]}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access commit statuses"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Commit status access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_repo_deployment(self) -> Dict[str, Any]:
        """Test repo_deployment permission (access deployment status)."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:5]:
                    try:
                        deployments = self.api_client.get_paginated(f"/repos/{repo['full_name']}/deployments")
                        if deployments is not None:
                            return {
                                "granted": True,
                                "message": "Can access deployments",
                                "details": {"repo": repo["full_name"], "deployment_count": len(deployments)}
                            }
                    except:
                        continue
            return {"granted": False, "message": "Cannot access deployments"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Deployment access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_public_repo(self) -> Dict[str, Any]:
        """Test public_repo permission (access public repositories)."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                public_repos = [r for r in repos if not r.get("private", False)]
                if public_repos:
                    return {
                        "granted": True,
                        "message": f"Can access {len(public_repos)} public repositories",
                        "details": {"public_repo_count": len(public_repos)}
                    }
            return {"granted": False, "message": "Cannot access public repositories"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Public repository access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_repo_invite(self) -> Dict[str, Any]:
        """Test repo:invite permission (access repository invitations)."""
        try:
            # Try to get repository invitations
            invitations = self.api_client.get_paginated("/user/repository_invitations")
            if invitations is not None:
                return {
                    "granted": True,
                    "message": f"Can access {len(invitations)} repository invitations",
                    "details": {"invitation_count": len(invitations)}
                }
            return {"granted": False, "message": "Cannot access repository invitations"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Repository invitation access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_write_org(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test write:org permission (write org and team membership)."""
        try:
            if org_name:
                # Try to access org teams (write access allows managing teams)
                teams = self.api_client.get_paginated(f"/orgs/{org_name}/teams")
                if teams is not None:
                    # Try to get team members (write access can manage members)
                    if teams:
                        try:
                            members = self.api_client.get_paginated(f"/teams/{teams[0]['id']}/members")
                            if members is not None:
                                return {
                                    "granted": True,
                                    "message": f"Can manage teams and members in organization: {org_name}",
                                    "details": {"org": org_name, "team_count": len(teams)}
                                }
                        except:
                            pass
            
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:3]:
                try:
                    teams = self.api_client.get_paginated(f"/orgs/{org['login']}/teams")
                    if teams is not None and len(teams) > 0:
                        return {
                            "granted": True,
                            "message": f"Can manage teams in organization: {org['login']}",
                            "details": {"org": org["login"], "team_count": len(teams)}
                        }
                except:
                    continue
            
            return {"granted": False, "message": "Cannot manage organization teams"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Organization write access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_admin_enterprise(self) -> Dict[str, Any]:
        """Test admin:enterprise permission (full control of enterprise accounts)."""
        try:
            # Try enterprise endpoints
            try:
                enterprise = self.api_client.get("/enterprise/settings")
                if enterprise:
                    return {
                        "granted": True,
                        "message": "Has enterprise admin access",
                        "details": {}
                    }
            except:
                pass
            
            # Try enterprise stats
            try:
                stats = self.api_client.get("/enterprise/stats/all")
                if stats:
                    return {
                        "granted": True,
                        "message": "Can access enterprise statistics",
                        "details": {}
                    }
            except:
                pass
            
            return {"granted": False, "message": "No enterprise admin access"}
        except Exception as e:
            if "404" in str(e):
                return {"granted": False, "message": "Enterprise API not available (not Enterprise instance)"}
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Enterprise admin access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_manage_billing_enterprise(self) -> Dict[str, Any]:
        """Test manage_billing:enterprise permission."""
        try:
            # Try to access billing information
            try:
                billing = self.api_client.get("/enterprise/billing")
                if billing:
                    return {
                        "granted": True,
                        "message": "Can manage enterprise billing",
                        "details": {}
                    }
            except:
                pass
            
            return {"granted": False, "message": "Cannot manage enterprise billing"}
        except Exception as e:
            if "404" in str(e):
                return {"granted": False, "message": "Enterprise billing API not available"}
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Enterprise billing access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_manage_runners_enterprise(self, enterprise_slug: Optional[str] = None) -> Dict[str, Any]:
        """Test manage_runners:enterprise permission."""
        slug = enterprise_slug or self.enterprise_slug
        if not slug:
            return {"granted": False, "message": "Enterprise slug required for runner management checks"}
        try:
            inspector = EnterpriseRunnerInspector(self.api_client, slug)
            summary = inspector.fetch_runners(max_pages=1)
            return {
                "granted": True,
                "message": f"Can manage enterprise runners for {slug}",
                "details": {
                    "enterprise": slug,
                    "runner_count": summary.get("total_runners", 0)
                }
            }
        except Exception as e:
            if "404" in str(e):
                return {"granted": False, "message": "Enterprise runners API not available (check slug)"}  # noqa: E501
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Enterprise runners management denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_read_runners_enterprise(self, enterprise_slug: Optional[str] = None) -> Dict[str, Any]:
        """Test read:runners:enterprise permission."""
        result = self._test_manage_runners_enterprise(enterprise_slug)
        if result["granted"]:
            result["message"] = "Can read enterprise runner metadata"
        return result
    
    def _test_read_enterprise(self) -> Dict[str, Any]:
        """Test read:enterprise permission (read enterprise account data)."""
        try:
            # Try to read enterprise information
            try:
                enterprise = self.api_client.get("/enterprise/settings")
                if enterprise:
                    return {
                        "granted": True,
                        "message": "Can read enterprise settings",
                        "details": {}
                    }
            except:
                pass
            
            # Try enterprise stats
            try:
                stats = self.api_client.get("/enterprise/stats/all")
                if stats:
                    return {
                        "granted": True,
                        "message": "Can read enterprise statistics",
                        "details": {}
                    }
            except:
                pass
            
            return {"granted": False, "message": "Cannot read enterprise data"}
        except Exception as e:
            if "404" in str(e):
                return {"granted": False, "message": "Enterprise API not available (not Enterprise instance)"}
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Enterprise read access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_read_audit_log(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test read:audit_log permission."""
        if not org_name:
            return {"granted": False, "message": "Organization name required for audit log access"}
        try:
            audit_events = self.api_client.get(f"/orgs/{org_name}/audit-log")
            if audit_events is not None:
                count = len(audit_events) if isinstance(audit_events, list) else 0
                return {
                    "granted": True,
                    "message": f"Can read audit log for {org_name}",
                    "details": {"event_count": count}
                }
            return {"granted": False, "message": "Cannot read audit log"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Audit log read access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}

    def _test_write_audit_log(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test write:audit_log permission (proxy via read access)."""
        result = self._test_read_audit_log(org_name)
        if result["granted"]:
            result["message"] = f"Audit log write access assumed for {org_name}"
        return result
    
    def _test_runners_repo(self) -> Dict[str, Any]:
        """Test repository-level GitHub Actions runners access."""
        try:
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                runners_info = []
                total_runners = 0
                
                for repo in repos[:10]:  # Check first 10 repos
                    try:
                        runners = self.api_client.get_paginated(f"/repos/{repo['full_name']}/actions/runners")
                        if runners is not None:
                            runner_count = len(runners)
                            if runner_count > 0:
                                runners_info.append({
                                    "repo": repo["full_name"],
                                    "runner_count": runner_count,
                                    "runners": [
                                        {
                                            "id": r.get("id", ""),
                                            "name": r.get("name", ""),
                                            "os": r.get("os", ""),
                                            "status": r.get("status", ""),
                                            "busy": r.get("busy", False)
                                        }
                                        for r in runners[:5]  # Limit details
                                    ]
                                })
                                total_runners += runner_count
                    except:
                        continue
                
                if runners_info:
                    return {
                        "granted": True,
                        "message": f"Can access runners in {len(runners_info)} repositories (total: {total_runners} runners)",
                        "details": {
                            "repo_count": len(runners_info),
                            "total_runners": total_runners,
                            "repos_with_runners": runners_info
                        }
                    }
            
            return {"granted": False, "message": "Cannot access repository runners"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Repository runners access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_runners_org(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Test organization-level GitHub Actions runners access."""
        try:
            runners_info = []
            
            if org_name:
                try:
                    runners = self.api_client.get_paginated(f"/orgs/{org_name}/actions/runners")
                    if runners is not None:
                        return {
                            "granted": True,
                            "message": f"Can access {len(runners)} organization runners: {org_name}",
                            "details": {
                                "org": org_name,
                                "runner_count": len(runners),
                                "runners": [
                                    {
                                        "id": r.get("id", ""),
                                        "name": r.get("name", ""),
                                        "os": r.get("os", ""),
                                        "status": r.get("status", ""),
                                        "busy": r.get("busy", False)
                                    }
                                    for r in runners[:10]  # Limit details
                                ]
                            }
                        }
                except:
                    pass
            
            # Try to get orgs and test
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:3]:
                try:
                    runners = self.api_client.get_paginated(f"/orgs/{org['login']}/actions/runners")
                    if runners is not None and len(runners) > 0:
                        runners_info.append({
                            "org": org["login"],
                            "runner_count": len(runners)
                        })
                except:
                    continue
            
            if runners_info:
                total_runners = sum(r["runner_count"] for r in runners_info)
                return {
                    "granted": True,
                    "message": f"Can access organization runners in {len(runners_info)} orgs (total: {total_runners} runners)",
                    "details": {
                        "org_count": len(runners_info),
                        "total_runners": total_runners,
                        "orgs_with_runners": runners_info
                    }
                }
            
            return {"granted": False, "message": "Cannot access organization runners"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Organization runners access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_repo_access_count(self) -> Dict[str, Any]:
        """Test and count how many repositories have access."""
        try:
            # Get all repositories
            repos = self.api_client.get_paginated("/user/repos")
            
            if repos:
                # Categorize repositories
                private_repos = [r for r in repos if r.get("private", False)]
                public_repos = [r for r in repos if not r.get("private", False)]
                archived_repos = [r for r in repos if r.get("archived", False)]
                
                # Check permissions for each repo
                repos_with_admin = []
                repos_with_push = []
                repos_with_pull = []
                
                for repo in repos[:50]:  # Check first 50 repos for performance
                    try:
                        repo_info = self.api_client.get(f"/repos/{repo['full_name']}")
                        if repo_info:
                            perms = repo_info.get("permissions", {})
                            if perms.get("admin", False):
                                repos_with_admin.append(repo["full_name"])
                            if perms.get("push", False):
                                repos_with_push.append(repo["full_name"])
                            if perms.get("pull", False):
                                repos_with_pull.append(repo["full_name"])
                    except:
                        continue
                
                return {
                    "granted": True,
                    "message": f"Has access to {len(repos)} repositories",
                    "details": {
                        "total_repos": len(repos),
                        "private_repos": len(private_repos),
                        "public_repos": len(public_repos),
                        "archived_repos": len(archived_repos),
                        "repos_with_admin": len(repos_with_admin),
                        "repos_with_push": len(repos_with_push),
                        "repos_with_pull": len(repos_with_pull),
                        "sample_admin_repos": repos_with_admin[:10],
                        "sample_push_repos": repos_with_push[:10],
                        "sample_pull_repos": repos_with_pull[:10]
                    }
                }
            
            return {"granted": False, "message": "Cannot access repositories"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Repository access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def _test_secrets_comprehensive(self, org_name: Optional[str] = None) -> Dict[str, Any]:
        """Comprehensive test of all secrets access (repo and org level)."""
        try:
            secrets_summary = {
                "repo_secrets": [],
                "org_secrets": [],
                "total_repo_secrets": 0,
                "total_org_secrets": 0,
                "repos_with_secrets": 0,
                "orgs_with_secrets": 0
            }
            
            # Test repository secrets
            repos = self.api_client.get_paginated("/user/repos")
            if repos:
                for repo in repos[:20]:  # Check first 20 repos
                    try:
                        secrets = self.api_client.get_paginated(f"/repos/{repo['full_name']}/actions/secrets")
                        if secrets is not None and len(secrets) > 0:
                            secrets_summary["repos_with_secrets"] += 1
                            secrets_summary["total_repo_secrets"] += len(secrets)
                            secrets_summary["repo_secrets"].append({
                                "repo": repo["full_name"],
                                "secret_count": len(secrets),
                                "secrets": [
                                    {
                                        "name": s.get("name", ""),
                                        "created_at": s.get("created_at", ""),
                                        "updated_at": s.get("updated_at", "")
                                    }
                                    for s in secrets
                                ]
                            })
                    except:
                        continue
            
            # Test organization secrets
            if org_name:
                try:
                    secrets = self.api_client.get_paginated(f"/orgs/{org_name}/actions/secrets")
                    if secrets is not None and len(secrets) > 0:
                        secrets_summary["orgs_with_secrets"] += 1
                        secrets_summary["total_org_secrets"] += len(secrets)
                        secrets_summary["org_secrets"].append({
                            "org": org_name,
                            "secret_count": len(secrets),
                            "secrets": [
                                {
                                    "name": s.get("name", ""),
                                    "visibility": s.get("visibility", ""),
                                    "created_at": s.get("created_at", ""),
                                    "updated_at": s.get("updated_at", "")
                                }
                                for s in secrets
                            ]
                        })
                except:
                    pass
            
            # Try other orgs
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs[:5]:  # Check first 5 orgs
                try:
                    secrets = self.api_client.get_paginated(f"/orgs/{org['login']}/actions/secrets")
                    if secrets is not None and len(secrets) > 0:
                        secrets_summary["orgs_with_secrets"] += 1
                        secrets_summary["total_org_secrets"] += len(secrets)
                        secrets_summary["org_secrets"].append({
                            "org": org["login"],
                            "secret_count": len(secrets),
                            "secrets": [
                                {
                                    "name": s.get("name", ""),
                                    "visibility": s.get("visibility", ""),
                                    "created_at": s.get("created_at", ""),
                                    "updated_at": s.get("updated_at", "")
                                }
                                for s in secrets
                            ]
                        })
                except:
                    continue
            
            total_secrets = secrets_summary["total_repo_secrets"] + secrets_summary["total_org_secrets"]
            
            if total_secrets > 0:
                return {
                    "granted": True,
                    "message": f"Can access {total_secrets} secrets ({secrets_summary['total_repo_secrets']} repo, {secrets_summary['total_org_secrets']} org)",
                    "details": secrets_summary
                }
            
            return {"granted": False, "message": "Cannot access secrets or no secrets found"}
        except Exception as e:
            if "403" in str(e) or "Forbidden" in str(e):
                return {"granted": False, "message": "Secrets access denied"}
            return {"granted": False, "message": f"Error: {str(e)}"}
    
    def validate_all_permissions(self, org_name: Optional[str] = None, enterprise_slug: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate all permissions for the API key.
        
        Args:
            org_name: Optional organization name to test org-specific permissions
        
        Returns:
            Dictionary with all permission validation results
        """
        target_enterprise = enterprise_slug or self.enterprise_slug

        results = {
            "critical_permissions": {},
            "standard_permissions": {},
            "summary": {
                "total_tested": 0,
                "granted": 0,
                "denied": 0,
                "errors": 0
            }
        }
        
        # Test critical permissions
        critical_tests = {
            "repo": self._test_repo_access,
            "repo_write": self._test_repo_write,
            "repo_delete": self._test_repo_delete,
            "admin:org": lambda: self._test_org_admin(org_name),
            "read:org": lambda: self._test_org_read(org_name),
            "write:org": lambda: self._test_write_org(org_name),
            "admin:repo_hook": self._test_repo_hooks_admin,
            "write:repo_hook": self._test_repo_hooks_write,
            "read:repo_hook": self._test_repo_hooks_read,
            "admin:org_hook": lambda: self._test_org_hooks_admin(org_name),
            "read:org_hook": lambda: self._test_org_hooks_read(org_name),
            "workflow": self._test_workflow_access,
            "repo_secrets": self._test_repo_secrets,
            "org_secrets": lambda: self._test_org_secrets(org_name),
            "write:packages": self._test_packages_write,
            "delete:packages": self._test_packages_delete,
            "admin:gpg_key": self._test_gpg_keys_admin,
            "write:gpg_key": self._test_gpg_keys_write,
            "admin:public_key": self._test_ssh_keys_admin,
            "write:public_key": self._test_ssh_keys_write,
            "admin:enterprise": self._test_admin_enterprise,
            "manage_billing:enterprise": self._test_manage_billing_enterprise,
            "enterprise_admin": self._test_enterprise_admin,
            "manage_runners:enterprise": lambda: self._test_manage_runners_enterprise(target_enterprise),
            "read:runners:enterprise": lambda: self._test_read_runners_enterprise(target_enterprise),
            "read:audit_log": lambda: self._test_read_audit_log(org_name),
            "write:audit_log": lambda: self._test_write_audit_log(org_name),
        }
        
        for perm_name, test_func in critical_tests.items():
            result = self._test_permission(perm_name, test_func)
            results["critical_permissions"][perm_name] = result
            results["summary"]["total_tested"] += 1
            if result["granted"]:
                results["summary"]["granted"] += 1
            else:
                results["summary"]["denied"] += 1
            if "Error" in result["message"]:
                results["summary"]["errors"] += 1
        
        # Test standard permissions
        standard_tests = {
            "read:user": self._test_user_info_access,
            "user": self._test_user_full_profile,
            "gist": self._test_gist_access,
            "read:packages": self._test_packages_access,
            "notifications": self._test_notifications_access,
            "user:email": self._test_user_email_access,
            "user:follow": self._test_user_follow,
            "read:discussion": lambda: self._test_discussions_read(org_name),
            "write:discussion": lambda: self._test_discussions_write(org_name),
            "read:gpg_key": self._test_gpg_keys_read,
            "read:public_key": self._test_ssh_keys_read,
            "read:enterprise": self._test_read_enterprise,
            "repo:status": self._test_repo_status,
            "repo_deployment": self._test_repo_deployment,
            "public_repo": self._test_public_repo,
            "repo:invite": self._test_repo_invite,
            "issues": self._test_issues_access,
            "team_management": lambda: self._test_team_management(org_name),
            "branch_protection": self._test_branch_protection,
            "code_scanning": self._test_code_scanning,
            "dependabot_alerts": self._test_dependabot_alerts,
            "security_advisories": self._test_security_advisories,
            "secret_scanning_alerts": self._test_secret_scanning_alerts,
            "security_events": self._test_security_events,
            "projects": lambda: self._test_projects_access(org_name),
            "runners_repo": self._test_runners_repo,
            "runners_org": lambda: self._test_runners_org(org_name),
            "repo_access_count": self._test_repo_access_count,
            "secrets_comprehensive": lambda: self._test_secrets_comprehensive(org_name),
            "codespace": self._test_codespaces_access,
            "codespaces_metadata": self._test_codespaces_metadata,
            "codespaces_user": self._test_codespaces_user,
            "codespaces_lifecycle_admin": self._test_codespaces_lifecycle_admin,
        }
        
        for perm_name, test_func in standard_tests.items():
            result = self._test_permission(perm_name, test_func)
            results["standard_permissions"][perm_name] = result
            results["summary"]["total_tested"] += 1
            if result["granted"]:
                results["summary"]["granted"] += 1
            else:
                results["summary"]["denied"] += 1
            if "Error" in result["message"]:
                results["summary"]["errors"] += 1
        
        # Get authenticated user info for additional context
        try:
            user_info = self.api_client.test_authentication()
            if user_info:
                results["authenticated_user"] = {
                    "login": user_info.get("login", ""),
                    "type": user_info.get("type", ""),
                    "name": user_info.get("name", ""),
                    "email": user_info.get("email", "")
                }
        except:
            pass
        
        # Get rate limit info
        try:
            rate_limit = self.api_client.get_rate_limit_info()
            if rate_limit:
                results["rate_limit"] = rate_limit.get("rate", {})
        except:
            pass
        
        return results

