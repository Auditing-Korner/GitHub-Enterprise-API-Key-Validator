"""
Packages and Container Registry Analysis Module

Analyzes packages and container registries:
- npm, Docker, Maven, NuGet, RubyGems packages
- Package versions and permissions
- Container registry images
- Package download statistics
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient


class PackagesAnalyzer:
    """Analyzes packages and container registries."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def analyze_user_packages(self) -> Dict[str, Any]:
        """
        Analyze user packages.
        
        Returns:
            Dictionary with user packages information
        """
        packages_data = {
            "packages": [],
            "package_types": {},
            "total_packages": 0,
            "errors": []
        }
        
        # Package types to check
        package_types = ["npm", "maven", "rubygems", "docker", "nuget", "container"]
        
        for pkg_type in package_types:
            try:
                packages = self.api_client.get_paginated(f"/user/packages?package_type={pkg_type}")
                for pkg in packages:
                    package_data = {
                        "id": pkg.get("id", ""),
                        "name": pkg.get("name", ""),
                        "package_type": pkg.get("package_type", ""),
                        "owner": {
                            "login": pkg.get("owner", {}).get("login", ""),
                            "type": pkg.get("owner", {}).get("type", "")
                        } if pkg.get("owner") else {},
                        "version_count": pkg.get("version_count", 0),
                        "visibility": pkg.get("visibility", ""),
                        "url": pkg.get("url", ""),
                        "html_url": pkg.get("html_url", ""),
                        "created_at": pkg.get("created_at", ""),
                        "updated_at": pkg.get("updated_at", "")
                    }
                    
                    # Get package versions
                    try:
                        versions = self.api_client.get_paginated(
                            f"/user/packages/{pkg_type}/{pkg.get('name', '')}/versions"
                        )
                        package_data["versions"] = [
                            {
                                "id": v.get("id", ""),
                                "name": v.get("name", ""),
                                "url": v.get("url", ""),
                                "package_html_url": v.get("package_html_url", ""),
                                "created_at": v.get("created_at", ""),
                                "updated_at": v.get("updated_at", ""),
                                "html_url": v.get("html_url", "")
                            }
                            for v in versions[:20]  # Limit for performance
                        ]
                    except Exception:
                        package_data["versions"] = []
                    
                    packages_data["packages"].append(package_data)
                    packages_data["total_packages"] += 1
                    
                    # Count by type
                    if pkg_type not in packages_data["package_types"]:
                        packages_data["package_types"][pkg_type] = 0
                    packages_data["package_types"][pkg_type] += 1
            except Exception as e:
                packages_data["errors"].append(f"Failed to get {pkg_type} packages: {str(e)}")
        
        return packages_data
    
    def analyze_org_packages(self, org_name: str) -> Dict[str, Any]:
        """
        Analyze organization packages.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with organization packages information
        """
        org_packages = {
            "organization": org_name,
            "packages": [],
            "package_types": {},
            "total_packages": 0,
            "errors": []
        }
        
        package_types = ["npm", "maven", "rubygems", "docker", "nuget", "container"]
        
        for pkg_type in package_types:
            try:
                packages = self.api_client.get_paginated(
                    f"/orgs/{org_name}/packages",
                    params={"package_type": pkg_type}
                )
                for pkg in packages:
                    package_data = {
                        "id": pkg.get("id", ""),
                        "name": pkg.get("name", ""),
                        "package_type": pkg.get("package_type", ""),
                        "owner": {
                            "login": pkg.get("owner", {}).get("login", ""),
                            "type": pkg.get("owner", {}).get("type", "")
                        } if pkg.get("owner") else {},
                        "version_count": pkg.get("version_count", 0),
                        "visibility": pkg.get("visibility", ""),
                        "url": pkg.get("url", ""),
                        "html_url": pkg.get("html_url", ""),
                        "created_at": pkg.get("created_at", ""),
                        "updated_at": pkg.get("updated_at", "")
                    }
                    
                    # Get package versions
                    try:
                        versions = self.api_client.get_paginated(
                            f"/orgs/{org_name}/packages/{pkg_type}/{pkg.get('name', '')}/versions"
                        )
                        package_data["versions"] = [
                            {
                                "id": v.get("id", ""),
                                "name": v.get("name", ""),
                                "url": v.get("url", ""),
                                "created_at": v.get("created_at", ""),
                                "updated_at": v.get("updated_at", "")
                            }
                            for v in versions[:20]  # Limit for performance
                        ]
                    except Exception:
                        package_data["versions"] = []
                    
                    org_packages["packages"].append(package_data)
                    org_packages["total_packages"] += 1
                    
                    if pkg_type not in org_packages["package_types"]:
                        org_packages["package_types"][pkg_type] = 0
                    org_packages["package_types"][pkg_type] += 1
            except Exception as e:
                org_packages["errors"].append(f"Failed to get {pkg_type} packages: {str(e)}")
        
        return org_packages
    
    def analyze_all_packages(self) -> Dict[str, Any]:
        """
        Analyze packages across user and all organizations.
        
        Returns:
            Dictionary with comprehensive packages analysis
        """
        all_packages = {
            "user_packages": {},
            "organization_packages": {},
            "summary": {
                "total_user_packages": 0,
                "total_org_packages": 0,
                "package_types": {},
                "orgs_with_packages": 0
            },
            "errors": []
        }
        
        # Get user packages
        try:
            user_packages = self.analyze_user_packages()
            all_packages["user_packages"] = user_packages
            all_packages["summary"]["total_user_packages"] = user_packages.get("total_packages", 0)
            for pkg_type, count in user_packages.get("package_types", {}).items():
                if pkg_type not in all_packages["summary"]["package_types"]:
                    all_packages["summary"]["package_types"][pkg_type] = 0
                all_packages["summary"]["package_types"][pkg_type] += count
        except Exception as e:
            all_packages["errors"].append(f"Failed to get user packages: {str(e)}")
        
        # Get organization packages
        try:
            orgs = self.api_client.get_paginated("/user/orgs")
            for org in orgs:
                org_name = org.get("login", "")
                if org_name:
                    try:
                        org_packages = self.analyze_org_packages(org_name)
                        all_packages["organization_packages"][org_name] = org_packages
                        
                        if org_packages.get("total_packages", 0) > 0:
                            all_packages["summary"]["orgs_with_packages"] += 1
                            all_packages["summary"]["total_org_packages"] += org_packages.get("total_packages", 0)
                            
                            for pkg_type, count in org_packages.get("package_types", {}).items():
                                if pkg_type not in all_packages["summary"]["package_types"]:
                                    all_packages["summary"]["package_types"][pkg_type] = 0
                                all_packages["summary"]["package_types"][pkg_type] += count
                    except Exception as e:
                        all_packages["errors"].append(f"Failed to get packages for {org_name}: {str(e)}")
        except Exception as e:
            all_packages["errors"].append(f"Failed to get organizations: {str(e)}")
        
        return all_packages

