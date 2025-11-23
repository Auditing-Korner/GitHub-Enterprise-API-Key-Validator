"""
API Key Comparison Module

Compares two or more GitHub API keys to identify differences in:
- Permissions and scopes
- Accessible resources
- Security posture
"""

from typing import Dict, List, Optional, Any
from .api_client import GitHubAPIClient
from .permissions import PermissionChecker
from .enumerator import CompanyEnumerator


class APIKeyComparator:
    """Compares multiple GitHub API keys."""
    
    def __init__(self):
        self.comparisons = []
    
    def compare_keys(self, 
                    api_keys: List[Dict[str, str]], 
                    org_name: Optional[str] = None,
                    enterprise_slug: Optional[str] = None) -> Dict[str, Any]:
        """
        Compare multiple API keys.
        
        Args:
            api_keys: List of dictionaries with 'name' and 'key' fields
            org_name: Optional organization name to test
            enterprise_slug: Optional enterprise slug
            
        Returns:
            Dictionary with comparison results
        """
        comparison_results = {
            "keys_compared": len(api_keys),
            "comparisons": [],
            "summary": {
                "permissions": {},
                "resources": {},
                "security_posture": {}
            },
            "differences": [],
            "errors": []
        }
        
        # Analyze each key
        key_analyses = []
        for key_info in api_keys:
            key_name = key_info.get("name", f"Key_{len(key_analyses) + 1}")
            api_key = key_info.get("key", "")
            base_url = key_info.get("base_url")
            
            try:
                api_client = GitHubAPIClient(api_key, base_url)
                
                # Test authentication
                user_info = api_client.test_authentication()
                if not user_info:
                    comparison_results["errors"].append(f"{key_name}: Authentication failed")
                    continue
                
                # Get permissions
                permission_checker = PermissionChecker(api_client, enterprise_slug=enterprise_slug)
                permissions = permission_checker.validate_all_permissions(
                    org_name=org_name,
                    enterprise_slug=enterprise_slug
                )
                
                # Get basic enumeration
                enumerator = CompanyEnumerator(api_client)
                enumeration = None
                if org_name:
                    try:
                        enumeration = enumerator.enumerate_organization(org_name)
                    except Exception:
                        pass
                
                # Get token metadata
                from .token_metadata import TokenMetadataAnalyzer
                token_metadata = TokenMetadataAnalyzer(api_client)
                metadata = token_metadata.analyze_token_metadata()
                
                key_analysis = {
                    "name": key_name,
                    "user": user_info.get("login", "Unknown"),
                    "permissions": permissions,
                    "enumeration": enumeration,
                    "token_metadata": metadata,
                    "scopes": metadata.get("scopes", [])
                }
                
                key_analyses.append(key_analysis)
                comparison_results["comparisons"].append(key_analysis)
                
            except Exception as e:
                comparison_results["errors"].append(f"{key_name}: {str(e)}")
        
        # Compare permissions
        if len(key_analyses) >= 2:
            comparison_results["summary"]["permissions"] = self._compare_permissions(key_analyses)
            comparison_results["summary"]["resources"] = self._compare_resources(key_analyses)
            comparison_results["summary"]["security_posture"] = self._compare_security_posture(key_analyses)
            comparison_results["differences"] = self._identify_differences(key_analyses)
        
        return comparison_results
    
    def _compare_permissions(self, key_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare permissions across keys."""
        all_permissions = set()
        permission_matrix = {}
        
        # Collect all unique permissions
        for analysis in key_analyses:
            perms = analysis.get("permissions", {})
            critical = perms.get("critical_permissions", {})
            standard = perms.get("standard_permissions", {})
            
            for perm_name in list(critical.keys()) + list(standard.keys()):
                all_permissions.add(perm_name)
        
        # Build matrix
        for perm_name in all_permissions:
            permission_matrix[perm_name] = {}
            for analysis in key_analyses:
                key_name = analysis["name"]
                perms = analysis.get("permissions", {})
                critical = perms.get("critical_permissions", {})
                standard = perms.get("standard_permissions", {})
                
                perm_data = critical.get(perm_name) or standard.get(perm_name)
                permission_matrix[perm_name][key_name] = {
                    "granted": perm_data.get("granted", False) if perm_data else False,
                    "message": perm_data.get("message", "") if perm_data else "Not tested"
                }
        
        return {
            "total_permissions": len(all_permissions),
            "permission_matrix": permission_matrix,
            "common_permissions": self._find_common_permissions(permission_matrix),
            "unique_permissions": self._find_unique_permissions(permission_matrix)
        }
    
    def _compare_resources(self, key_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare accessible resources."""
        resource_comparison = {
            "repositories": {},
            "organizations": {},
            "secrets": {}
        }
        
        for analysis in key_analyses:
            key_name = analysis["name"]
            enumeration = analysis.get("enumeration", {})
            
            # Repositories
            repos = enumeration.get("repositories", [])
            resource_comparison["repositories"][key_name] = {
                "count": len(repos) if isinstance(repos, list) else 0,
                "private": len([r for r in repos if r.get("private", False)]) if isinstance(repos, list) else 0
            }
            
            # Organizations
            org_info = enumeration.get("organization_info", {})
            resource_comparison["organizations"][key_name] = {
                "name": org_info.get("login", ""),
                "members": len(enumeration.get("members", []))
            }
            
            # Secrets
            secrets = enumeration.get("secrets", [])
            resource_comparison["secrets"][key_name] = len(secrets) if isinstance(secrets, list) else 0
        
        return resource_comparison
    
    def _compare_security_posture(self, key_analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare security posture."""
        posture_comparison = {}
        
        for analysis in key_analyses:
            key_name = analysis["name"]
            perms = analysis.get("permissions", {})
            critical_perms = perms.get("critical_permissions", {})
            
            critical_granted = sum(1 for p in critical_perms.values() if p.get("granted", False))
            total_critical = len(critical_perms)
            
            scopes = analysis.get("scopes", [])
            admin_scopes = [s for s in scopes if "admin" in s.lower() or "delete" in s.lower()]
            
            posture_comparison[key_name] = {
                "critical_permissions_granted": critical_granted,
                "total_critical_permissions": total_critical,
                "admin_scopes_count": len(admin_scopes),
                "total_scopes": len(scopes),
                "risk_level": self._calculate_risk_level(critical_granted, len(admin_scopes))
            }
        
        return posture_comparison
    
    def _calculate_risk_level(self, critical_perms: int, admin_scopes: int) -> str:
        """Calculate risk level."""
        if critical_perms >= 5 or admin_scopes >= 3:
            return "CRITICAL"
        elif critical_perms >= 3 or admin_scopes >= 1:
            return "HIGH"
        elif critical_perms >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _find_common_permissions(self, permission_matrix: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
        """Find permissions common to all keys."""
        common = {}
        
        for perm_name, key_data in permission_matrix.items():
            granted_keys = [key for key, data in key_data.items() if data.get("granted", False)]
            if len(granted_keys) == len(key_data):
                common[perm_name] = granted_keys
        
        return common
    
    def _find_unique_permissions(self, permission_matrix: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
        """Find permissions unique to specific keys."""
        unique = {}
        
        for perm_name, key_data in permission_matrix.items():
            granted_keys = [key for key, data in key_data.items() if data.get("granted", False)]
            if len(granted_keys) == 1:
                unique_key = granted_keys[0]
                if unique_key not in unique:
                    unique[unique_key] = []
                unique[unique_key].append(perm_name)
        
        return unique
    
    def _identify_differences(self, key_analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify key differences between API keys."""
        differences = []
        
        if len(key_analyses) < 2:
            return differences
        
        # Compare scopes
        all_scopes = set()
        scope_map = {}
        for analysis in key_analyses:
            key_name = analysis["name"]
            scopes = set(analysis.get("scopes", []))
            scope_map[key_name] = scopes
            all_scopes.update(scopes)
        
        for scope in all_scopes:
            keys_with_scope = [name for name, scopes in scope_map.items() if scope in scopes]
            if len(keys_with_scope) < len(key_analyses):
                differences.append({
                    "type": "scope_difference",
                    "scope": scope,
                    "keys_with": keys_with_scope,
                    "keys_without": [name for name in scope_map.keys() if name not in keys_with_scope]
                })
        
        # Compare critical permissions
        for i, analysis1 in enumerate(key_analyses):
            for analysis2 in key_analyses[i+1:]:
                perms1 = analysis1.get("permissions", {})
                perms2 = analysis2.get("permissions", {})
                
                critical1 = perms1.get("critical_permissions", {})
                critical2 = perms2.get("critical_permissions", {})
                
                for perm_name in set(list(critical1.keys()) + list(critical2.keys())):
                    granted1 = critical1.get(perm_name, {}).get("granted", False)
                    granted2 = critical2.get(perm_name, {}).get("granted", False)
                    
                    if granted1 != granted2:
                        differences.append({
                            "type": "permission_difference",
                            "permission": perm_name,
                            "key1": analysis1["name"],
                            "key1_granted": granted1,
                            "key2": analysis2["name"],
                            "key2_granted": granted2
                        })
        
        return differences


def compare_api_keys(api_keys: List[Dict[str, str]], 
                     org_name: Optional[str] = None,
                     enterprise_slug: Optional[str] = None) -> Dict[str, Any]:
    """
    Compare multiple API keys.
    
    Args:
        api_keys: List of dictionaries with 'name' and 'key' fields
        org_name: Optional organization name
        enterprise_slug: Optional enterprise slug
        
    Returns:
        Comparison results
    """
    comparator = APIKeyComparator()
    return comparator.compare_keys(api_keys, org_name, enterprise_slug)

