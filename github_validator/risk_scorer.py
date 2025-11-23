"""
Risk Scoring and Prioritization Module

Calculates risk scores for security findings and provides prioritization.
"""

from typing import Dict, List, Any, Optional, Tuple
from enum import Enum


class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskScorer:
    """Calculates risk scores and prioritizes findings."""
    
    # Risk weights for different permission types
    PERMISSION_WEIGHTS = {
        "admin:org": 100,
        "admin:enterprise": 100,
        "admin:repo": 90,
        "admin:public_key": 85,
        "admin:gpg_key": 85,
        "admin:org_hook": 80,
        "admin:repo_hook": 75,
        "repo": 70,
        "workflow": 70,
        "write:packages": 65,
        "read:packages": 40,
        "delete:packages": 80,
        "write:org": 75,
        "read:org": 30,
        "user:email": 20,
        "user:follow": 10,
        "read:user": 15,
    }
    
    # Risk weights for resource types
    RESOURCE_WEIGHTS = {
        "secrets": 90,
        "webhooks": 70,
        "runners": 85,
        "codespaces": 80,
        "packages": 60,
        "repositories": 50,
        "organizations": 70,
        "deploy_keys": 75,
        "collaborators": 60,
        "environments": 65,
        "actions": 70,
        "audit_logs": 55,
    }
    
    # Risk multipliers for specific conditions
    MULTIPLIERS = {
        "public_repo_access": 1.2,
        "private_repo_access": 1.5,
        "write_access": 1.3,
        "admin_access": 1.5,
        "secrets_exposed": 2.0,
        "runner_execution": 1.8,
        "codespace_creation": 1.4,
        "package_publish": 1.3,
        "webhook_modification": 1.4,
    }
    
    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.total_risk_score = 0
    
    def calculate_permission_risk(self, permission_name: str, granted: bool, 
                                 context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate risk score for a permission.
        
        Args:
            permission_name: Name of the permission
            granted: Whether permission is granted
            context: Additional context (repo type, etc.)
            
        Returns:
            Risk assessment dictionary
        """
        if not granted:
            return {
                "risk_score": 0,
                "risk_level": RiskLevel.INFO.value,
                "priority": 0,
                "reasoning": "Permission not granted"
            }
        
        base_score = self.PERMISSION_WEIGHTS.get(permission_name, 50)
        
        # Apply multipliers based on context
        multiplier = 1.0
        if context:
            if context.get("is_private_repo"):
                multiplier *= self.MULTIPLIERS.get("private_repo_access", 1.0)
            if context.get("is_public_repo"):
                multiplier *= self.MULTIPLIERS.get("public_repo_access", 1.0)
            if "write" in permission_name.lower() or "admin" in permission_name.lower():
                if "admin" in permission_name.lower():
                    multiplier *= self.MULTIPLIERS.get("admin_access", 1.0)
                else:
                    multiplier *= self.MULTIPLIERS.get("write_access", 1.0)
        
        risk_score = base_score * multiplier
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = RiskLevel.CRITICAL
            priority = 1
        elif risk_score >= 60:
            risk_level = RiskLevel.HIGH
            priority = 2
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
            priority = 3
        elif risk_score >= 20:
            risk_level = RiskLevel.LOW
            priority = 4
        else:
            risk_level = RiskLevel.INFO
            priority = 5
        
        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level.value,
            "priority": priority,
            "base_score": base_score,
            "multiplier": round(multiplier, 2),
            "reasoning": self._generate_reasoning(permission_name, risk_level, context)
        }
    
    def calculate_resource_risk(self, resource_type: str, count: int,
                                details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Calculate risk score for a resource type.
        
        Args:
            resource_type: Type of resource (secrets, webhooks, etc.)
            count: Number of resources
            details: Additional details about resources
            
        Returns:
            Risk assessment dictionary
        """
        base_weight = self.RESOURCE_WEIGHTS.get(resource_type, 50)
        
        # Scale based on count (logarithmic scale to avoid extreme scores)
        import math
        if count == 0:
            return {
                "risk_score": 0,
                "risk_level": RiskLevel.INFO.value,
                "priority": 0
            }
        
        count_factor = min(math.log10(count + 1) * 10, 50)  # Cap at 50
        risk_score = base_weight * (1 + count_factor / 100)
        
        # Apply multipliers from details
        multiplier = 1.0
        if details:
            if details.get("has_secrets_exposed"):
                multiplier *= self.MULTIPLIERS.get("secrets_exposed", 1.0)
            if details.get("has_public_access"):
                multiplier *= self.MULTIPLIERS.get("public_repo_access", 1.0)
        
        risk_score *= multiplier
        
        # Determine risk level
        if risk_score >= 100:
            risk_level = RiskLevel.CRITICAL
            priority = 1
        elif risk_score >= 70:
            risk_level = RiskLevel.HIGH
            priority = 2
        elif risk_score >= 40:
            risk_level = RiskLevel.MEDIUM
            priority = 3
        else:
            risk_level = RiskLevel.LOW
            priority = 4
        
        return {
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level.value,
            "priority": priority,
            "count": count,
            "base_weight": base_weight,
            "multiplier": round(multiplier, 2)
        }
    
    def assess_permissions(self, permissions_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess risk for all permissions.
        
        Args:
            permissions_data: Permissions validation data
            
        Returns:
            Risk assessment summary
        """
        assessments = []
        total_risk = 0
        critical_count = 0
        high_count = 0
        
        # Assess critical permissions
        critical_perms = permissions_data.get("critical_permissions", {})
        for perm_name, perm_data in critical_perms.items():
            granted = perm_data.get("granted", False)
            assessment = self.calculate_permission_risk(perm_name, granted)
            assessment["permission"] = perm_name
            assessment["granted"] = granted
            assessments.append(assessment)
            
            if granted:
                total_risk += assessment["risk_score"]
                if assessment["risk_level"] == RiskLevel.CRITICAL.value:
                    critical_count += 1
                elif assessment["risk_level"] == RiskLevel.HIGH.value:
                    high_count += 1
        
        # Assess standard permissions
        standard_perms = permissions_data.get("standard_permissions", {})
        for perm_name, perm_data in standard_perms.items():
            granted = perm_data.get("granted", False)
            assessment = self.calculate_permission_risk(perm_name, granted)
            assessment["permission"] = perm_name
            assessment["granted"] = granted
            assessments.append(assessment)
            
            if granted:
                total_risk += assessment["risk_score"]
                if assessment["risk_level"] == RiskLevel.CRITICAL.value:
                    critical_count += 1
                elif assessment["risk_level"] == RiskLevel.HIGH.value:
                    high_count += 1
        
        # Sort by priority
        assessments.sort(key=lambda x: (x["priority"], -x["risk_score"]))
        
        return {
            "assessments": assessments,
            "total_risk_score": round(total_risk, 2),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": sum(1 for a in assessments if a["risk_level"] == RiskLevel.MEDIUM.value and a.get("granted")),
            "low_count": sum(1 for a in assessments if a["risk_level"] == RiskLevel.LOW.value and a.get("granted")),
            "top_risks": assessments[:10]  # Top 10 risks
        }
    
    def assess_resources(self, resources_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess risk for all resources.
        
        Args:
            resources_data: Resources enumeration data
            
        Returns:
            Risk assessment summary
        """
        assessments = []
        total_risk = 0
        
        # Assess different resource types
        resource_types = {
            "secrets": resources_data.get("secrets", []),
            "webhooks": resources_data.get("webhooks", {}),
            "repositories": resources_data.get("repositories", {}),
            "runners": resources_data.get("runners", {}),
            "codespaces": resources_data.get("codespaces", {}),
            "packages": resources_data.get("packages", {}),
        }
        
        for resource_type, resource_data in resource_types.items():
            if not resource_data:
                continue
            
            count = 0
            details = {}
            
            if isinstance(resource_data, list):
                count = len(resource_data)
                if resource_type == "secrets":
                    details["has_secrets_exposed"] = count > 0
            elif isinstance(resource_data, dict):
                if "total" in resource_data:
                    count = resource_data["total"]
                elif "summary" in resource_data:
                    summary = resource_data["summary"]
                    count = summary.get("total", summary.get("total_runners", summary.get("total_codespaces", 0)))
            
            if count > 0:
                assessment = self.calculate_resource_risk(resource_type, count, details)
                assessment["resource_type"] = resource_type
                assessment["count"] = count
                assessments.append(assessment)
                total_risk += assessment["risk_score"]
        
        # Sort by priority
        assessments.sort(key=lambda x: (x["priority"], -x["risk_score"]))
        
        return {
            "assessments": assessments,
            "total_risk_score": round(total_risk, 2),
            "top_risks": assessments[:10]
        }
    
    def calculate_overall_risk(self, permissions_assessment: Dict[str, Any],
                              resources_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall risk score.
        
        Args:
            permissions_assessment: Permissions risk assessment
            resources_assessment: Resources risk assessment
            
        Returns:
            Overall risk assessment
        """
        perm_risk = permissions_assessment.get("total_risk_score", 0)
        resource_risk = resources_assessment.get("total_risk_score", 0)
        
        # Weighted combination (permissions are more critical)
        overall_score = (perm_risk * 0.6) + (resource_risk * 0.4)
        
        # Determine overall risk level
        if overall_score >= 150:
            risk_level = RiskLevel.CRITICAL
        elif overall_score >= 100:
            risk_level = RiskLevel.HIGH
        elif overall_score >= 50:
            risk_level = RiskLevel.MEDIUM
        elif overall_score >= 20:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO
        
        return {
            "overall_risk_score": round(overall_score, 2),
            "risk_level": risk_level.value,
            "permissions_risk": round(perm_risk, 2),
            "resources_risk": round(resource_risk, 2),
            "critical_findings": permissions_assessment.get("critical_count", 0) + 
                                sum(1 for a in resources_assessment.get("assessments", []) 
                                    if a.get("risk_level") == RiskLevel.CRITICAL.value),
            "high_findings": permissions_assessment.get("high_count", 0) + 
                            sum(1 for a in resources_assessment.get("assessments", []) 
                                if a.get("risk_level") == RiskLevel.HIGH.value)
        }
    
    def generate_recommendations(self, overall_risk: Dict[str, Any],
                                permissions_assessment: Dict[str, Any],
                                resources_assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate actionable recommendations based on risk assessment.
        
        Args:
            overall_risk: Overall risk assessment
            permissions_assessment: Permissions risk assessment
            resources_assessment: Resources risk assessment
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Critical recommendations
        if overall_risk["risk_level"] == RiskLevel.CRITICAL.value:
            recommendations.append({
                "priority": "CRITICAL",
                "title": "Immediate Action Required",
                "description": "The API key has critical-level permissions that pose significant security risks.",
                "actions": [
                    "Review and revoke unnecessary admin permissions",
                    "Implement principle of least privilege",
                    "Rotate the API key immediately if compromised",
                    "Enable audit logging for all admin actions"
                ]
            })
        
        # Permission-specific recommendations
        critical_perms = [a for a in permissions_assessment.get("assessments", []) 
                         if a.get("risk_level") == RiskLevel.CRITICAL.value and a.get("granted")]
        if critical_perms:
            recommendations.append({
                "priority": "HIGH",
                "title": "Revoke Critical Permissions",
                "description": f"Found {len(critical_perms)} critical permissions that should be reviewed.",
                "actions": [
                    f"Review permission: {perm['permission']}" for perm in critical_perms[:5]
                ]
            })
        
        # Resource-specific recommendations
        if resources_assessment.get("assessments"):
            high_risk_resources = [a for a in resources_assessment.get("assessments", [])
                                  if a.get("risk_level") in [RiskLevel.CRITICAL.value, RiskLevel.HIGH.value]]
            if high_risk_resources:
                recommendations.append({
                    "priority": "HIGH",
                    "title": "Review High-Risk Resources",
                    "description": f"Found {len(high_risk_resources)} high-risk resource types.",
                    "actions": [
                        f"Audit {r['resource_type']} access (count: {r.get('count', 0)})" 
                        for r in high_risk_resources[:5]
                    ]
                })
        
        # General recommendations
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Implement Security Best Practices",
            "description": "General security improvements for API key management.",
            "actions": [
                "Use fine-grained personal access tokens instead of classic tokens",
                "Set expiration dates for all tokens",
                "Regularly audit token usage and permissions",
                "Enable 2FA for all accounts with API access",
                "Monitor API key usage through audit logs"
            ]
        })
        
        return recommendations
    
    def _generate_reasoning(self, permission_name: str, risk_level: RiskLevel,
                           context: Optional[Dict[str, Any]]) -> str:
        """Generate human-readable reasoning for risk assessment."""
        reasons = []
        
        if "admin" in permission_name.lower():
            reasons.append("Administrative access grants full control")
        if "write" in permission_name.lower():
            reasons.append("Write access allows modification of resources")
        if "delete" in permission_name.lower():
            reasons.append("Delete access allows removal of resources")
        
        if context:
            if context.get("is_private_repo"):
                reasons.append("Access to private repositories")
            if context.get("has_secrets"):
                reasons.append("Access to secrets")
        
        if not reasons:
            reasons.append(f"{risk_level.value.upper()} risk level based on permission scope")
        
        return "; ".join(reasons)

