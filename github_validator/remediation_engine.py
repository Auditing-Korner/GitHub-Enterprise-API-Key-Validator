"""
Automated Remediation Suggestions Engine

Analyzes security findings and generates prioritized, actionable remediation steps
with step-by-step guides and implementation details.
"""

from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime


class RemediationPriority(Enum):
    """Remediation priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RemediationCategory(Enum):
    """Categories of remediation actions."""
    PERMISSIONS = "permissions"
    SECRETS = "secrets"
    ACCESS_CONTROL = "access_control"
    NETWORK_SECURITY = "network_security"
    COMPLIANCE = "compliance"
    MONITORING = "monitoring"
    BEST_PRACTICES = "best_practices"


class RemediationEngine:
    """Generates automated remediation suggestions based on security findings."""
    
    def __init__(self):
        self.remediation_templates = self._load_remediation_templates()
    
    def generate_remediations(
        self,
        permissions_data: Optional[Dict[str, Any]] = None,
        resources_data: Optional[Dict[str, Any]] = None,
        compliance_data: Optional[Dict[str, Any]] = None,
        drift_data: Optional[Dict[str, Any]] = None,
        runner_data: Optional[Dict[str, Any]] = None,
        risk_assessment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive remediation suggestions.
        
        Args:
            permissions_data: Permission validation results
            resources_data: Resources enumeration results
            compliance_data: Compliance checking results
            drift_data: Permission drift detection results
            runner_data: Runner telemetry data
            risk_assessment: Risk assessment results
            
        Returns:
            Dictionary with remediation suggestions organized by priority
        """
        remediations = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
            "summary": {
                "total": 0,
                "by_priority": {},
                "by_category": {},
                "estimated_effort": {}
            }
        }
        
        # Analyze permissions
        if permissions_data:
            remediations = self._analyze_permissions(permissions_data, remediations)
        
        # Analyze resources
        if resources_data:
            remediations = self._analyze_resources(resources_data, remediations)
        
        # Analyze compliance
        if compliance_data:
            remediations = self._analyze_compliance(compliance_data, remediations)
        
        # Analyze drift
        if drift_data:
            remediations = self._analyze_drift(drift_data, remediations)
        
        # Analyze runners
        if runner_data:
            remediations = self._analyze_runners(runner_data, remediations)
        
        # Analyze risk assessment
        if risk_assessment:
            remediations = self._analyze_risk_assessment(risk_assessment, remediations)
        
        # Calculate summary statistics
        remediations["summary"] = self._calculate_summary(remediations)
        
        return remediations
    
    def _analyze_permissions(self, permissions_data: Dict[str, Any], remediations: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze permissions and generate remediation suggestions."""
        critical_perms = permissions_data.get("critical_permissions", {})
        summary = permissions_data.get("summary", {})
        
        # Check for excessive admin permissions
        admin_perms = [p for p in critical_perms.values() if p.get("granted", False) and "admin" in p.get("name", "").lower()]
        if len(admin_perms) > 2:
            remediations["critical"].append({
                "id": "perm-001",
                "title": "Reduce Administrative Permissions",
                "description": f"Found {len(admin_perms)} administrative permissions. This violates the principle of least privilege.",
                "category": RemediationCategory.PERMISSIONS.value,
                "priority": RemediationPriority.CRITICAL.value,
                "effort": "medium",
                "impact": "high",
                "steps": [
                    "Review each administrative permission and determine if it's necessary",
                    "Replace admin permissions with read-only alternatives where possible",
                    "Use organization roles (member, billing manager) instead of admin:org",
                    "Implement role-based access control (RBAC) for fine-grained permissions",
                    "Document the business justification for each remaining admin permission"
                ],
                "commands": [
                    "# Review current permissions:",
                    "gh api user --jq '.permissions'",
                    "",
                    "# For organization admin, consider using:",
                    "# - read:org (for read-only access)",
                    "# - write:org (for limited write access)",
                    "# - billing (for billing management only)"
                ],
                "references": [
                    "https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles",
                    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
                ]
            })
        
        # Check for delete permissions
        delete_perms = [p for p in critical_perms.values() if p.get("granted", False) and "delete" in p.get("name", "").lower()]
        if delete_perms:
            remediations["critical"].append({
                "id": "perm-002",
                "title": "Remove Delete Permissions",
                "description": f"Found {len(delete_perms)} delete permissions. These allow permanent data destruction.",
                "category": RemediationCategory.PERMISSIONS.value,
                "priority": RemediationPriority.CRITICAL.value,
                "effort": "low",
                "impact": "high",
                "steps": [
                    "Identify all delete permissions currently granted",
                    "Verify if delete operations are actually required",
                    "Remove delete permissions from API tokens",
                    "Use GitHub's soft delete features where available",
                    "Implement approval workflows for destructive operations"
                ],
                "commands": [
                    "# Review tokens with delete permissions:",
                    "gh api user/installations --jq '.[] | select(.permissions.contents == \"write\" or .permissions.repository == \"write\")'",
                    "",
                    "# Remove delete permissions from token scopes"
                ],
                "references": [
                    "https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens"
                ]
            })
        
        # Check for secret access permissions
        secret_perms = [p for p in critical_perms.values() if p.get("granted", False) and "secret" in p.get("name", "").lower()]
        if secret_perms:
            remediations["high"].append({
                "id": "perm-003",
                "title": "Secure Secret Access",
                "description": f"Found {len(secret_perms)} secret-related permissions. Implement proper secret management.",
                "category": RemediationCategory.SECRETS.value,
                "priority": RemediationPriority.HIGH.value,
                "effort": "medium",
                "impact": "high",
                "steps": [
                    "Audit all accessible secrets and their usage",
                    "Rotate all secrets accessible by this token",
                    "Implement secret scanning and monitoring",
                    "Use GitHub Secrets Manager with proper access controls",
                    "Enable secret rotation policies",
                    "Monitor secret access in audit logs"
                ],
                "commands": [
                    "# List all organization secrets:",
                    "gh api orgs/{org}/actions/secrets",
                    "",
                    "# Rotate a secret:",
                    "# 1. Create new secret value",
                    "# 2. Update secret in GitHub",
                    "# 3. Update all references",
                    "# 4. Delete old secret after verification"
                ],
                "references": [
                    "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
                    "https://docs.github.com/en/code-security/secret-scanning"
                ]
            })
        
        # Check for excessive granted permissions
        granted_count = summary.get("granted", 0)
        total_count = summary.get("total_tested", 0)
        if total_count > 0:
            grant_ratio = granted_count / total_count
            if grant_ratio > 0.5:
                remediations["high"].append({
                    "id": "perm-004",
                    "title": "Implement Least Privilege Principle",
                    "description": f"{grant_ratio:.1%} of tested permissions are granted. This exceeds recommended thresholds.",
                    "category": RemediationCategory.PERMISSIONS.value,
                    "priority": RemediationPriority.HIGH.value,
                    "effort": "high",
                    "impact": "high",
                    "steps": [
                        "Conduct a comprehensive permission audit",
                        "Identify the minimum set of permissions required",
                        "Create separate tokens for different use cases",
                        "Use fine-grained personal access tokens (PATs)",
                        "Implement permission review process",
                        "Document permission requirements and justifications"
                    ],
                    "commands": [
                        "# Use fine-grained PATs with minimal scopes:",
                        "gh auth token --scopes 'repo:read,read:org'",
                        "",
                        "# Review token permissions:",
                        "gh api user --jq '.permissions'"
                    ],
                    "references": [
                        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#fine-grained-personal-access-tokens"
                    ]
                })
        
        return remediations
    
    def _analyze_resources(self, resources_data: Dict[str, Any], remediations: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze resources and generate remediation suggestions."""
        # Check for exposed secrets
        if "secrets" in resources_data:
            secrets = resources_data.get("secrets", [])
            if isinstance(secrets, list) and len(secrets) > 0:
                remediations["critical"].append({
                    "id": "res-001",
                    "title": "Rotate Exposed Organization Secrets",
                    "description": f"Found {len(secrets)} organization secrets accessible by this token. Immediate rotation required.",
                    "category": RemediationCategory.SECRETS.value,
                    "priority": RemediationPriority.CRITICAL.value,
                    "effort": "high",
                    "impact": "critical",
                    "steps": [
                        "Immediately rotate all accessible secrets",
                        "Update all applications and services using these secrets",
                        "Verify no unauthorized access occurred",
                        "Implement secret rotation schedule (every 90 days)",
                        "Enable secret scanning alerts",
                        "Review secret access logs for suspicious activity"
                    ],
                    "commands": [
                        "# List all secrets:",
                        "gh api orgs/{org}/actions/secrets",
                        "",
                        "# For each secret:",
                        "# 1. Generate new secret value",
                        "# 2. Update secret: gh api -X PUT orgs/{org}/actions/secrets/{secret_name}",
                        "# 3. Update all references in workflows and applications",
                        "# 4. Monitor for failures",
                        "# 5. Delete old secret after 7-day grace period"
                    ],
                    "references": [
                        "https://docs.github.com/en/actions/security-guides/encrypted-secrets#rotating-your-secrets"
                    ]
                })
        
        # Check for webhooks
        if "webhooks" in resources_data:
            webhooks = resources_data.get("webhooks", {})
            total_webhooks = webhooks.get("total", 0) if isinstance(webhooks, dict) else len(webhooks) if isinstance(webhooks, list) else 0
            if total_webhooks > 10:
                remediations["medium"].append({
                    "id": "res-002",
                    "title": "Review and Secure Webhooks",
                    "description": f"Found {total_webhooks} webhooks. Review for security and proper configuration.",
                    "category": RemediationCategory.NETWORK_SECURITY.value,
                    "priority": RemediationPriority.MEDIUM.value,
                    "effort": "medium",
                    "impact": "medium",
                    "steps": [
                        "Audit all webhook endpoints and configurations",
                        "Verify webhook URLs use HTTPS",
                        "Implement webhook secret validation",
                        "Review webhook event subscriptions (subscribe only to needed events)",
                        "Monitor webhook delivery failures",
                        "Implement webhook rate limiting",
                        "Document webhook purposes and owners"
                    ],
                    "commands": [
                        "# List all webhooks:",
                        "gh api orgs/{org}/hooks",
                        "",
                        "# Review webhook configuration:",
                        "gh api orgs/{org}/hooks/{hook_id}",
                        "",
                        "# Update webhook secret:",
                        "gh api -X PATCH orgs/{org}/hooks/{hook_id} -f secret='new-secret'"
                    ],
                    "references": [
                        "https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks"
                    ]
                })
        
        # Check for repositories
        if "repositories" in resources_data:
            repos = resources_data.get("repositories", {})
            total_repos = repos.get("total", 0) if isinstance(repos, dict) else len(repos) if isinstance(repos, list) else 0
            if total_repos > 50:
                remediations["medium"].append({
                    "id": "res-003",
                    "title": "Review Repository Access",
                    "description": f"Access to {total_repos} repositories detected. Review access scope and necessity.",
                    "category": RemediationCategory.ACCESS_CONTROL.value,
                    "priority": RemediationPriority.MEDIUM.value,
                    "effort": "high",
                    "impact": "medium",
                    "steps": [
                        "Audit repository access requirements",
                        "Implement repository-level access controls",
                        "Use repository visibility settings appropriately",
                        "Review and remove unnecessary repository access",
                        "Implement repository access review process",
                        "Document repository access justifications"
                    ],
                    "commands": [
                        "# List accessible repositories:",
                        "gh api user/repos --jq '.[].full_name'",
                        "",
                        "# Review repository permissions:",
                        "gh api repos/{owner}/{repo} --jq '.permissions'"
                    ],
                    "references": [
                        "https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings"
                    ]
                })
        
        return remediations
    
    def _analyze_compliance(self, compliance_data: Dict[str, Any], remediations: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance findings and generate remediation suggestions."""
        frameworks = compliance_data.get("frameworks", {})
        overall_compliant = compliance_data.get("overall_compliant", False)
        
        if not overall_compliant:
            non_compliant_frameworks = [
                name for name, data in frameworks.items()
                if not data.get("compliant", False)
            ]
            
            remediations["high"].append({
                "id": "comp-001",
                "title": "Address Compliance Violations",
                "description": f"Non-compliant with {len(non_compliant_frameworks)} framework(s): {', '.join(non_compliant_frameworks)}",
                "category": RemediationCategory.COMPLIANCE.value,
                "priority": RemediationPriority.HIGH.value,
                "effort": "high",
                "impact": "high",
                "steps": [
                    "Review compliance findings for each framework",
                    "Prioritize critical and high-severity findings",
                    "Develop remediation plan with timelines",
                    "Implement required security controls",
                    "Document compliance evidence",
                    "Schedule follow-up compliance review"
                ],
                "commands": [
                    "# Review compliance findings in the generated report",
                    "# Address each finding systematically",
                    "# Document remediation actions taken"
                ],
                "references": [
                    "https://docs.github.com/en/enterprise-cloud@latest/admin/policies/enforcing-policies-for-your-enterprise"
                ]
            })
        
        # Check for specific compliance issues
        for framework_name, framework_data in frameworks.items():
            findings = framework_data.get("findings", [])
            non_compliant = [f for f in findings if f.get("status") == "non_compliant"]
            
            if non_compliant:
                for finding in non_compliant[:3]:  # Limit to first 3 per framework
                    remediations["high"].append({
                        "id": f"comp-{framework_name}-{finding.get('requirement', 'unknown')}",
                        "title": f"Fix {framework_name} Compliance: {finding.get('requirement', 'Unknown')}",
                        "description": finding.get("description", ""),
                        "category": RemediationCategory.COMPLIANCE.value,
                        "priority": RemediationPriority.HIGH.value,
                        "effort": "medium",
                        "impact": "high",
                        "steps": [
                            f"Review {finding.get('requirement', 'requirement')} requirements",
                            "Implement required controls",
                            "Document implementation",
                            "Verify compliance"
                        ],
                        "commands": [],
                        "references": []
                    })
        
        return remediations
    
    def _analyze_drift(self, drift_data: Dict[str, Any], remediations: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze permission drift and generate remediation suggestions."""
        if drift_data.get("has_changes", False):
            changes = drift_data.get("changes", [])
            critical_changes = drift_data.get("critical_changes", [])
            
            if critical_changes:
                remediations["critical"].append({
                    "id": "drift-001",
                    "title": "Investigate Critical Permission Changes",
                    "description": f"Detected {len(critical_changes)} critical permission changes. Immediate investigation required.",
                    "category": RemediationCategory.PERMISSIONS.value,
                    "priority": RemediationPriority.CRITICAL.value,
                    "effort": "low",
                    "impact": "high",
                    "steps": [
                        "Review all critical permission changes",
                        "Verify if changes were authorized",
                        "Check audit logs for change source",
                        "Revert unauthorized changes immediately",
                        "Document authorized changes",
                        "Implement change approval process"
                    ],
                    "commands": [
                        "# Review permission history:",
                        "# Check .permission_history/ directory for snapshots",
                        "",
                        "# Review audit logs:",
                        "gh api orgs/{org}/audit-log --jq '.entries[] | select(.action == \"org.update_member\")'"
                    ],
                    "references": [
                        "https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise"
                    ]
                })
            
            if len(changes) > 5:
                remediations["high"].append({
                    "id": "drift-002",
                    "title": "Address Permission Drift",
                    "description": f"Detected {len(changes)} permission changes. Review and implement change controls.",
                    "category": RemediationCategory.PERMISSIONS.value,
                    "priority": RemediationPriority.HIGH.value,
                    "effort": "medium",
                    "impact": "medium",
                    "steps": [
                        "Review all permission changes",
                        "Implement permission change approval workflow",
                        "Set up automated drift detection alerts",
                        "Document change management process",
                        "Regular permission audits (monthly)"
                    ],
                    "commands": [
                        "# Run drift detection regularly:",
                        "python main.py --api-key $TOKEN --company $ORG --detect-drift --generate-report drift_report.html"
                    ],
                    "references": []
                })
        
        return remediations
    
    def _analyze_runners(self, runner_data: Dict[str, Any], remediations: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze runner data and generate remediation suggestions."""
        network_info = runner_data.get("network_info", {})
        exposure_summary = network_info.get("network_exposure_summary", {})
        
        online_exposed = exposure_summary.get("online_exposed_runners", 0)
        if online_exposed > 0:
            remediations["high"].append({
                "id": "runner-001",
                "title": "Secure Exposed CI/CD Runners",
                "description": f"Found {online_exposed} online runners with exposed network information. Secure immediately.",
                "category": RemediationCategory.NETWORK_SECURITY.value,
                "priority": RemediationPriority.HIGH.value,
                "effort": "high",
                "impact": "high",
                "steps": [
                    "Review runner network exposure",
                    "Implement network isolation for runners",
                    "Restrict SSH access to runners",
                    "Use GitHub-hosted runners for public repositories",
                    "Implement runner group access controls",
                    "Enable runner monitoring and alerting",
                    "Review and rotate runner credentials"
                ],
                "commands": [
                    "# List runners:",
                    "gh api orgs/{org}/actions/runners",
                    "",
                    "# Configure runner groups with restricted access:",
                    "gh api orgs/{org}/actions/runner-groups",
                    "",
                    "# Review runner labels and access:",
                    "gh api orgs/{org}/actions/runners/{runner_id}"
                ],
                "references": [
                    "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners",
                    "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"
                ]
            })
        
        return remediations
    
    def _analyze_risk_assessment(self, risk_assessment: Dict[str, Any], remediations: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze risk assessment and generate remediation suggestions."""
        overall_risk = risk_assessment.get("overall_risk", {})
        risk_level = overall_risk.get("risk_level", "unknown")
        
        if risk_level in ["critical", "high"]:
            remediations["critical"].append({
                "id": "risk-001",
                "title": "Address High-Risk Findings",
                "description": f"Overall risk level is {risk_level.upper()}. Immediate action required.",
                "category": RemediationCategory.BEST_PRACTICES.value,
                "priority": RemediationPriority.CRITICAL.value,
                "effort": "high",
                "impact": "critical",
                "steps": [
                    "Review all critical and high-risk findings",
                    "Prioritize remediation based on risk scores",
                    "Implement immediate fixes for critical issues",
                    "Develop remediation timeline",
                    "Assign ownership for each remediation",
                    "Track remediation progress",
                    "Schedule follow-up risk assessment"
                ],
                "commands": [
                    "# Review risk assessment in generated report",
                    "# Address findings in priority order",
                    "# Re-run assessment after remediation"
                ],
                "references": []
            })
        
        return remediations
    
    def _calculate_summary(self, remediations: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate summary statistics for remediations."""
        summary = {
            "total": 0,
            "by_priority": {},
            "by_category": {},
            "estimated_effort": {
                "low": 0,
                "medium": 0,
                "high": 0
            }
        }
        
        for priority in ["critical", "high", "medium", "low", "info"]:
            items = remediations.get(priority, [])
            count = len(items)
            summary["total"] += count
            summary["by_priority"][priority] = count
            
            # Count by category
            for item in items:
                category = item.get("category", "unknown")
                summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
                
                # Count by effort
                effort = item.get("effort", "medium")
                if effort in summary["estimated_effort"]:
                    summary["estimated_effort"][effort] += 1
        
        return summary
    
    def _load_remediation_templates(self) -> Dict[str, Any]:
        """Load remediation templates (can be extended with external templates)."""
        return {
            "permission_reduction": {
                "title": "Reduce Permissions",
                "steps": []
            }
        }

