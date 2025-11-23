"""
Compliance Checking Module

Checks GitHub API key permissions and configurations against
various compliance frameworks (SOC2, ISO27001, NIST, etc.)
"""

from typing import Dict, List, Any, Optional
from enum import Enum
from datetime import datetime


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    NIST_CSF = "NIST_CSF"
    CIS_BENCHMARKS = "CIS_BENCHMARKS"
    PCI_DSS = "PCI_DSS"
    GDPR = "GDPR"


class ComplianceChecker:
    """Checks compliance against various frameworks."""
    
    def __init__(self):
        self.frameworks = {
            ComplianceFramework.SOC2: self._check_soc2,
            ComplianceFramework.ISO27001: self._check_iso27001,
            ComplianceFramework.NIST_CSF: self._check_nist_csf,
            ComplianceFramework.CIS_BENCHMARKS: self._check_cis,
            ComplianceFramework.PCI_DSS: self._check_pci_dss,
            ComplianceFramework.GDPR: self._check_gdpr
        }
    
    def check_compliance(
        self,
        permissions_data: Dict[str, Any],
        resources_data: Dict[str, Any],
        frameworks: Optional[List[ComplianceFramework]] = None
    ) -> Dict[str, Any]:
        """
        Check compliance against specified frameworks.
        
        Args:
            permissions_data: Permissions validation data
            resources_data: Resources enumeration data
            frameworks: List of frameworks to check (default: all)
            
        Returns:
            Compliance check results
        """
        if frameworks is None:
            frameworks = list(ComplianceFramework)
        
        results = {}
        overall_compliance = True
        
        for framework in frameworks:
            checker = self.frameworks.get(framework)
            if checker:
                result = checker(permissions_data, resources_data)
                results[framework.value] = result
                if not result.get("compliant", False):
                    overall_compliance = False
        
        return {
            "overall_compliant": overall_compliance,
            "frameworks": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _check_soc2(self, permissions_data: Dict[str, Any], resources_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check SOC2 compliance requirements."""
        findings = []
        compliant = True
        
        # CC6.1 - Logical and physical access controls
        critical_perms = permissions_data.get("critical_permissions", {})
        admin_perms_granted = sum(1 for p in critical_perms.values() if p.get("granted", False) and "admin" in p.get("name", "").lower())
        
        if admin_perms_granted > 3:
            findings.append({
                "requirement": "CC6.1",
                "status": "non_compliant",
                "severity": "high",
                "description": f"Too many administrative permissions granted ({admin_perms_granted}). Principle of least privilege violated."
            })
            compliant = False
        else:
            findings.append({
                "requirement": "CC6.1",
                "status": "compliant",
                "description": "Administrative permissions are appropriately limited."
            })
        
        # CC6.2 - Access credentials and authentication
        if "secrets" in resources_data:
            secrets = resources_data.get("secrets", [])
            if isinstance(secrets, list) and len(secrets) > 0:
                findings.append({
                    "requirement": "CC6.2",
                    "status": "warning",
                    "severity": "medium",
                    "description": f"Found {len(secrets)} secrets. Ensure proper credential management and rotation."
                })
        
        # CC7.1 - System operations
        if "runners" in resources_data:
            runners = resources_data.get("runners", {})
            if isinstance(runners, dict):
                total_runners = runners.get("total_runners", 0)
                if total_runners > 0:
                    findings.append({
                        "requirement": "CC7.1",
                        "status": "compliant",
                        "description": f"CI/CD infrastructure detected ({total_runners} runners). Ensure proper monitoring."
                    })
        
        return {
            "framework": "SOC2",
            "compliant": compliant,
            "findings": findings,
            "compliance_score": self._calculate_score(findings)
        }
    
    def _check_iso27001(self, permissions_data: Dict[str, Any], resources_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check ISO27001 compliance requirements."""
        findings = []
        compliant = True
        
        # A.9.2 - User access management
        critical_perms = permissions_data.get("critical_permissions", {})
        delete_perms = [p for p in critical_perms.values() if p.get("granted", False) and "delete" in p.get("name", "").lower()]
        
        if delete_perms:
            findings.append({
                "requirement": "A.9.2.3",
                "status": "non_compliant",
                "severity": "high",
                "description": f"Delete permissions granted. Review necessity and implement additional controls."
            })
            compliant = False
        
        # A.9.4 - Access control to program and information
        if "webhooks" in resources_data:
            webhooks = resources_data.get("webhooks", {})
            total_webhooks = webhooks.get("total", 0) if isinstance(webhooks, dict) else len(webhooks) if isinstance(webhooks, list) else 0
            if total_webhooks > 10:
                findings.append({
                    "requirement": "A.9.4.2",
                    "status": "warning",
                    "severity": "medium",
                    "description": f"High number of webhooks ({total_webhooks}). Ensure proper access controls and monitoring."
                })
        
        return {
            "framework": "ISO27001",
            "compliant": compliant,
            "findings": findings,
            "compliance_score": self._calculate_score(findings)
        }
    
    def _check_nist_csf(self, permissions_data: Dict[str, Any], resources_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check NIST Cybersecurity Framework compliance."""
        findings = []
        compliant = True
        
        # PR.AC - Identity Management and Access Control
        summary = permissions_data.get("summary", {})
        granted = summary.get("granted", 0)
        total = summary.get("total_tested", 0)
        
        if total > 0:
            grant_ratio = granted / total
            if grant_ratio > 0.5:
                findings.append({
                    "requirement": "PR.AC-1",
                    "status": "non_compliant",
                    "severity": "medium",
                    "description": f"High permission grant ratio ({grant_ratio:.1%}). Implement least privilege principle."
                })
                compliant = False
        
        return {
            "framework": "NIST_CSF",
            "compliant": compliant,
            "findings": findings,
            "compliance_score": self._calculate_score(findings)
        }
    
    def _check_cis(self, permissions_data: Dict[str, Any], resources_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check CIS Benchmarks compliance."""
        findings = []
        compliant = True
        
        # CIS Benchmark 1.1 - Ensure MFA is enabled
        findings.append({
            "requirement": "CIS 1.1",
            "status": "info",
            "description": "Verify MFA is enabled for all accounts with API access."
        })
        
        # CIS Benchmark 2.1 - Limit administrative access
        critical_perms = permissions_data.get("critical_permissions", {})
        admin_count = sum(1 for p in critical_perms.values() if p.get("granted", False) and "admin" in p.get("name", "").lower())
        
        if admin_count > 2:
            findings.append({
                "requirement": "CIS 2.1",
                "status": "non_compliant",
                "severity": "high",
                "description": f"Multiple administrative permissions granted ({admin_count}). Limit to minimum necessary."
            })
            compliant = False
        
        return {
            "framework": "CIS_BENCHMARKS",
            "compliant": compliant,
            "findings": findings,
            "compliance_score": self._calculate_score(findings)
        }
    
    def _check_pci_dss(self, permissions_data: Dict[str, Any], resources_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check PCI DSS compliance."""
        findings = []
        compliant = True
        
        # Requirement 7 - Restrict access to cardholder data
        if "secrets" in resources_data:
            secrets = resources_data.get("secrets", [])
            if isinstance(secrets, list) and len(secrets) > 0:
                findings.append({
                    "requirement": "PCI DSS 7",
                    "status": "warning",
                    "severity": "high",
                    "description": f"Secrets detected. Ensure proper access controls and encryption for cardholder data."
                })
        
        return {
            "framework": "PCI_DSS",
            "compliant": compliant,
            "findings": findings,
            "compliance_score": self._calculate_score(findings)
        }
    
    def _check_gdpr(self, permissions_data: Dict[str, Any], resources_data: Dict[str, Any]) -> Dict[str, Any]:
        """Check GDPR compliance."""
        findings = []
        compliant = True
        
        # Article 32 - Security of processing
        if "repositories" in resources_data:
            repos = resources_data.get("repositories", {})
            total_repos = repos.get("total", 0) if isinstance(repos, dict) else len(repos) if isinstance(repos, list) else 0
            if total_repos > 0:
                findings.append({
                    "requirement": "GDPR Art. 32",
                    "status": "info",
                    "description": f"Access to {total_repos} repositories. Ensure proper data protection measures."
                })
        
        return {
            "framework": "GDPR",
            "compliant": compliant,
            "findings": findings,
            "compliance_score": self._calculate_score(findings)
        }
    
    def _calculate_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate compliance score (0-100)."""
        if not findings:
            return 100.0
        
        total = len(findings)
        compliant = sum(1 for f in findings if f.get("status") == "compliant")
        non_compliant = sum(1 for f in findings if f.get("status") == "non_compliant")
        
        # Weight: compliant = 1, warning = 0.5, non_compliant = 0
        score = (compliant * 1.0 + (total - compliant - non_compliant) * 0.5) / total * 100
        return round(score, 2)

