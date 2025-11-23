"""
Enterprise Runner Inspection Module

Provides utilities to collect and summarize GitHub Enterprise self-hosted
runners by talking to the enterprise-level Actions endpoints.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional

from .api_client import GitHubAPIClient


class EnterpriseRunnerInspector:
    """Fetches and summarizes enterprise-level self-hosted runners."""

    LABELS_OF_INTEREST = ["appsec", "appsec-dind"]

    def __init__(self, api_client: GitHubAPIClient, enterprise_slug: str):
        if not enterprise_slug:
            raise ValueError("enterprise_slug is required to inspect runners")
        self.api_client = api_client
        self.enterprise_slug = enterprise_slug

    def fetch_runners(self, max_pages: Optional[int] = None) -> Dict[str, Any]:
        """
        Fetch all enterprise runners and return detailed telemetry.

        Args:
            max_pages: Optional limit to stop after N pages (for lightweight probes).

        Returns:
            Dictionary containing per-runner details and aggregated metrics.
        """
        per_page = 100
        page = 1
        all_runners: List[Dict[str, Any]] = []

        while True:
            response = self.api_client.get(
                f"/enterprises/{self.enterprise_slug}/actions/runners",
                params={"per_page": per_page, "page": page},
            )
            if not response:
                break

            runners = response.get("runners", [])
            all_runners.extend(runners)

            if len(runners) < per_page:
                break

            page += 1
            if max_pages is not None and page > max_pages:
                break

        return self._summarize(all_runners)

    def _summarize(self, runners: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build derived insights for runner metadata."""
        status_counts: Dict[str, int] = {}
        label_counts: Dict[str, int] = {}
        label_online_counts: Dict[str, int] = {}

        summarized_runners: List[Dict[str, Any]] = []
        for runner in runners:
            status = (runner.get("status") or "").lower()
            status_counts[status] = status_counts.get(status, 0) + 1
            is_online = status == "online"

            labels = [
                label.get("name", "")
                for label in runner.get("labels", [])
                if label.get("name")
            ]
            for label_name in labels:
                label_counts[label_name] = label_counts.get(label_name, 0) + 1
                if is_online:
                    label_online_counts[label_name] = (
                        label_online_counts.get(label_name, 0) + 1
                    )

            summarized_runners.append(
                {
                    "id": runner.get("id"),
                    "name": runner.get("name"),
                    "os": runner.get("os"),
                    "status": runner.get("status"),
                    "busy": runner.get("busy"),
                    "labels": labels,
                    "runner_group_id": runner.get("runner_group_id"),
                    "runner_group_name": runner.get("runner_group_name"),
                    "architecture": runner.get("architecture"),
                    "created_at": runner.get("created_at"),
                    "updated_at": runner.get("updated_at"),
                }
            )

        total = len(runners)
        online = status_counts.get("online", 0)
        offline = total - online

        labels_of_interest = {
            label: {
                "online": label_online_counts.get(label, 0),
                "total": label_counts.get(label, 0),
            }
            for label in self.LABELS_OF_INTEREST
            if label in label_counts
        }

        network_info = self.extract_network_info(summarized_runners)
        
        return {
            "enterprise": self.enterprise_slug,
            "total_runners": total,
            "online_runners": online,
            "offline_runners": offline,
            "status_counts": status_counts,
            "label_counts": label_counts,
            "label_online_counts": label_online_counts,
            "labels_of_interest": labels_of_interest,
            "network_info": network_info,
            "runners": summarized_runners,
        }
    
    def extract_network_info(self, runners: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract comprehensive network information from runners.
        
        Args:
            runners: List of runner dictionaries
            
        Returns:
            Dictionary with OS distribution, architecture, runner groups, IPs, hostnames, etc.
        """
        import re
        import socket
        from collections import Counter, defaultdict
        from datetime import datetime
        from ipaddress import ip_address, AddressValueError
        
        os_distribution = Counter()
        arch_distribution = Counter()
        runner_groups = Counter()
        ip_addresses = []
        hostnames = []
        network_exposure = []
        runner_ages = []
        label_statistics = Counter()
        online_runners_with_network_info = []
        
        # Enhanced IP validation pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        # Hostname pattern (RFC 1123 compliant)
        hostname_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)'
        
        for runner in runners:
            # OS distribution
            os_name = runner.get("os", "unknown")
            os_distribution[os_name] += 1
            
            # Architecture distribution
            arch = runner.get("architecture", "unknown")
            arch_distribution[arch] += 1
            
            # Runner groups
            group = runner.get("runner_group_name") or "default"
            runner_groups[group] += 1
            
            # Enhanced network information extraction
            runner_name = runner.get("name", "")
            runner_id = runner.get("id")
            runner_status = runner.get("status", "").lower()
            is_online = runner_status == "online"
            
            # Extract and validate IP addresses
            ip_matches = re.findall(ip_pattern, runner_name)
            for ip_str in ip_matches:
                try:
                    # Validate IP address
                    ip_obj = ip_address(ip_str)
                    if ip_str not in ip_addresses:
                        ip_addresses.append(ip_str)
                    
                    # Store network exposure info
                    network_exposure.append({
                        "runner_id": runner_id,
                        "runner_name": runner_name,
                        "type": "ip_address",
                        "value": ip_str,
                        "status": runner_status,
                        "is_online": is_online,
                        "is_private": ip_obj.is_private,
                        "is_loopback": ip_obj.is_loopback,
                        "is_link_local": ip_obj.is_link_local
                    })
                except (AddressValueError, ValueError):
                    pass  # Invalid IP, skip
            
            # Extract hostnames
            # Try user@hostname format first
            if '@' in runner_name:
                parts = runner_name.split('@')
                if len(parts) > 1:
                    potential_hostname = parts[1].split()[0].split(':')[0]  # Remove port if present
                    hostname_match = re.match(hostname_pattern, potential_hostname)
                    if hostname_match and len(potential_hostname) <= 253:
                        if potential_hostname not in hostnames:
                            hostnames.append(potential_hostname)
                        network_exposure.append({
                            "runner_id": runner_id,
                            "runner_name": runner_name,
                            "type": "hostname",
                            "value": potential_hostname,
                            "status": runner_status,
                            "is_online": is_online,
                            "format": "user@hostname"
                        })
            
            # Try to extract standalone hostnames
            # Remove common prefixes/suffixes
            cleaned_name = re.sub(r'^(runner-|gh-|github-|actions-|ci-|build-)', '', runner_name, flags=re.IGNORECASE)
            cleaned_name = re.sub(r'(-runner|-gh|-github|-actions|-ci|-build)$', '', cleaned_name, flags=re.IGNORECASE)
            
            # Extract hostname-like patterns
            hostname_matches = re.findall(hostname_pattern, cleaned_name)
            for match in hostname_matches:
                if isinstance(match, tuple):
                    potential_hostname = match[0] if match[0] else (match[1] if match[1] else "")
                else:
                    potential_hostname = match
                
                # Validate hostname length and format
                if potential_hostname and len(potential_hostname) <= 253 and len(potential_hostname) > 0:
                    # Skip if it's just numbers (likely not a hostname)
                    if not potential_hostname.replace('.', '').replace('-', '').isdigit():
                        if potential_hostname not in hostnames:
                            hostnames.append(potential_hostname)
                        if not any(exp.get("value") == potential_hostname for exp in network_exposure):
                            network_exposure.append({
                                "runner_id": runner_id,
                                "runner_name": runner_name,
                                "type": "hostname",
                                "value": potential_hostname,
                                "status": runner_status,
                                "is_online": is_online,
                                "format": "standalone"
                            })
            
            # Store online runners with network info for execution capability assessment
            if is_online and (ip_matches or hostnames):
                online_runners_with_network_info.append({
                    "runner_id": runner_id,
                    "runner_name": runner_name,
                    "ip_addresses": ip_matches,
                    "hostnames": [h for h in hostnames if h in runner_name],
                    "os": os_name,
                    "architecture": arch,
                    "runner_group": group
                })
            
            # Runner age (from created_at)
            created_at = runner.get("created_at")
            if created_at:
                try:
                    created = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    age_days = (datetime.now(created.tzinfo) - created).days
                    runner_ages.append(age_days)
                except Exception:
                    pass
            
            # Label statistics
            labels = runner.get("labels", [])
            for label in labels:
                label_name = label if isinstance(label, str) else label.get("name", "")
                if label_name:
                    label_statistics[label_name] += 1
        
        # Calculate age statistics
        age_stats = {}
        if runner_ages:
            age_stats = {
                "min": min(runner_ages),
                "max": max(runner_ages),
                "avg": sum(runner_ages) / len(runner_ages) if runner_ages else 0
            }
        
        # Analyze network exposure risk
        private_ips = [exp for exp in network_exposure if exp.get("type") == "ip_address" and exp.get("is_private")]
        public_ips = [exp for exp in network_exposure if exp.get("type") == "ip_address" and not exp.get("is_private") and not exp.get("is_loopback")]
        online_with_exposure = [exp for exp in network_exposure if exp.get("is_online")]
        
        return {
            "os_distribution": dict(os_distribution),
            "architecture_distribution": dict(arch_distribution),
            "runner_groups": dict(runner_groups),
            "unique_ip_addresses": sorted(list(set(ip_addresses))),
            "unique_hostnames": sorted(list(set(hostnames))),
            "ip_count": len(set(ip_addresses)),
            "hostname_count": len(set(hostnames)),
            "network_exposure": network_exposure,
            "network_exposure_summary": {
                "total_exposed_runners": len(set(exp.get("runner_id") for exp in network_exposure)),
                "online_exposed_runners": len(set(exp.get("runner_id") for exp in online_with_exposure)),
                "private_ip_count": len(set(exp.get("value") for exp in private_ips)),
                "public_ip_count": len(set(exp.get("value") for exp in public_ips)),
                "hostname_count": len(set(exp.get("value") for exp in network_exposure if exp.get("type") == "hostname"))
            },
            "online_runners_with_network_info": online_runners_with_network_info,
            "execution_capability": {
                "online_runners_count": len(online_runners_with_network_info),
                "runners_with_network_info": len(online_runners_with_network_info),
                "potential_ssh_targets": len(online_runners_with_network_info)
            },
            "runner_age_statistics": age_stats,
            "label_statistics": dict(label_statistics)
        }


