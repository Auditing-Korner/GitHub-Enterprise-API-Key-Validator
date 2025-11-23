"""
Runner Operations Module

Provides functionality to execute commands on runners, manage SSH keys,
and perform various runner-related operations.
"""

from typing import Dict, List, Optional, Any
import subprocess
import os
import re
from pathlib import Path
from .api_client import GitHubAPIClient


class RunnerOperations:
    """Operations for managing and interacting with runners."""
    
    def __init__(self, api_client: GitHubAPIClient):
        self.api_client = api_client
    
    def list_ssh_keys(self) -> List[Dict[str, Any]]:
        """
        List SSH public keys from GitHub account.
        
        Returns:
            List of SSH key dictionaries with id, key, title, etc.
        """
        return self.api_client.get_paginated("/user/keys")
    
    def find_matching_private_key(self, public_key_fingerprint: str) -> Optional[str]:
        """
        Find local private key matching a GitHub public key fingerprint.
        
        Args:
            public_key_fingerprint: Fingerprint of the public key from GitHub
            
        Returns:
            Path to matching private key, or None if not found
        """
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return None
        
        # Common private key filenames
        key_patterns = [
            "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
            "id_rsa_*", "id_ed25519_*", "id_ecdsa_*"
        ]
        
        for pattern in key_patterns:
            for key_file in ssh_dir.glob(pattern):
                if key_file.is_file() and not key_file.name.endswith(".pub"):
                    try:
                        # Try to get fingerprint of private key
                        result = subprocess.run(
                            ["ssh-keygen", "-lf", str(key_file)],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if result.returncode == 0:
                            local_fp = result.stdout.split()[1] if len(result.stdout.split()) > 1 else None
                            if local_fp and local_fp == public_key_fingerprint:
                                return str(key_file)
                    except (subprocess.TimeoutExpired, FileNotFoundError, IndexError):
                        continue
        
        return None
    
    def auto_detect_ssh_key(self) -> Optional[str]:
        """
        Auto-detect local SSH private key matching a GitHub public key.
        
        Returns:
            Path to matching private key, or None if not found
        """
        try:
            ssh_keys = self.list_ssh_keys()
            if not ssh_keys:
                return None
            
            # Try to match with first available key
            for key_data in ssh_keys:
                key_str = key_data.get("key", "")
                if not key_str:
                    continue
                
                # Extract fingerprint from public key
                try:
                    result = subprocess.run(
                        ["ssh-keygen", "-lf", "-"],
                        input=key_str,
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        fingerprint = result.stdout.split()[1] if len(result.stdout.split()) > 1 else None
                        if fingerprint:
                            matched = self.find_matching_private_key(fingerprint)
                            if matched:
                                return matched
                except (subprocess.TimeoutExpired, FileNotFoundError, IndexError):
                    continue
            
            # Fallback to default key
            default_key = Path.home() / ".ssh" / "id_rsa"
            if default_key.exists():
                return str(default_key)
            
            return None
        except Exception:
            return None
    
    def extract_hostname(self, runner_name: str) -> str:
        """
        Extract hostname or IP address from runner name with enhanced detection.
        
        Args:
            runner_name: Name of the runner
            
        Returns:
            Extracted hostname or IP address
        """
        from ipaddress import ip_address, AddressValueError
        
        # Enhanced IP pattern with validation
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ip_match = re.search(ip_pattern, runner_name)
        if ip_match:
            ip_str = ip_match.group(0)
            try:
                # Validate IP address
                ip_address(ip_str)
                return ip_str
            except (AddressValueError, ValueError):
                pass  # Invalid IP, continue to hostname extraction
        
        # Try to extract hostname (format: hostname or user@hostname)
        if '@' in runner_name:
            parts = runner_name.split('@')
            if len(parts) > 1:
                potential_hostname = parts[1].split()[0].split(':')[0]  # Remove port if present
                # Validate hostname format (RFC 1123)
                if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', potential_hostname):
                    if len(potential_hostname) <= 253:
                        return potential_hostname
        
        # Try common hostname patterns (remove common prefixes/suffixes)
        cleaned_name = re.sub(r'^(runner-|gh-|github-|actions-|ci-|build-)', '', runner_name, flags=re.IGNORECASE)
        cleaned_name = re.sub(r'(-runner|-gh|-github|-actions|-ci|-build)$', '', cleaned_name, flags=re.IGNORECASE)
        
        # Enhanced hostname pattern (RFC 1123 compliant)
        hostname_pattern = r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*)'
        hostname_match = re.search(hostname_pattern, cleaned_name)
        if hostname_match:
            potential_hostname = hostname_match.group(1) if hostname_match.group(1) else hostname_match.group(0)
            # Skip if it's just numbers
            if not potential_hostname.replace('.', '').replace('-', '').isdigit():
                if len(potential_hostname) <= 253:
                    return potential_hostname
        
        # Fallback to runner name
        return runner_name.split()[0] if runner_name else "unknown"
    
    def assess_execution_capability(self, runners: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Assess execution capability on runners.
        
        Args:
            runners: List of runner dictionaries
            
        Returns:
            Dictionary with execution capability assessment
        """
        online_runners = [r for r in runners if r.get("status", "").lower() == "online"]
        
        if not online_runners:
            return {
                "has_execution_capability": False,
                "online_runners_count": 0,
                "runners_with_network_info": 0,
                "ssh_keys_available": False,
                "execution_risk": "none"
            }
        
        # Check for network information (IPs/hostnames)
        runners_with_network_info = []
        for runner in online_runners:
            runner_name = runner.get("name", "")
            hostname = self.extract_hostname(runner_name)
            if hostname and hostname != "unknown" and hostname != runner_name.split()[0]:
                runners_with_network_info.append({
                    "runner_id": runner.get("id"),
                    "runner_name": runner_name,
                    "hostname": hostname,
                    "os": runner.get("os", "unknown"),
                    "architecture": runner.get("architecture", "unknown")
                })
        
        # Check for SSH keys
        ssh_keys_available = False
        try:
            ssh_keys = self.list_ssh_keys()
            ssh_keys_available = len(ssh_keys) > 0
        except Exception:
            pass
        
        # Check if we can auto-detect SSH key
        auto_detected_key = self.auto_detect_ssh_key()
        has_ssh_access = auto_detected_key is not None and os.path.exists(auto_detected_key) if auto_detected_key else False
        
        # Assess execution risk
        execution_risk = "none"
        if len(runners_with_network_info) > 0:
            if has_ssh_access:
                execution_risk = "high"
            elif ssh_keys_available:
                execution_risk = "medium"
            else:
                execution_risk = "low"
        
        return {
            "has_execution_capability": len(runners_with_network_info) > 0,
            "online_runners_count": len(online_runners),
            "runners_with_network_info": len(runners_with_network_info),
            "runners_with_network_details": runners_with_network_info,
            "ssh_keys_available": ssh_keys_available,
            "ssh_key_auto_detected": has_ssh_access,
            "auto_detected_key_path": auto_detected_key if has_ssh_access else None,
            "execution_risk": execution_risk,
            "risk_factors": {
                "network_exposure": len(runners_with_network_info) > 0,
                "ssh_keys_available": ssh_keys_available,
                "ssh_access_configured": has_ssh_access,
                "online_runners_count": len(online_runners)
            }
        }
    
    def execute_on_runners(
        self,
        runners: List[Dict[str, Any]],
        command: str,
        ssh_user: Optional[str] = None,
        ssh_key: Optional[str] = None,
        ssh_port: int = 22
    ) -> Dict[str, Any]:
        """
        Execute command on online runners via SSH.
        
        Args:
            runners: List of runner dictionaries
            command: Command to execute
            ssh_user: SSH username (default: inferred from runner name or current user)
            ssh_key: Path to SSH private key (default: auto-detect)
            ssh_port: SSH port (default: 22)
            
        Returns:
            Dictionary with execution results
        """
        if not command:
            return {"error": "No command specified"}
        
        # Filter online runners
        online_runners = [r for r in runners if r.get("status", "").lower() == "online"]
        
        if not online_runners:
            return {
                "error": "No online runners found",
                "total": 0,
                "successful": 0,
                "failed": 0
            }
        
        # Auto-detect SSH key if not provided
        if not ssh_key:
            ssh_key = self.auto_detect_ssh_key()
            if not ssh_key:
                ssh_key = str(Path.home() / ".ssh" / "id_rsa")
        
        if not os.path.exists(ssh_key):
            return {
                "error": f"SSH key not found at {ssh_key}",
                "total": len(online_runners),
                "successful": 0,
                "failed": 0
            }
        
        results = {
            "total": len(online_runners),
            "successful": 0,
            "failed": 0,
            "runners": []
        }
        
        for runner in online_runners:
            runner_id = runner.get("id")
            runner_name = runner.get("name", "unknown")
            runner_os = runner.get("os", "unknown")
            runner_group = runner.get("runner_group_name", "default")
            
            hostname = self.extract_hostname(runner_name)
            
            # Determine SSH user
            user = ssh_user
            if not user:
                if '@' in runner_name:
                    user = runner_name.split('@')[0]
                else:
                    user = os.getenv("USER") or os.getenv("USERNAME") or "root"
            
            runner_result = {
                "runner_id": runner_id,
                "runner_name": runner_name,
                "hostname": hostname,
                "user": user,
                "status": "unknown",
                "output": "",
                "error": ""
            }
            
            # Build SSH command
            ssh_cmd = [
                "ssh",
                "-i", ssh_key,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=10",
                "-o", "BatchMode=yes",
                "-p", str(ssh_port),
                f"{user}@{hostname}",
                command
            ]
            
            try:
                result = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    runner_result["status"] = "success"
                    runner_result["output"] = result.stdout
                    results["successful"] += 1
                else:
                    runner_result["status"] = "failed"
                    runner_result["error"] = result.stderr or f"Exit code: {result.returncode}"
                    results["failed"] += 1
            except subprocess.TimeoutExpired:
                runner_result["status"] = "failed"
                runner_result["error"] = "Connection timeout"
                results["failed"] += 1
            except Exception as e:
                runner_result["status"] = "failed"
                runner_result["error"] = str(e)
                results["failed"] += 1
            
            results["runners"].append(runner_result)
        
        return results

