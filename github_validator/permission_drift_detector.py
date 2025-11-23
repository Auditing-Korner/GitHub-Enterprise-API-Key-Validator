"""
Permission Drift Detection Module

Detects changes in API key permissions over time by comparing
current permissions with historical snapshots.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import os
from pathlib import Path


class PermissionDriftDetector:
    """Detects permission changes and drift over time."""
    
    def __init__(self, storage_dir: str = "./.permission_history"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    def save_permission_snapshot(self, api_key_id: str, permissions_data: Dict[str, Any]) -> str:
        """
        Save a snapshot of current permissions.
        
        Args:
            api_key_id: Identifier for the API key
            permissions_data: Current permissions data
            
        Returns:
            Path to saved snapshot file
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{api_key_id}_{timestamp}.json"
        filepath = self.storage_dir / filename
        
        snapshot = {
            "api_key_id": api_key_id,
            "timestamp": datetime.utcnow().isoformat(),
            "permissions": permissions_data,
            "summary": {
                "total_tested": permissions_data.get("summary", {}).get("total_tested", 0),
                "granted": permissions_data.get("summary", {}).get("granted", 0),
                "denied": permissions_data.get("summary", {}).get("denied", 0),
                "critical_granted": sum(
                    1 for p in permissions_data.get("critical_permissions", {}).values()
                    if p.get("granted", False)
                )
            }
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(snapshot, f, indent=2)
        
        return str(filepath)
    
    def load_permission_snapshot(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Load a permission snapshot from file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None
    
    def get_latest_snapshot(self, api_key_id: str) -> Optional[Dict[str, Any]]:
        """Get the most recent snapshot for an API key."""
        snapshots = list(self.storage_dir.glob(f"{api_key_id}_*.json"))
        if not snapshots:
            return None
        
        latest = max(snapshots, key=lambda p: p.stat().st_mtime)
        return self.load_permission_snapshot(str(latest))
    
    def compare_permissions(self, current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare current permissions with previous snapshot.
        
        Args:
            current: Current permissions data
            previous: Previous permissions snapshot
            
        Returns:
            Dictionary with comparison results and detected changes
        """
        if not previous:
            return {
                "has_changes": False,
                "message": "No previous snapshot found for comparison",
                "changes": []
            }
        
        changes = []
        current_perms = current.get("critical_permissions", {})
        current_perms.update(current.get("standard_permissions", {}))
        
        previous_perms = previous.get("permissions", {}).get("critical_permissions", {})
        previous_perms.update(previous.get("permissions", {}).get("standard_permissions", {}))
        
        # Check for new permissions
        for perm_name, perm_data in current_perms.items():
            if perm_name not in previous_perms:
                if perm_data.get("granted", False):
                    changes.append({
                        "type": "new_permission_granted",
                        "permission": perm_name,
                        "status": "granted",
                        "severity": "high" if perm_name in current.get("critical_permissions", {}) else "medium"
                    })
            else:
                prev_granted = previous_perms[perm_name].get("granted", False)
                curr_granted = perm_data.get("granted", False)
                
                if prev_granted != curr_granted:
                    changes.append({
                        "type": "permission_changed",
                        "permission": perm_name,
                        "previous_status": "granted" if prev_granted else "denied",
                        "current_status": "granted" if curr_granted else "denied",
                        "severity": "critical" if perm_name in current.get("critical_permissions", {}) else "high"
                    })
        
        # Check for removed permissions
        for perm_name in previous_perms:
            if perm_name not in current_perms:
                changes.append({
                    "type": "permission_removed",
                    "permission": perm_name,
                    "previous_status": previous_perms[perm_name].get("granted", False),
                    "severity": "medium"
                })
        
        # Calculate summary
        current_summary = current.get("summary", {})
        previous_summary = previous.get("summary", {})
        
        summary_changes = {
            "total_tested": current_summary.get("total_tested", 0) - previous_summary.get("total_tested", 0),
            "granted": current_summary.get("granted", 0) - previous_summary.get("granted", 0),
            "critical_granted": current_summary.get("critical_granted", 0) - previous_summary.get("critical_granted", 0)
        }
        
        return {
            "has_changes": len(changes) > 0,
            "change_count": len(changes),
            "changes": changes,
            "summary_changes": summary_changes,
            "comparison_timestamp": datetime.utcnow().isoformat(),
            "previous_snapshot_time": previous.get("timestamp"),
            "critical_changes": [c for c in changes if c.get("severity") == "critical"],
            "high_changes": [c for c in changes if c.get("severity") == "high"]
        }
    
    def detect_drift(self, api_key_id: str, current_permissions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect permission drift by comparing with latest snapshot.
        
        Args:
            api_key_id: Identifier for the API key
            current_permissions: Current permissions data
            
        Returns:
            Drift detection results
        """
        previous = self.get_latest_snapshot(api_key_id)
        comparison = self.compare_permissions(current_permissions, previous)
        
        # Save current snapshot
        snapshot_path = self.save_permission_snapshot(api_key_id, current_permissions)
        
        return {
            **comparison,
            "current_snapshot_path": snapshot_path,
            "has_previous_snapshot": previous is not None
        }

