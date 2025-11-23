"""
Output Formatters Module

Formats validation and enumeration results for JSON and human-readable console output.
"""

import json
import csv
import os
from datetime import datetime
from typing import Dict, Any, Optional, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box


class OutputFormatter:
    """Formats output in various formats."""
    
    def __init__(self):
        """Initialize formatter."""
        self.console = Console()
    
    def format_permissions_json(self, permissions_data: Dict[str, Any]) -> str:
        """
        Format permissions data as JSON.
        
        Args:
            permissions_data: Permission validation results
        
        Returns:
            JSON string
        """
        return json.dumps(permissions_data, indent=2, default=str)
    
    def format_enumeration_json(self, enumeration_data: Dict[str, Any]) -> str:
        """
        Format enumeration data as JSON.
        
        Args:
            enumeration_data: Company enumeration results
        
        Returns:
            JSON string
        """
        return json.dumps(enumeration_data, indent=2, default=str)
    
    def format_combined_json(self, permissions_data: Optional[Dict[str, Any]], 
                            enumeration_data: Optional[Dict[str, Any]],
                            enterprise_runners: Optional[Dict[str, Any]] = None) -> str:
        """
        Format combined results as JSON.
        
        Args:
            permissions_data: Permission validation results
            enumeration_data: Company enumeration results
        
        Returns:
            JSON string
        """
        combined = {}
        if permissions_data:
            combined["permissions"] = permissions_data
        if enumeration_data:
            combined["enumeration"] = enumeration_data
        if enterprise_runners:
            combined["enterprise_runners"] = enterprise_runners
        
        return json.dumps(combined, indent=2, default=str)
    
    def format_permissions_console(self, permissions_data: Dict[str, Any]) -> None:
        """
        Format permissions data for console output.
        
        Args:
            permissions_data: Permission validation results
        """
        self.console.print("\n")
        self.console.print(Panel.fit(
            "[bold cyan]GitHub API Key Permission Validation[/bold cyan]",
            border_style="cyan"
        ))
        
        # Authenticated user info
        if "authenticated_user" in permissions_data:
            user = permissions_data["authenticated_user"]
            self.console.print(f"\n[bold]Authenticated User:[/bold] {user.get('login', 'N/A')}")
            if user.get("name"):
                self.console.print(f"[bold]Name:[/bold] {user.get('name')}")
            if user.get("email"):
                self.console.print(f"[bold]Email:[/bold] {user.get('email')}")
        
        # Summary
        if "summary" in permissions_data:
            summary = permissions_data["summary"]
            self.console.print(f"\n[bold]Summary:[/bold]")
            self.console.print(f"  Total Tested: {summary.get('total_tested', 0)}")
            self.console.print(f"  [green]Granted:[/green] {summary.get('granted', 0)}")
            self.console.print(f"  [red]Denied:[/red] {summary.get('denied', 0)}")
            if summary.get('errors', 0) > 0:
                self.console.print(f"  [yellow]Errors:[/yellow] {summary.get('errors', 0)}")
        
        # Critical permissions
        if "critical_permissions" in permissions_data:
            self.console.print("\n[bold red]Critical Permissions:[/bold red]")
            critical_table = Table(show_header=True, header_style="bold red", box=box.ROUNDED)
            critical_table.add_column("Permission", style="cyan")
            critical_table.add_column("Status", justify="center")
            critical_table.add_column("Message", style="white")
            
            for perm_name, perm_data in permissions_data["critical_permissions"].items():
                status = "[green]✓ GRANTED[/green]" if perm_data.get("granted") else "[red]✗ DENIED[/red]"
                message = perm_data.get("message", "")
                critical_table.add_row(perm_name, status, message)
            
            self.console.print(critical_table)
        
        # Standard permissions
        if "standard_permissions" in permissions_data:
            self.console.print("\n[bold yellow]Standard Permissions:[/bold yellow]")
            standard_table = Table(show_header=True, header_style="bold yellow", box=box.ROUNDED)
            standard_table.add_column("Permission", style="cyan")
            standard_table.add_column("Status", justify="center")
            standard_table.add_column("Message", style="white")
            
            for perm_name, perm_data in permissions_data["standard_permissions"].items():
                status = "[green]✓ GRANTED[/green]" if perm_data.get("granted") else "[red]✗ DENIED[/red]"
                message = perm_data.get("message", "")
                standard_table.add_row(perm_name, status, message)
            
            self.console.print(standard_table)
        
        # Enhanced details for new validations
        self._format_enhanced_permission_details(permissions_data)
        
        # Rate limit info
        if "rate_limit" in permissions_data:
            rate_limit = permissions_data["rate_limit"]
            self.console.print(f"\n[bold]Rate Limit:[/bold]")
            self.console.print(f"  Remaining: {rate_limit.get('remaining', 'N/A')}")
            self.console.print(f"  Limit: {rate_limit.get('limit', 'N/A')}")
            self.console.print(f"  Reset: {rate_limit.get('reset', 'N/A')}")
        
        self.console.print("\n")
    
    def _format_enhanced_permission_details(self, permissions_data: Dict[str, Any]) -> None:
        """Format enhanced details for specific permissions like runners, repo counts, and secrets."""
        
        # Repository Access Count Details
        if "standard_permissions" in permissions_data:
            repo_count_data = permissions_data["standard_permissions"].get("repo_access_count")
            if repo_count_data and repo_count_data.get("granted") and repo_count_data.get("details"):
                details = repo_count_data["details"]
                self.console.print("\n[bold cyan]Repository Access Summary:[/bold cyan]")
                repo_summary_table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
                repo_summary_table.add_column("Metric", style="yellow")
                repo_summary_table.add_column("Count", justify="right", style="green")
                
                repo_summary_table.add_row("Total Repositories", str(details.get("total_repos", 0)))
                repo_summary_table.add_row("Private Repositories", str(details.get("private_repos", 0)))
                repo_summary_table.add_row("Public Repositories", str(details.get("public_repos", 0)))
                repo_summary_table.add_row("Archived Repositories", str(details.get("archived_repos", 0)))
                repo_summary_table.add_row("", "")  # Separator
                repo_summary_table.add_row("[bold]With Admin Access[/bold]", str(details.get("repos_with_admin", 0)))
                repo_summary_table.add_row("[bold]With Push Access[/bold]", str(details.get("repos_with_push", 0)))
                repo_summary_table.add_row("[bold]With Pull Access[/bold]", str(details.get("repos_with_pull", 0)))
                
                self.console.print(repo_summary_table)
                
                # Show sample repos if available
                if details.get("sample_admin_repos"):
                    self.console.print(f"\n  [dim]Sample Admin Repos:[/dim] {', '.join(details['sample_admin_repos'][:5])}")
        
        # Runners Details
        if "standard_permissions" in permissions_data:
            # Repository runners
            runners_repo_data = permissions_data["standard_permissions"].get("runners_repo")
            if runners_repo_data and runners_repo_data.get("granted") and runners_repo_data.get("details"):
                details = runners_repo_data["details"]
                self.console.print("\n[bold magenta]Repository Runners:[/bold magenta]")
                self.console.print(f"  Total Runners: [green]{details.get('total_runners', 0)}[/green]")
                self.console.print(f"  Repositories with Runners: [green]{details.get('repo_count', 0)}[/green]")
                
                if details.get("repos_with_runners"):
                    runners_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
                    runners_table.add_column("Repository", style="cyan")
                    runners_table.add_column("Runner Count", justify="right", style="green")
                    
                    for repo_info in details["repos_with_runners"][:10]:
                        runners_table.add_row(
                            repo_info.get("repo", ""),
                            str(repo_info.get("runner_count", 0))
                        )
                    
                    if len(details["repos_with_runners"]) > 10:
                        runners_table.add_row("...", f"({len(details['repos_with_runners']) - 10} more)")
                    
                    self.console.print(runners_table)
            
            # Organization runners
            runners_org_data = permissions_data["standard_permissions"].get("runners_org")
            if runners_org_data and runners_org_data.get("granted") and runners_org_data.get("details"):
                details = runners_org_data["details"]
                self.console.print("\n[bold magenta]Organization Runners:[/bold magenta]")
                self.console.print(f"  Total Runners: [green]{details.get('total_runners', 0)}[/green]")
                self.console.print(f"  Organizations with Runners: [green]{details.get('org_count', 0)}[/green]")
                
                if details.get("orgs_with_runners"):
                    org_runners_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
                    org_runners_table.add_column("Organization", style="cyan")
                    org_runners_table.add_column("Runner Count", justify="right", style="green")
                    
                    for org_info in details["orgs_with_runners"]:
                        org_runners_table.add_row(
                            org_info.get("org", ""),
                            str(org_info.get("runner_count", 0))
                        )
                    
                    self.console.print(org_runners_table)
        
        # Comprehensive Secrets Details
        if "standard_permissions" in permissions_data:
            secrets_data = permissions_data["standard_permissions"].get("secrets_comprehensive")
            if secrets_data and secrets_data.get("granted") and secrets_data.get("details"):
                details = secrets_data["details"]
                self.console.print("\n[bold red]Secrets Summary:[/bold red]")
                secrets_summary_table = Table(show_header=True, header_style="bold red", box=box.SIMPLE)
                secrets_summary_table.add_column("Type", style="yellow")
                secrets_summary_table.add_column("Count", justify="right", style="green")
                
                total_secrets = details.get("total_repo_secrets", 0) + details.get("total_org_secrets", 0)
                secrets_summary_table.add_row("Total Secrets", str(total_secrets))
                secrets_summary_table.add_row("Repository Secrets", str(details.get("total_repo_secrets", 0)))
                secrets_summary_table.add_row("Organization Secrets", str(details.get("total_org_secrets", 0)))
                secrets_summary_table.add_row("", "")  # Separator
                secrets_summary_table.add_row("Repos with Secrets", str(details.get("repos_with_secrets", 0)))
                secrets_summary_table.add_row("Orgs with Secrets", str(details.get("orgs_with_secrets", 0)))
                
                self.console.print(secrets_summary_table)
                
                # Show repository secrets details
                if details.get("repo_secrets"):
                    self.console.print("\n  [bold]Repository Secrets:[/bold]")
                    for repo_secret in details["repo_secrets"][:5]:
                        secret_names = [s.get("name", "") for s in repo_secret.get("secrets", [])]
                        self.console.print(f"    [cyan]{repo_secret.get('repo', '')}:[/cyan] {repo_secret.get('secret_count', 0)} secrets")
                        if secret_names:
                            self.console.print(f"      [dim]{', '.join(secret_names[:5])}[/dim]")
                    if len(details["repo_secrets"]) > 5:
                        self.console.print(f"    [dim]... and {len(details['repo_secrets']) - 5} more repositories[/dim]")
                
                # Show organization secrets details
                if details.get("org_secrets"):
                    self.console.print("\n  [bold]Organization Secrets:[/bold]")
                    for org_secret in details["org_secrets"][:5]:
                        secret_names = [s.get("name", "") for s in org_secret.get("secrets", [])]
                        self.console.print(f"    [cyan]{org_secret.get('org', '')}:[/cyan] {org_secret.get('secret_count', 0)} secrets")
                        if secret_names:
                            self.console.print(f"      [dim]{', '.join(secret_names[:5])}[/dim]")
                    if len(details["org_secrets"]) > 5:
                        self.console.print(f"    [dim]... and {len(details['org_secrets']) - 5} more organizations[/dim]")
    
    def export_to_csv(self, permissions_data: Optional[Dict[str, Any]], 
                      enumeration_data: Optional[Dict[str, Any]], 
                      filename: Optional[str] = None,
                      enterprise_runners: Optional[Dict[str, Any]] = None) -> str:
        """
        Export results to CSV format.
        
        Args:
            permissions_data: Permission validation results
            enumeration_data: Company enumeration results
            filename: Optional filename (auto-generated if not provided)
        
        Returns:
            Path to the created CSV file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"github_validation_{timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow([
                "Category", "Type", "Name", "Status", "Message", "Details"
            ])
            
            # Write permissions data
            if permissions_data:
                # Critical permissions
                if "critical_permissions" in permissions_data:
                    for perm_name, perm_data in permissions_data["critical_permissions"].items():
                        status = "GRANTED" if perm_data.get("granted") else "DENIED"
                        message = perm_data.get("message", "")
                        details = json.dumps(perm_data.get("details", {}), default=str)
                        writer.writerow([
                            "Permissions", "Critical", perm_name, status, message, details
                        ])
                
                # Standard permissions
                if "standard_permissions" in permissions_data:
                    for perm_name, perm_data in permissions_data["standard_permissions"].items():
                        status = "GRANTED" if perm_data.get("granted") else "DENIED"
                        message = perm_data.get("message", "")
                        details = json.dumps(perm_data.get("details", {}), default=str)
                        writer.writerow([
                            "Permissions", "Standard", perm_name, status, message, details
                        ])
            
            # Write enumeration data
            if enumeration_data:
                if "organization_name" in enumeration_data:
                    org_name = enumeration_data.get("organization_name", "Unknown")
                    
                    # Organization info
                    if "organization_info" in enumeration_data:
                        org_info = enumeration_data["organization_info"]
                        writer.writerow([
                            "Enumeration", "Organization", org_name, "INFO", 
                            f"Public Repos: {org_info.get('public_repos', 0)}",
                            json.dumps(org_info, default=str)
                        ])
                    
                    # Members
                    if "members" in enumeration_data:
                        for member in enumeration_data["members"]:
                            writer.writerow([
                                "Enumeration", "Member", member.get("login", ""),
                                "MEMBER", f"Type: {member.get('type', '')}",
                                f"Site Admin: {member.get('site_admin', False)}"
                            ])
                    
                    # Repositories
                    if "repositories" in enumeration_data:
                        for repo in enumeration_data["repositories"]:
                            private = "Private" if repo.get("private") else "Public"
                            details = {
                                "language": repo.get("language", "N/A"),
                                "stars": repo.get("stargazers_count", 0),
                                "runners": len(repo.get("runners", [])),
                            }
                            writer.writerow([
                                "Enumeration", "Repository", repo.get("name", ""),
                                private, f"Stars: {repo.get('stargazers_count', 0)}",
                                json.dumps(details, default=str)
                            ])

                    if enumeration_data.get("organization_runners"):
                        for runner in enumeration_data["organization_runners"]:
                            writer.writerow([
                                "Enumeration", "OrgRunner", runner.get("name") or runner.get("id"),
                                runner.get("status", "unknown"),
                                f"OS: {runner.get('os', 'N/A')}",
                                json.dumps(runner, default=str)
                            ])

                elif "organizations" in enumeration_data:
                    for org in enumeration_data.get("organizations", []):
                        writer.writerow([
                            "Enumeration", "Organization", org.get("organization_name", "Unknown"),
                            "INFO", f"Repositories: {len(org.get('repositories', []))}",
                            json.dumps(org.get("organization_info", {}), default=str)
                        ])

            if enumeration_data and enumeration_data.get("actions_overview"):
                overview = enumeration_data["actions_overview"]
                writer.writerow([
                    "Enumeration", "ActionsOverview", enumeration_data.get("organization_name", "Unknown"),
                    "INFO", "GitHub Actions Summary",
                    json.dumps(overview, default=str)
                ])

            if enterprise_runners:
                writer.writerow([
                    "EnterpriseRunners", "Summary", enterprise_runners.get("enterprise", ""),
                    "INFO", f"Total Runners: {enterprise_runners.get('total_runners', 0)}",
                    json.dumps({
                        "online": enterprise_runners.get("online_runners", 0),
                        "offline": enterprise_runners.get("offline_runners", 0),
                        "status_counts": enterprise_runners.get("status_counts", {})
                    }, default=str)
                ])
                for runner in enterprise_runners.get("runners", []):
                    writer.writerow([
                        "EnterpriseRunners", "Runner", runner.get("name") or runner.get("id"),
                        runner.get("status", "unknown"),
                        f"OS: {runner.get('os', 'N/A')}",
                        json.dumps(runner, default=str)
                    ])
        
        return filename
    
    def save_to_file(self, data: Dict[str, Any], filename: Optional[str] = None, 
                     format_type: str = "json") -> str:
        """
        Save data to a file.
        
        Args:
            data: Data to save
            filename: Optional filename (auto-generated if not provided)
            format_type: File format ("json" or "csv")
        
        Returns:
            Path to the created file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if format_type == "csv":
                filename = f"github_validation_{timestamp}.csv"
            else:
                filename = f"github_validation_{timestamp}.json"
        
        if format_type == "json":
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
        elif format_type == "csv":
            # For CSV, we need to handle permissions and enumeration separately
            permissions_data = data.get("permissions")
            enumeration_data = data.get("enumeration")
            enterprise_runners = data.get("enterprise_runners")
            return self.export_to_csv(permissions_data, enumeration_data, filename, enterprise_runners)
        
        return filename
    
    def format_enumeration_console(self, enumeration_data: Dict[str, Any]) -> None:
        """
        Format enumeration data for console output.
        
        Args:
            enumeration_data: Company enumeration results
        """
        self.console.print("\n")
        self.console.print(Panel.fit(
            "[bold cyan]Company/Organization Enumeration[/bold cyan]",
            border_style="cyan"
        ))
        
        # Handle single organization
        if "organization_name" in enumeration_data:
            org_name = enumeration_data.get("organization_name", "Unknown")
            self.console.print(f"\n[bold cyan]Organization:[/bold cyan] {org_name}\n")
            
            # Organization info
            if enumeration_data.get("organization_info"):
                org_info = enumeration_data["organization_info"]
                self.console.print("[bold]Organization Information:[/bold]")
                if org_info.get("name"):
                    self.console.print(f"  Name: {org_info.get('name')}")
                if org_info.get("description"):
                    self.console.print(f"  Description: {org_info.get('description')}")
                if org_info.get("email"):
                    self.console.print(f"  Email: {org_info.get('email')}")
                if org_info.get("location"):
                    self.console.print(f"  Location: {org_info.get('location')}")
                self.console.print(f"  Public Repos: {org_info.get('public_repos', 0)}")
                self.console.print(f"  Created: {org_info.get('created_at', 'N/A')}")
            
            # Members
            if enumeration_data.get("members"):
                members = enumeration_data["members"]
                self.console.print(f"\n[bold]Members:[/bold] {len(members)}")
                members_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
                members_table.add_column("Login", style="cyan")
                members_table.add_column("Type", style="yellow")
                members_table.add_column("Site Admin", justify="center")
                
                for member in members[:20]:  # Show first 20
                    members_table.add_row(
                        member.get("login", ""),
                        member.get("type", ""),
                        "Yes" if member.get("site_admin") else "No"
                    )
                
                if len(members) > 20:
                    members_table.add_row("...", f"({len(members) - 20} more)", "")
                
                self.console.print(members_table)
            
            # Teams
            if enumeration_data.get("teams"):
                teams = enumeration_data["teams"]
                self.console.print(f"\n[bold]Teams:[/bold] {len(teams)}")
                teams_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
                teams_table.add_column("Name", style="cyan")
                teams_table.add_column("Permission", style="yellow")
                teams_table.add_column("Members", justify="center")
                teams_table.add_column("Repos", justify="center")
                
                for team in teams:
                    teams_table.add_row(
                        team.get("name", ""),
                        team.get("permission", ""),
                        str(team.get("members_count", 0)),
                        str(team.get("repos_count", 0))
                    )
                
                self.console.print(teams_table)
            
            # Repositories
            if enumeration_data.get("repositories"):
                repos = enumeration_data["repositories"]
                self.console.print(f"\n[bold]Repositories:[/bold] {len(repos)}")
                repos_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
                repos_table.add_column("Name", style="cyan")
                repos_table.add_column("Private", justify="center")
                repos_table.add_column("Language", style="yellow")
                repos_table.add_column("Stars", justify="center")
                repos_table.add_column("Forks", justify="center")
                repos_table.add_column("Webhooks", justify="center")
                repos_table.add_column("Workflows", justify="center")
                
                for repo in repos[:30]:  # Show first 30
                    private = "Yes" if repo.get("private") else "No"
                    webhooks_count = len(repo.get("webhooks", []))
                    workflows_count = len(repo.get("workflows", []))
                    repos_table.add_row(
                        repo.get("name", ""),
                        private,
                        repo.get("language", "N/A"),
                        str(repo.get("stargazers_count", 0)),
                        str(repo.get("forks_count", 0)),
                        str(webhooks_count),
                        str(workflows_count)
                    )
                
                if len(repos) > 30:
                    repos_table.add_row("...", "", "", "", "", "", f"({len(repos) - 30} more)")
                
                self.console.print(repos_table)

                repos_with_runners = [
                    repo for repo in repos if repo.get("runners")
                ]
                if repos_with_runners:
                    self.console.print(f"\n[bold magenta]Repository Runners:[/bold magenta]")
                    runner_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
                    runner_table.add_column("Repository", style="cyan")
                    runner_table.add_column("Runner Count", justify="right")
                    runner_table.add_column("Online", justify="right")
                    for repo in repos_with_runners[:15]:
                        total_runners = len(repo.get("runners", []))
                        online = sum(1 for r in repo.get("runners", []) if (r.get("status") or "").lower() == "online")
                        runner_table.add_row(repo.get("name", ""), str(total_runners), str(online))
                    if len(repos_with_runners) > 15:
                        runner_table.add_row("...", f"({len(repos_with_runners) - 15} more)", "")
                    self.console.print(runner_table)

            actions_overview = enumeration_data.get("actions_overview")
            if actions_overview:
                self.console.print("\n[bold cyan]GitHub Actions Overview:[/bold cyan]")
                actions_table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
                actions_table.add_column("Metric", style="yellow")
                actions_table.add_column("Count", justify="right", style="green")
                actions_table.add_row("Repositories", str(actions_overview.get("repository_count", 0)))
                actions_table.add_row("Workflow-enabled repos", str(actions_overview.get("workflow_repositories", 0)))
                actions_table.add_row("Total workflows", str(actions_overview.get("workflow_total", 0)))
                actions_table.add_row("Repos with Actions secrets", str(actions_overview.get("repository_secrets", 0)))
                actions_table.add_row("Repos with runners", str(actions_overview.get("repository_runners", 0)))
                actions_table.add_row("Organization secrets", str(actions_overview.get("org_secrets", 0)))
                self.console.print(actions_table)
            
            if enumeration_data.get("organization_runners"):
                org_runners = enumeration_data["organization_runners"]
                self.console.print(f"\n[bold magenta]Organization Runners:[/bold magenta] {len(org_runners)}")
                org_runner_table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
                org_runner_table.add_column("Name/ID", style="cyan")
                org_runner_table.add_column("Status", style="green")
                org_runner_table.add_column("OS", style="yellow")
                org_runner_table.add_column("Labels", style="white")
                for runner in org_runners[:20]:
                    org_runner_table.add_row(
                        runner.get("name") or str(runner.get("id")),
                        runner.get("status", "unknown"),
                        runner.get("os", "N/A"),
                        ", ".join(runner.get("labels", []))
                    )
                if len(org_runners) > 20:
                    org_runner_table.add_row("...", f"({len(org_runners) - 20} more)", "", "")
                self.console.print(org_runner_table)
            
            # Organization webhooks
            if enumeration_data.get("webhooks"):
                webhooks = enumeration_data["webhooks"]
                self.console.print(f"\n[bold]Organization Webhooks:[/bold] {len(webhooks)}")
                for webhook in webhooks:
                    self.console.print(f"  - {webhook.get('name', 'N/A')} ({webhook.get('config', {}).get('url', 'N/A')})")
            
            # Organization secrets
            if enumeration_data.get("secrets"):
                secrets = enumeration_data["secrets"]
                self.console.print(f"\n[bold]Organization Secrets:[/bold] {len(secrets)}")
                for secret in secrets:
                    self.console.print(f"  - {secret.get('name', 'N/A')} (Visibility: {secret.get('visibility', 'N/A')})")
            
            # Errors
            if enumeration_data.get("errors"):
                self.console.print(f"\n[yellow]Errors encountered:[/yellow]")
                for error in enumeration_data["errors"]:
                    self.console.print(f"  - {error}")
        
        # Handle multiple organizations
        elif "organizations" in enumeration_data:
            orgs = enumeration_data["organizations"]
            self.console.print(f"\n[bold]Total Organizations:[/bold] {enumeration_data.get('total_count', 0)}\n")
            
            for org_data in orgs:
                org_name = org_data.get("organization_name", "Unknown")
                self.console.print(Panel(
                    f"[bold]{org_name}[/bold]\n"
                    f"Members: {len(org_data.get('members', []))}\n"
                    f"Teams: {len(org_data.get('teams', []))}\n"
                    f"Repositories: {len(org_data.get('repositories', []))}",
                    title="Organization",
                    border_style="cyan"
                ))
            
            if enumeration_data.get("errors"):
                self.console.print(f"\n[yellow]Errors encountered:[/yellow]")
                for error in enumeration_data["errors"]:
                    self.console.print(f"  - {error}")
        
        self.console.print("\n")
    
    def format_combined_console(self, permissions_data: Optional[Dict[str, Any]], 
                               enumeration_data: Optional[Dict[str, Any]],
                               enterprise_runners: Optional[Dict[str, Any]] = None) -> None:
        """
        Format combined results for console output.
        
        Args:
            permissions_data: Permission validation results
            enumeration_data: Company enumeration results
        """
        if permissions_data:
            self.format_permissions_console(permissions_data)
        
        if enumeration_data:
            self.format_enumeration_console(enumeration_data)

        if enterprise_runners:
            self._format_enterprise_runners_console(enterprise_runners)

    def _format_enterprise_runners_console(self, runner_data: Dict[str, Any]) -> None:
        """Print enterprise-wide runner telemetry."""
        self.console.print("\n[bold cyan]Enterprise Runners[/bold cyan]")
        self.console.print(f"Enterprise: {runner_data.get('enterprise', 'Unknown')}")
        summary_table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
        summary_table.add_column("Metric", style="yellow")
        summary_table.add_column("Count", justify="right", style="green")
        summary_table.add_row("Total", str(runner_data.get("total_runners", 0)))
        summary_table.add_row("Online", str(runner_data.get("online_runners", 0)))
        summary_table.add_row("Offline", str(runner_data.get("offline_runners", 0)))
        self.console.print(summary_table)

        if runner_data.get("labels_of_interest"):
            self.console.print("\n[bold]Tracked Labels:[/bold]")
            label_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
            label_table.add_column("Label", style="cyan")
            label_table.add_column("Online", justify="right", style="green")
            label_table.add_column("Total", justify="right")
            for label, counts in runner_data["labels_of_interest"].items():
                label_table.add_row(label, str(counts.get("online", 0)), str(counts.get("total", 0)))
            self.console.print(label_table)

        if runner_data.get("runners"):
            self.console.print("\n[bold]Runner Details (first 20):[/bold]")
            runner_table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
            runner_table.add_column("Name/ID", style="cyan")
            runner_table.add_column("Status", style="green")
            runner_table.add_column("OS", style="yellow")
            runner_table.add_column("Labels", style="white")
            for runner in runner_data["runners"][:20]:
                runner_table.add_row(
                    runner.get("name") or str(runner.get("id")),
                    runner.get("status", "unknown"),
                    runner.get("os", "N/A"),
                    ", ".join(runner.get("labels", []))
                )
            if len(runner_data["runners"]) > 20:
                runner_table.add_row("...", f"({len(runner_data['runners']) - 20} more)", "", "")
            self.console.print(runner_table)
        self.console.print("\n")

